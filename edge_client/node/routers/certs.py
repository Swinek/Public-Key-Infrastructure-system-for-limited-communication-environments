"""The certificate held by the edge client: show, download, check offline, hand to this node's edge app.

There is no upload of a certificate, a private key or a Root CA: the key is generated here and the certificate
comes from the CA after the administrator approves the node's request (enroll.py); the Root CA is pinned at
deployment (CA_FINGERPRINT) and fetched by pki_sync.py. Two manual actions remain:
    POST /api/certs/csr   new key + request (e.g. after a rejection) - the certificate still needs the CA's approval
    POST /api/certs/crl   CRL delivered out of band (e.g. on a USB stick) - stored only if signed by the CA and newer

The edge app of this node takes the certificate from here (GET /api/certs/bundle, diagram arrow "cert") and uses it
only to authenticate communication. The bundle contains the private key, so it is served only to the edge app.
"""
import socket
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response

import certs
import config
import contact
import enroll

router = APIRouter(prefix="/api/certs", tags=["Certificates (edge client)"])

# A certificate or CRL of this PKI is a few KB; anything far larger is not a PKI object.
MAX_OBJECT_BYTES = 256 * 1024


async def _read(upload: Optional[UploadFile], field: str) -> Optional[bytes]:
    if upload is None:
        return None
    data = await upload.read(MAX_OBJECT_BYTES + 1)
    if len(data) > MAX_OBJECT_BYTES:
        raise HTTPException(status_code=413, detail=f"'{field}' przekracza {MAX_OBJECT_BYTES} B.")
    if not data.strip():
        raise HTTPException(status_code=400, detail=f"'{field}' jest pusty.")
    return data


def is_edge_app(host: Optional[str]) -> bool:
    """True if the request comes from this node's edge app (its address on mgmt_N)."""
    app_host = urlparse(config.EDGE_APP_URL).hostname
    try:
        return host is not None and host == socket.gethostbyname(app_host)
    except OSError:
        return False


def _status():
    store = certs.get_store()
    pending = store.pending()
    return {
        "node_id": config.NODE_ID,
        "ca_pinned": bool(config.CA_FINGERPRINT),
        **store.status(),
        "request": None if pending is None else {k: v for k, v in pending.items() if k != "csr_der"},
    }


@router.get("", summary="Certificate (metadata + offline verdict), pending request, Root CA and CRL")
def list_certificates():
    return _status()


@router.post("/csr", summary="New key + certificate request (sent to the CA on the next WAN contact)")
def new_request():
    request = enroll.request_now()
    print(f"[CERTS] New key and CSR requested by the operator ({request['key_fingerprint'][:16]}...)")
    return {"request": request, "status": _status()}


@router.post("/crl", summary="Store a CRL delivered out of band (only if signed by the Root CA and newer)")
async def upload_crl(crl: UploadFile = File(..., description="CRL (PEM/DER) signed by the Root CA")):
    data = await _read(crl, "crl")
    try:
        stored = certs.get_store().update_crl(data)
    except certs.CertStoreError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if stored:
        print("[CERTS] CRL stored from an out-of-band upload")
        contact.announce("pki-upload")  # neighbours pull the new CRL from here (pki_sync.py)
    warnings = [] if stored else ["CRL pominięta: Edge client ma już tę samą lub nowszą listę."]
    return {"stored": ["crl"] if stored else [], "warnings": warnings, "status": _status()}


def _parse_at(at: Optional[str]) -> datetime:
    """'now' for the verifier: current UTC time or an explicit ISO 8601 instant (demo/tests)."""
    if not at:
        return datetime.now(timezone.utc)
    try:
        value = datetime.fromisoformat(at.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Niepoprawny czas '{at}' (oczekiwany ISO 8601).")
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


@router.post("/verify", summary="Check the stored certificate or any other one offline (Root CA, validity, stored CRL)")
async def verify_certificate(
    cert: Optional[UploadFile] = File(None, description="Other certificate to check (PEM/DER); default: the stored one"),
    at: Optional[str] = Form(None, description="Check at this instant (ISO 8601, UTC); default: now"),
):
    store = certs.get_store()
    now = _parse_at(at)
    data = await _read(cert, "cert")
    try:
        if data is not None:
            target = certs.load_certificate(data)
        else:
            target = store.certificate()
            if target is None:
                raise HTTPException(status_code=400, detail="Podaj certyfikat – Edge client nie ma jeszcze własnego.")
    except certs.CertStoreError as exc:
        return {"checked_at": now.isoformat(), "stored": False, "status": "invalid", "reason": str(exc),
                "serial_number": None, "crl_number": None}
    return {"checked_at": now.isoformat(), "stored": data is None, **store.check(target, now).to_dict()}


@router.get("/bundle", summary="Certificate + key, Root CA and CRL for this node's edge app only")
def get_bundle(request: Request):
    if not is_edge_app(request.client.host if request.client else None):
        raise HTTPException(status_code=403, detail="Pakiet z kluczem prywatnym jest dostępny tylko dla Edge app tego węzła.")
    print("[CERTS] Edge app took the certificate")
    return certs.get_store().bundle()


@router.get("/nodes", summary="Certificates of other nodes held here (from radio neighbours), with an offline verdict")
def list_node_certificates():
    store = certs.get_store()
    out = []
    for cn in store.node_certificates():
        cert = store.peer_certificate(cn)
        if cert is not None:
            out.append({"cn": cn, "serial_number": str(cert.serial_number),
                        "not_after": cert.not_valid_after_utc.isoformat(), "verdict": store.check(cert).to_dict()})
    return {"node_id": config.NODE_ID, "certificates": out}


@router.get("/nodes/{cn}", summary="Certificate of another node (PEM) - e.g. for the edge app to encrypt for it")
def download_node_certificate(cn: str):
    cert = certs.get_store().peer_certificate(cn)
    if cert is None:
        raise HTTPException(status_code=404, detail=f"{config.NODE_ID} nie ma (jeszcze) certyfikatu węzła {cn} – "
                                                    f"dotrze przy kontakcie radiowym z węzłem, który go zna.")
    return Response(content=cert.public_bytes(serialization.Encoding.PEM), media_type="application/x-pem-file")


@router.get("/certificate", summary="Download the certificate (PEM, without the key)")
def download_certificate():
    data = certs.get_store().certificate_pem()
    if data is None:
        raise HTTPException(status_code=404, detail="Edge client nie ma jeszcze certyfikatu.")
    return Response(content=data, media_type="application/x-pem-file",
                    headers={"Content-Disposition": f'attachment; filename="{config.NODE_ID}_cert.pem"'})
