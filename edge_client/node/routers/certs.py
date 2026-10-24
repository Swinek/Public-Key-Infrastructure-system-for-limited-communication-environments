"""The certificate held by the edge client: upload (replaces the previous one), show, download, check offline.

The edge app of this node takes it from here (GET /api/certs/bundle, diagram arrow "cert") and uses it only
to authenticate communication. The bundle contains the private key, so it is served only to the edge app.
"""
import socket
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response

import certs
import config

router = APIRouter(prefix="/api/certs", tags=["Certificates (edge client)"])

# A certificate, key or CRL of this PKI is a few KB; anything far larger is not a PKI object.
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


@router.get("", summary="Certificate (metadata + offline verdict), Root CA and CRL held by this edge client")
def list_certificates():
    return {"node_id": config.NODE_ID, **certs.get_store().status()}


async def _classified(files: List[UploadFile]) -> Dict[str, bytes]:
    """Files of unknown kind, sorted by content into ca / cert / key / crl (at most one of each)."""
    found: Dict[str, bytes] = {}
    for upload in files:
        name = upload.filename or "plik"
        data = await _read(upload, name)
        try:
            kind = certs.classify(data)
        except certs.CertStoreError:
            raise HTTPException(status_code=400, detail=f"Nie rozpoznano pliku '{name}' (oczekiwany certyfikat, klucz lub CRL).")
        if kind in found:
            raise HTTPException(status_code=400, detail=f"Dwa pliki tego samego rodzaju ({kind}) – wgraj jeden.")
        found[kind] = data
    return found


@router.post("", summary="Upload Root CA, the certificate + key (replaces the previous one) and/or a CRL")
async def upload_certificate(
    files: List[UploadFile] = File([], description="Any of the files below in any order - recognised by content"),
    ca: Optional[UploadFile] = File(None, description="Root CA certificate (PEM/DER), needed before the first certificate"),
    cert: Optional[UploadFile] = File(None, description="Certificate (PEM/DER) issued by the Root CA"),
    key: Optional[UploadFile] = File(None, description="Its private key (PEM, unencrypted), together with cert"),
    crl: Optional[UploadFile] = File(None, description="CRL (PEM/DER) signed by the Root CA, stored only if newer"),
):
    found = await _classified(files)
    ca_data = await _read(ca, "ca") or found.get("ca")
    cert_data = await _read(cert, "cert") or found.get("cert")
    key_data = await _read(key, "key") or found.get("key")
    crl_data = await _read(crl, "crl") or found.get("crl")
    if not any((ca_data, cert_data, key_data, crl_data)):
        raise HTTPException(status_code=400, detail="Brak danych: podaj co najmniej jedno z pól ca, cert+key, crl.")
    if (cert_data is None) != (key_data is None):
        raise HTTPException(status_code=400, detail="Certyfikat i klucz prywatny wgrywa się razem.")

    store = certs.get_store()
    stored, warnings, replaced = [], [], False
    try:
        # Order matters: the certificate and the CRL are checked against the (newly) stored CA.
        if ca_data is not None:
            if store.set_ca(ca_data):
                stored.append("ca")
        if cert_data is not None:
            replaced = store.set_certificate(cert_data, key_data)
            stored.append("cert")
        if crl_data is not None:
            if store.update_crl(crl_data):
                stored.append("crl")
            else:
                warnings.append("CRL pominięta: Edge client ma już tę samą lub nowszą listę.")
    except certs.CertStoreError as exc:
        raise HTTPException(status_code=400, detail={"error": str(exc), "stored": stored})

    print(f"[CERTS] Stored: {', '.join(stored) or 'nothing new'}" + (" (previous certificate replaced)" if replaced else ""))
    return {"stored": stored, "replaced": replaced, "warnings": warnings, "status": list_certificates()}


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


@router.get("/certificate", summary="Download the certificate (PEM, without the key)")
def download_certificate():
    data = certs.get_store().certificate_pem()
    if data is None:
        raise HTTPException(status_code=404, detail="Edge client nie ma jeszcze certyfikatu.")
    return Response(content=data, media_type="application/x-pem-file",
                    headers={"Content-Disposition": f'attachment; filename="{config.NODE_ID}_cert.pem"'})
