"""The same PKI endpoints as the portal (edge_client/backend/routers/pki.py), served to neighbours.

A neighbour exchanges data with this edge client exactly as with the portal (pki_sync.py): small metadata first
(/pki/summary), then only an object it does not have. Objects are the originals signed by the CA - DER by default
(fewer bytes on the radio link), PEM with ?format=pem; ETag = CRLNumber / fingerprint, so a repeated request
with If-None-Match gets 304 without a body.
"""
import zlib
import base64
import textwrap
from typing import Optional

from fastapi import APIRouter, Query, Request, Response, HTTPException
from fastapi.responses import JSONResponse

import peer_state
import certs
import neighbours
import transfers
import wire

router = APIRouter(prefix="/pki", tags=["PKI (neighbours)"])

FORMAT = Query("der", pattern="^(der|pem)$")

LABELS = {"ca_cert": "CERTIFICATE", "crl_full": "X509 CRL"}


def peer_id(request: Request, fallback: Optional[str] = None) -> str:
    """Id of the requesting neighbour: from the hello table, else from its User-Agent (wire.py sends
    'EdgeClient/<node_id>'; its first request may come before our hello-ack), else its address."""
    host = request.client.host if request.client else None
    entry = neighbours.by_ip(host)
    if entry:
        return entry["id"]
    agent = request.headers.get("user-agent", "")
    if agent.startswith("EdgeClient/"):
        return agent.split("/", 1)[1][:64]
    return fallback or host or "?"


def _served(request: Request, response: Response, kind: str, payload: int, **extra) -> Response:
    """Records the object sent over a radio link (a local or UI request is not a transfer)."""
    if not neighbours.is_radio(request.client.host if request.client else None):
        return response
    wire_bytes = wire.server_wire_bytes(request.method, request.url.path, request.headers, 0,
                                        response.status_code, response.raw_headers, len(response.body))
    transfers.record(kind, "out", peer_id(request), payload, wire_bytes, **extra)
    return response


def _der_to_pem(der: bytes, label: str) -> bytes:
    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode(), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n".encode()


def _object(request: Request, der: Optional[bytes], fmt: str, kind: str, filename: str, media_type: str,
            etag: str, compression: str = "none", **extra) -> Response:
    if der is None:
        return JSONResponse(status_code=404, content={"error": f"{kind} not available on this node"})
    etag = f'"{etag}-{fmt}{"-zlib" if compression == "zlib" else ""}"'
    if request.headers.get("if-none-match") == etag:
        return _served(request, Response(status_code=304, headers={"ETag": etag}), kind, 0,
                       status="skipped", saved_bytes=len(der), **extra)
    if fmt == "pem":
        content, media_type, filename = _der_to_pem(der, LABELS[kind]), "application/x-pem-file", f"{filename}.pem"
    else:
        content, filename = der, f"{filename}.der"
    if compression == "zlib":
        content = zlib.compress(content)
        media_type, filename = "application/zlib", f"{filename}.zlib"
    response = Response(content=content, media_type=media_type,
                        headers={"ETag": etag, "Content-Disposition": f'attachment; filename="{filename}"'})
    return _served(request, response, kind, len(response.body), encoding=fmt.upper() + ("+zlib" if compression == "zlib" else ""), **extra)


@router.get("/summary", summary="Version numbers and sizes of the PKI objects held by this edge client")
def get_summary(request: Request):
    response = JSONResponse(certs.get_store().summary())
    return _served(request, response, "summary", len(response.body), encoding="JSON")


@router.get("/ca", summary="Root CA certificate (DER or PEM)")
def get_ca(request: Request, format: str = FORMAT):
    store = certs.get_store()
    ca = store.ca()
    return _object(request, store.ca_der(), format, "ca_cert", "ca_certificate", "application/pkix-cert",
                   certs.fingerprint(ca)[:16] if ca else "",
                   signature=certs.signature_name(ca) if ca else None)


@router.get("/crl", summary="Newest CRL signed by the CA (DER or PEM), ETag = CRLNumber")
def get_crl(request: Request, format: str = FORMAT,
            compression: str = Query("none", pattern="^(none|zlib)$")):
    store = certs.get_store()
    crl = store.crl()
    number = certs.crl_number(crl) if crl else None
    return _object(request, store.crl_der(), format, "crl_full", "crl", "application/pkix-crl",
                   f"crl-{number}", compression=compression, number=number, signature=certs.signature_name(crl) if crl else None)


@router.get("/updates/{object_id}", summary="Podpisana aktualizacja CRL po SHA-256")
def get_crl_update(request: Request, object_id: str,
                   compression: str = Query("none", pattern="^(none|zlib)$")):
    for meta, data in certs.get_store().revocations.objects():
        if meta["id"] == object_id:
            packed = zlib.compress(data) if compression == "zlib" else data
            response = Response(packed, media_type="application/zlib" if compression == "zlib" else "application/octet-stream")
            return _served(request, response, "crl_delta" if meta["kind"] == "delta" else "crl_full", len(packed),
                           encoding=("JSON" if meta["kind"] == "bundle" else "DER") + ("+zlib" if compression == "zlib" else ""),
                           number=meta["number"])
    raise HTTPException(status_code=404, detail="Aktualizacja już niedostępna; pobierz nowe summary.")


@router.post("/ack", summary="Potwierdzenie po weryfikacji i trwałym zapisie CRL u odbiorcy")
async def acknowledge(request: Request):
    entry = neighbours.by_ip(request.client.host if request.client else None)
    if entry is None:
        raise HTTPException(status_code=403, detail="Potwierdzenia tylko od sąsiadów radiowych.")
    raw = b""
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > 256:
            raise HTTPException(status_code=413, detail="Potwierdzenie za duże.")
    import json
    try:
        value = json.loads(raw)["number"]
        if type(value) is not int or value < 0:
            raise ValueError()
    except (ValueError, TypeError, KeyError):
        raise HTTPException(status_code=400, detail="Niepoprawny numer CRL.")
    peer_state.confirm(entry["id"], value)
    return {"ok": True}


@router.get("/peers", summary="Obserwowane i potwierdzone wersje CRL sąsiadów")
def pki_peers():
    return peer_state.read()
