"""PKI of the edge app: take the certificate from the edge client (diagram arrow "cert"), show what is used.

The edge app does not accept uploads. Before authenticating it takes the active certificate (with its key,
the Root CA and the CRL) from the edge client of its node and checks everything against the pinned Root CA
before storing it. All checks live in pki/store.py and pki/verifier.py.
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, HTTPException

import config
import pki
from utils import atomic_write_bytes

router = APIRouter(prefix="/api/pki", tags=["PKI (offline)"])

# A certificate, key or CRL of this PKI is a few KB; anything far larger is not a PKI object.
MAX_OBJECT_BYTES = 256 * 1024
SOURCE_FILE = "source.json"  # when the certificate was taken from the edge client, next to the store files


def _common_name(cert) -> str:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def current_source() -> Optional[Dict[str, Any]]:
    try:
        return json.loads((config.PKI_DIR / SOURCE_FILE).read_text())
    except (FileNotFoundError, ValueError):
        return None


def _status(now: datetime) -> Dict[str, Any]:
    store = pki.get_store()
    cert = store.node_certificate()
    own = None if cert is None else pki.verify(cert, store.ca(), store.crl(), now).to_dict()
    return {
        "node_id": config.NODE_ID,
        "node_name": config.NODE_NAME,
        "app_id": config.APP_ID,
        "checked_at": now.isoformat(),
        **store.status(),
        "source": current_source(),
        "own_certificate": own,
    }


def _same_ca(store, data: bytes) -> bool:
    current = store.ca()
    try:
        return current is not None and pki.store.fingerprint(pki.store.load_certificate(data)) == \
            pki.store.fingerprint(current)
    except pki.PkiError:
        return False  # garbage: install_ca reports it


def _same_node(store, cert_data: bytes, key_data: Optional[bytes]) -> bool:
    """The same certificate with the same key is already stored (a key alone never changes without the cert)."""
    current, key = store.node_certificate(), store.private_key()
    if current is None or key is None or key_data is None:
        return False
    try:
        incoming = pki.store.load_certificate(cert_data)
        incoming_key = serialization.load_pem_private_key(key_data, password=None)
    except (pki.PkiError, ValueError, TypeError):
        return False  # install_node reports it
    return incoming == current and incoming_key.public_key() == key.public_key()


def install_objects(ca: Optional[bytes], cert: Optional[bytes], key: Optional[bytes],
                    crl: Optional[bytes]) -> Tuple[List[str], List[str]]:
    """Verifies and stores what came from the edge client. Returns (installed, warnings)."""
    for field, data in (("ca", ca), ("cert", cert), ("key", key), ("crl", crl)):
        if data is not None and len(data) > MAX_OBJECT_BYTES:
            raise HTTPException(status_code=413, detail=f"'{field}' przekracza {MAX_OBJECT_BYTES} B.")
    if (cert is None) != (key is None):
        raise HTTPException(status_code=400, detail="Certyfikat i klucz prywatny muszą przyjść razem.")

    store = pki.get_store()
    installed, warnings = [], []
    try:
        # Order matters: the certificate and the CRL are checked against the (newly) installed CA.
        # Objects identical to the stored ones are not reinstalled, so `installed` lists only real changes.
        if ca is not None and not _same_ca(store, ca):
            store.install_ca(ca)
            installed.append("ca")
        if cert is not None and not _same_node(store, cert, key):
            node_cert = store.install_node(cert, key)
            installed.append("cert")
            if _common_name(node_cert) != config.NODE_ID:
                warnings.append(f"CN certyfikatu ('{_common_name(node_cert)}') różni się od NODE_ID ('{config.NODE_ID}').")
        if crl is not None:
            if store.update_crl(crl):
                installed.append("crl")
            else:
                warnings.append("CRL pominięta: Edge app ma już tę samą lub nowszą listę.")
    except pki.PkiError as exc:
        print(f"[PKI] Rejected ({', '.join(installed) or 'nothing'} installed before): {exc}")
        raise HTTPException(status_code=400, detail={"error": str(exc), "installed": installed})
    return installed, warnings


def _edge_client_unreachable(exc: Exception) -> HTTPException:
    return HTTPException(status_code=502, detail=f"Edge client ({config.EDGE_CLIENT_URL}) jest nieosiągalny: {exc}")


@router.get("/status", summary="Local PKI store after a refresh from the edge client (offline: the last copy)")
def get_pki_status():
    # Without the refresh the panel showed the copy from the last use (e.g. an old certificate and a stale CRL
    # long after the edge client had new ones). The refresh is a local mgmt_N request, not a radio transfer.
    try:
        warning = ensure_certificate()
    except HTTPException as exc:
        warning = f"Brak danych od Edge clienta: {exc.detail}"
    return {**_status(datetime.now(timezone.utc)), "warning": warning}


def take_certificate() -> Dict[str, Any]:
    """Takes the certificate + key, Root CA and CRL from the edge client and installs what changed."""
    try:
        resp = requests.get(f"{config.EDGE_CLIENT_URL}/api/certs/bundle", timeout=config.EDGE_CLIENT_TIMEOUT)
    except requests.RequestException as exc:
        raise _edge_client_unreachable(exc)
    if resp.status_code != 200:
        try:
            detail = resp.json().get("detail", resp.text)
        except (ValueError, AttributeError):
            detail = resp.text
        raise HTTPException(status_code=resp.status_code, detail=f"Edge client odmówił: {detail}")

    bundle = resp.json()
    as_bytes = lambda name: None if bundle.get(name) is None else bundle[name].encode()
    if bundle.get("certificate") is None:
        raise HTTPException(status_code=404, detail="Edge client nie ma jeszcze certyfikatu.")
    installed, warnings = install_objects(as_bytes("ca"), as_bytes("certificate"), as_bytes("private_key"),
                                          as_bytes("crl_pem"))

    serial = str(pki.get_store().node_certificate().serial_number)
    source = {"serial_number": serial, "fetched_at": datetime.now(timezone.utc).isoformat()}
    atomic_write_bytes(config.PKI_DIR / SOURCE_FILE, json.dumps(source).encode())
    if installed:
        print(f"[PKI] Took from the edge client (certificate {serial}): {', '.join(installed)}")
    return {"installed": installed, "warnings": warnings, "status": _status(datetime.now(timezone.utc))}


def ensure_certificate() -> Optional[str]:
    """Before authenticating: take the current certificate, Root CA and CRL from the edge client.

    Offline fallback: when the edge client cannot provide them, the last taken copy is used (returns a warning).
    """
    try:
        take_certificate()
        return None
    except HTTPException as exc:
        if pki.get_store().node_certificate() is None:
            raise
        return f"Nie pobrano nowych danych od Edge clienta ({exc.detail}) – używam ostatnio pobranego certyfikatu."


@router.post("/fetch", summary="Take the certificate (+ key, Root CA, CRL) from the edge client and install it")
def fetch_from_edge_client():
    return take_certificate()
