"""PKI of the edge app: take the certificate from the edge client (diagram arrow "cert"), show what is used.

The edge app does not accept uploads. Before authenticating it takes the active certificate (with its key,
the Root CA and the CRL) from the edge client of its node and checks everything against the pinned Root CA
before storing it. All checks live in pki/store.py and pki/verifier.py.
"""
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
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
    own = None if cert is None else pki.verify(cert, store.ca(), store.crl(), now, store.delta()).to_dict()
    return {
        "node_id": config.NODE_ID,
        "node_name": config.NODE_NAME,
        "app_id": config.APP_ID,
        "checked_at": now.isoformat(),
        **store.status(),
        "source": current_source(),
        "own_certificate": own,
    }


def install_objects(ca: Optional[bytes], cert: Optional[bytes], key: Optional[bytes],
                    crl: Optional[bytes], crl_state: Optional[bytes] = None) -> Tuple[List[str], List[str]]:
    """Verifies and stores what came from the edge client. Returns (installed, warnings)."""
    for field, data in (("ca", ca), ("cert", cert), ("key", key), ("crl", crl), ("crl_state", crl_state)):
        if data is not None and len(data) > MAX_OBJECT_BYTES:
            raise HTTPException(status_code=413, detail=f"'{field}' przekracza {MAX_OBJECT_BYTES} B.")
    if (cert is None) != (key is None):
        raise HTTPException(status_code=400, detail="Certyfikat i klucz prywatny muszą przyjść razem.")

    store = pki.get_store()
    installed, warnings = [], []
    try:
        # Order matters: the certificate and the CRL are checked against the (newly) installed CA.
        if ca is not None:
            store.install_ca(ca)
            installed.append("ca")
        if cert is not None:
            node_cert = store.install_node(cert, key)
            installed.append("cert")
            if _common_name(node_cert) != config.NODE_ID:
                warnings.append(f"CN certyfikatu ('{_common_name(node_cert)}') różni się od NODE_ID ('{config.NODE_ID}').")
        if crl is not None or crl_state is not None:
            changed = (store.update_revocation(crl_state, "bundle") if crl_state is not None
                       else store.update_crl(crl))
            if changed:
                installed.append("crl")
            else:
                warnings.append("CRL pominięta: Edge app ma już tę samą lub nowszą listę.")
    except pki.PkiError as exc:
        print(f"[PKI] Rejected ({', '.join(installed) or 'nothing'} installed before): {exc}")
        raise HTTPException(status_code=400, detail={"error": str(exc), "installed": installed})
    return installed, warnings


def _edge_client_unreachable(exc: Exception) -> HTTPException:
    return HTTPException(status_code=502, detail=f"Edge client ({config.EDGE_CLIENT_URL}) jest nieosiągalny: {exc}")


@router.get("/status", summary="Local PKI store: CA, own certificate, CRL and the verdict for the own certificate")
def get_pki_status():
    return _status(datetime.now(timezone.utc))


def take_certificate() -> Dict[str, Any]:
    """Takes the certificate + key, Root CA and CRL from the edge client and installs them."""
    try:
        resp = requests.get(f"{config.EDGE_CLIENT_URL}/api/certs/bundle", timeout=config.EDGE_CLIENT_TIMEOUT)
    except requests.RequestException as exc:
        raise _edge_client_unreachable(exc)
    if resp.status_code != 200:
        detail = resp.json().get("detail", resp.text)
        raise HTTPException(status_code=resp.status_code, detail=f"Edge client odmówił: {detail}")

    bundle = resp.json()
    as_bytes = lambda name: None if bundle.get(name) is None else bundle[name].encode()
    if bundle.get("certificate") is None:
        raise HTTPException(status_code=404, detail="Edge client nie ma jeszcze certyfikatu.")
    installed, warnings = install_objects(as_bytes("ca"), as_bytes("certificate"), as_bytes("private_key"),
                                          as_bytes("crl_pem"), as_bytes("crl_state"))

    serial = str(pki.get_store().node_certificate().serial_number)
    source = {"serial_number": serial, "fetched_at": datetime.now(timezone.utc).isoformat()}
    atomic_write_bytes(config.PKI_DIR / SOURCE_FILE, json.dumps(source).encode())
    print(f"[PKI] Took certificate {serial} from the edge client: {', '.join(installed)}")
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
