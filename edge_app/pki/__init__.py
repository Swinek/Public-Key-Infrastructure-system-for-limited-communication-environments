"""PKI of the edge node, separated from the application.

The application only asks "is this certificate OK?" (check_certificate). The local store (store.py) keeps
the pinned Root CA, the node certificate/key and the last CRL; the verifier (verifier.py) works offline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import config
from pki.store import PkiError, PkiStore, load_certificate
from pki.verifier import Status, Verdict, verify

_store: Optional[PkiStore] = None


def get_store() -> PkiStore:
    global _store
    if _store is None:
        _store = PkiStore(config.PKI_DIR, config.CA_FINGERPRINT)
    return _store


def check_certificate(data: bytes, now: Optional[datetime] = None) -> Verdict:
    """Verifies a certificate (PEM or DER) against the local store, without network access."""
    try:
        cert = load_certificate(data)
    except PkiError as exc:
        return Verdict(Status.INVALID, str(exc))
    store = get_store()
    return verify(cert, store.ca(), store.crl(), now or datetime.now(timezone.utc), store.delta())


__all__ = ["PkiError", "PkiStore", "Status", "Verdict", "check_certificate", "get_store", "verify"]
