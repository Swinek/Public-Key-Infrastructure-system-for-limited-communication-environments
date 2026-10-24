"""Own certificate of the node, obtained automatically: the key is generated here, the CA approves every request.

On every WAN contact (contact.py, after pki_sync - the Root CA and the newest CRL are already stored):
    1. a request is pending  -> GET /pki/csr/<key fingerprint>
           APPROVED: GET /pki/certs/<serial>, install it if the pinned Root CA signed it for OUR pending key
           REJECTED: remembered; no new request until the operator asks for one (POST /api/certs/csr)
           PENDING:  nothing - the CA's decision wakes this node again (impulse cert_issued)
    2. no request, but the node needs a certificate (none, revoked, from another CA, expiring within
       RENEW_BEFORE_DAYS) -> new key + CSR (CN = NODE_ID), POST /pki/csr

The node never holds two certificates: the current one stays in use until the new one is installed, then it is
replaced (and the CA revokes the old one). The private key never leaves the node; only the CSR and the
certificate - public data - travel over the link. Revocation by the administrator therefore does not end in an
automatic new certificate: the revoked node files a request, and the administrator decides.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import certs
import config
import contact
import transfers
import wire


class EnrollError(Exception):
    pass


def needs_certificate(store: certs.CertStore, now: Optional[datetime] = None) -> Optional[str]:
    """Why this node needs a new certificate, or None when the current one is fine."""
    now = now or datetime.now(timezone.utc)
    cert = store.certificate()
    if cert is None:
        return "no certificate"
    status = store.check(cert, now).status.value
    if status in ("revoked", "invalid"):
        return f"certificate {status}"
    if cert.not_valid_after_utc - now < timedelta(days=config.RENEW_BEFORE_DAYS):
        return "certificate expiring"
    return None


def submit(peer: Dict[str, Any], request: Dict[str, Any]) -> Dict[str, Any]:
    body = request["csr_der"]
    try:
        fetched = wire.post_bytes(wire.peer_url(peer, "/pki/csr"), body, "application/pkcs10", 4096)
    except wire.WireError as exc:
        transfers.record("csr", "out", peer["id"], len(body), status="aborted", number=request["key_fingerprint"][:16],
                         note=str(exc)[:200])
        raise EnrollError(f"wniosek CSR nie został przyjęty: {exc}") from exc
    transfers.record("csr", "out", peer["id"], len(body), fetched.wire_bytes, encoding="DER",
                     number=request["key_fingerprint"][:16])
    answer = fetched.json()
    certs.get_store().set_pending_status(answer.get("status", "PENDING"), answer.get("reason"))
    print(f"[ENROLL] CSR sent to {peer['id']} (key {request['key_fingerprint'][:16]}...): {answer.get('status')}")
    return answer


def _install(peer: Dict[str, Any], serial: str) -> bool:
    store = certs.get_store()
    fetched = wire.get(wire.peer_url(peer, f"/pki/certs/{serial}"), config.MAX_PKI_OBJECT_BYTES)
    try:
        installed = store.install_issued(fetched.body)
    except certs.CertStoreError as exc:
        transfers.record("cert", "in", peer["id"], len(fetched.body), fetched.wire_bytes, status="rejected",
                         encoding="DER", number=serial, note=str(exc))
        raise EnrollError(f"certyfikat {serial} odrzucony: {exc}") from exc
    transfers.record("cert", "in", peer["id"], len(fetched.body), fetched.wire_bytes,
                     status="ok" if installed else "rejected", encoding="DER", number=serial,
                     note=None if installed else "not issued for the pending key")
    if installed:
        print(f"[ENROLL] certificate {serial} installed (previous one replaced)")
    return installed


def exchange(peer: Dict[str, Any]) -> Optional[str]:
    """Contact handler (WAN only): follow up the pending request or file a new one."""
    if peer["kind"] != contact.WAN:
        return None
    store = certs.get_store()
    if store.ca() is None:
        return None  # no pinned Root CA yet - nothing to check a certificate against
    pending = store.pending()
    if pending is not None:
        if pending.get("status") == "REJECTED":
            return "rejected"
        try:
            fetched = wire.get(wire.peer_url(peer, f"/pki/csr/{pending['key_fingerprint']}"), 4096)
        except wire.WireError as exc:
            if "HTTP 404" not in str(exc):
                raise EnrollError(str(exc)) from exc
            submit(peer, pending)  # the portal does not know it (e.g. not sent yet) - send it now
            return "submitted"
        transfers.record("summary", "in", peer["id"], len(fetched.body), fetched.wire_bytes, encoding="JSON",
                         note="csr status")
        answer = fetched.json()
        status = answer.get("status")
        if status == "APPROVED" and answer.get("serial_number"):
            return "installed" if _install(peer, str(answer["serial_number"])) else "not ours"
        store.set_pending_status(status or "PENDING", answer.get("reason"))
        if status == "REJECTED":
            print(f"[ENROLL] request {pending['key_fingerprint'][:16]}... rejected: {answer.get('reason')}")
        return (status or "pending").lower()
    reason = needs_certificate(store)
    if reason is None:
        return None
    print(f"[ENROLL] {reason} - new key and CSR")
    submit(peer, store.new_request(config.NODE_ID))
    return "submitted"


def request_now() -> Dict[str, Any]:
    """Operator's 'new request' (also after a rejection): new key + CSR, sent on the next WAN contact."""
    request = certs.get_store().new_request(config.NODE_ID)
    contact.on_wan()  # if the portal is reachable, the request goes out now; otherwise on `internet on`
    return {k: v for k, v in request.items() if k != "csr_der"}


exchange.__name__ = "enroll"
contact.register(exchange)
