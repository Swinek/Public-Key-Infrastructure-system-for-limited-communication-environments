"""Own certificate of the node: the key is generated here, the CA approves every request.

A request is filed ONLY by the operator of this node (`client.sh csr N`, POST /api/certs/csr -> request_now).
The node never files one by itself - not without a certificate, not after a revocation, not before expiry.
A node without a valid certificate still carries the requests and certificates of other nodes (relay.py,
saf.py): they are public data signed by their owner / the CA and checked by every carrier, so a carrier
cannot forge them.

On every WAN contact (contact.py, after pki_sync - the Root CA and the newest CRL are already stored), only when
this node has a request:
    unknown to the portal (not sent yet) -> POST /pki/csr
    known to the portal                  -> GET /pki/csr/<key fingerprint>
        APPROVED: GET /pki/certs/<serial>, install it if the pinned Root CA signed it for OUR pending key
        REJECTED: remembered; nothing more until the operator files a new request
        PENDING:  nothing - the CA's decision wakes this node again (impulse cert_issued)

On a radio contact the node with a request not sent yet (NEW) puts the CSR into the store-and-forward queue for
the portal and marks it RELAYED; a neighbour with internet hands it over and the certificate comes back the same
way (relay.py, saf.py). If the node gets internet itself, the WAN step continues with the same key (the portal
accepts the same key idempotently).

The node never holds two certificates: the current one stays in use until the new one is installed, then it is
replaced (and the CA revokes the old one). The private key never leaves the node; only the CSR and the
certificate - public data - travel over the link.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import certs
import config
import contact
import neighbours
import saf
import transfers
import wire


class EnrollError(Exception):
    pass


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


def relay(store: certs.CertStore) -> Optional[str]:
    """Radio contact: a request not sent yet goes to the portal with the neighbours (store-and-forward)."""
    pending = store.pending()
    if pending is None or pending.get("status") != "NEW":  # only the operator's request, and only once
        return None
    item = saf.new_item("csr", saf.PORTAL, content=pending["csr_der"], msg_id=pending["key_fingerprint"])
    store.set_pending_status("RELAYED")
    result = saf.enqueue_local(item, pending["csr_der"])
    print(f"[ENROLL] CSR (key {pending['key_fingerprint'][:16]}...) queued for the portal, "
          f"announced to {result['announced_to']}")
    return "relayed"


def exchange(peer: Dict[str, Any]) -> Optional[str]:
    """Contact handler: over WAN send / follow up the operator's request; over radio relay it."""
    store = certs.get_store()
    if store.ca() is None:
        return None  # no pinned Root CA yet - nothing to check a certificate against
    if peer["kind"] == contact.NEIGHBOUR:
        return relay(store)
    if peer["kind"] != contact.WAN:
        return None
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
    return None  # no request: nothing to send - only the operator files one (request_now)


def request_now() -> Dict[str, Any]:
    """Operator's 'new request' - the only way a request is filed: new key + CSR, sent now or on the next contact.

    A request still waiting for the CA is kept: a new key would make the certificate approved for the old one
    useless, and the portal accepts one pending request per node."""
    store = certs.get_store()
    request = store.pending()
    if request is None or request.get("status") == "REJECTED":
        request = store.new_request(config.NODE_ID)
    contact.on_wan(wait=True)  # portal reachable: the request goes out now
    if (store.pending() or {}).get("status") == "NEW" and neighbours.current():
        relay(store)  # no internet: with the neighbours in range; otherwise on the next contact
    request = store.pending() or request
    return {k: v for k, v in request.items() if k != "csr_der"}


exchange.__name__ = "enroll"
contact.register(exchange)
