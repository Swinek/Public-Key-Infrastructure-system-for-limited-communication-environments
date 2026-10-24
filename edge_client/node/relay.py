"""Certificate request of a node without internet, carried by its neighbours to the portal and back (Stage 3c).

The node (enroll.py) puts its CSR into the store-and-forward queue as an item for "portal" (saf.py). Every carrier
checks it, and the first one with a WAN link hands it over:

    WAN contact (or a CSR queued while the portal is reachable):
        csr items in the queue   -> POST /pki/csr (route in X-PKI-Route) -> the item leaves the queue,
                                    the key fingerprint goes to DATA_DIR/saf/relayed.json {fingerprint, node, at}
        relayed.json entries     -> GET /pki/csr/<fingerprint>
            APPROVED: GET /pki/certs/<serial>, checked (pinned Root CA, CN, key) -> saf item "cert" to the node
            REJECTED: saf item "csr_result" (unsigned hint; the node confirms it on its own WAN contact)
            PENDING:  kept - the CA's decision wakes this node (impulse cert_issued from the portal)

The carrier is not trusted: it could file a request with CN = another node and its own key. The administrator
therefore approves every request and compares the key fingerprint shown in the node's panel with the one in the CA
panel (with the route) out of band. A certificate for another key is useless to the node - it never installs it.
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

import certs
import config
import contact
import saf
import transfers
import utils
import wire

ROUTE_HEADER = "X-PKI-Route"
RELAYED_FILE = "relayed.json"

_LOCK = threading.Lock()


class RelayError(Exception):
    pass


def _path():
    return config.DATA_DIR / "saf" / RELAYED_FILE


def relayed() -> List[Dict[str, Any]]:
    with _LOCK:
        try:
            return json.loads(_path().read_text(encoding="utf-8"))
        except FileNotFoundError:
            return []
        except (OSError, ValueError) as exc:
            print(f"[RELAY] Cannot read {RELAYED_FILE}: {exc} - starting empty")
            return []


def _update(change) -> None:
    with _LOCK:
        try:
            entries = json.loads(_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            entries = []
        utils.atomic_write_bytes(_path(), json.dumps(change(entries), ensure_ascii=False).encode("utf-8"))


def _remember(fingerprint: str, node_id: str) -> None:
    entry = {"key_fingerprint": fingerprint, "node_id": node_id, "at": datetime.now(timezone.utc).isoformat()}
    _update(lambda entries: [e for e in entries if e["key_fingerprint"] != fingerprint] + [entry])


def _forget(fingerprint: str) -> None:
    _update(lambda entries: [e for e in entries if e["key_fingerprint"] != fingerprint])


def hand_over(peer: Dict[str, Any]) -> Dict[str, int]:
    """CSR items carried here -> portal. Accepted or refused (409/400) ones leave the queue; unreachable = kept."""
    counts = {"handed_over": 0, "refused": 0}
    for item in saf.queue():
        if item["type"] != "csr":
            continue
        body = saf.content(item["msg_id"])
        if body is None:
            continue
        number = item["msg_id"][:16]
        route = {ROUTE_HEADER: ",".join(item["hops"])} if len(item["hops"]) > 1 else None  # own one: direct
        try:
            fetched = wire.post_bytes(wire.peer_url(peer, "/pki/csr"), body, "application/pkcs10", 4096,
                                      headers=route)
        except wire.WireError as exc:
            if "HTTP 409" not in str(exc) and "HTTP 400" not in str(exc):  # portal unreachable: nothing was sent
                raise RelayError(f"portal nie przyjął wniosku {item['origin_id']}: {exc}") from exc
            # The portal decided (another pending request of that node / bad request): carrying it further is useless.
            counts["refused"] += 1
            saf.drop(item["msg_id"])
            transfers.record("csr", "out", peer["id"], len(body), status="rejected", encoding="DER", number=number,
                             note=f"for {item['origin_id']}: {str(exc)[:160]}")
            continue
        counts["handed_over"] += 1
        saf.drop(item["msg_id"])
        transfers.record("csr", "out", peer["id"], len(body), fetched.wire_bytes, encoding="DER", number=number,
                         note=f"carried for {item['origin_id']} via {' -> '.join(item['hops'])}")
        if item["origin_id"] != config.NODE_ID:  # own request: enroll.py follows it up
            _remember(item["msg_id"], item["origin_id"])
        print(f"[RELAY] CSR of {item['origin_id']} handed to the portal: {fetched.json().get('status')}")
    return counts


def _checked_certificate(data: bytes, entry: Dict[str, Any]) -> bytes:
    """The issued certificate before it is carried: pinned Root CA, CN = node, key of the relayed request."""
    ca = certs.get_store().ca()
    try:
        cert = certs.load_certificate(data)
        cert.verify_directly_issued_by(ca)
    except (certs.CertStoreError, ValueError, TypeError, InvalidSignature):
        raise RelayError("certyfikat nie został wystawiony przez przypięty Root CA") from None
    if saf.common_name(cert.subject) != entry["node_id"]:
        raise RelayError("CN certyfikatu różny od węzła z wniosku")
    if certs.key_fingerprint(cert.public_key()) != entry["key_fingerprint"]:
        raise RelayError("certyfikat na inny klucz niż przenoszony wniosek")
    return cert.public_bytes(serialization.Encoding.DER)


def _carry(kind: str, entry: Dict[str, Any], **fields) -> Dict[str, Any]:
    item = saf.new_item(kind, entry["node_id"], **fields)
    return saf.enqueue_local(item, fields.get("content"))


def collect(peer: Dict[str, Any]) -> Dict[str, int]:
    """Decisions of the CA on requests this node carried: certificate / rejection back to the node via SAF."""
    counts = {"certificates": 0, "rejections": 0, "pending": 0}
    cutoff = datetime.now(timezone.utc) - timedelta(hours=config.SAF_TTL_HOURS)
    for entry in relayed():
        fingerprint = entry["key_fingerprint"]
        at = datetime.fromisoformat(entry["at"])
        if at < cutoff:
            print(f"[RELAY] request of {entry['node_id']} ({fingerprint[:16]}...) older than TTL - forgotten")
            _forget(fingerprint)
            continue
        try:
            fetched = wire.get(wire.peer_url(peer, f"/pki/csr/{fingerprint}"), 4096)
        except wire.WireError as exc:
            if "HTTP 404" not in str(exc):
                raise RelayError(str(exc)) from exc
            _forget(fingerprint)
            continue
        transfers.record("summary", "in", peer["id"], len(fetched.body), fetched.wire_bytes, encoding="JSON",
                         note=f"csr status (carried for {entry['node_id']})")
        answer = fetched.json()
        status = answer.get("status")
        if status == "APPROVED" and answer.get("serial_number"):
            serial = str(answer["serial_number"])
            got = wire.get(wire.peer_url(peer, f"/pki/certs/{serial}"), config.MAX_PKI_OBJECT_BYTES)
            try:
                der = _checked_certificate(got.body, entry)
            except RelayError as exc:
                transfers.record("cert", "in", peer["id"], len(got.body), got.wire_bytes, status="rejected",
                                 number=serial, note=str(exc))
                _forget(fingerprint)
                continue
            transfers.record("cert", "in", peer["id"], len(got.body), got.wire_bytes, encoding="DER", number=serial,
                             note=f"carried for {entry['node_id']}")
            _carry("cert", entry, content=der, msg_id=hashlib.sha256(der).hexdigest())
            print(f"[RELAY] certificate {serial} for {entry['node_id']} goes back via the neighbours")
            counts["certificates"] += 1
            _forget(fingerprint)
        elif status == "REJECTED":
            result = {"key_fingerprint": fingerprint, "status": "REJECTED", "reason": (answer.get("reason") or "")[:255]}
            msg_id = hashlib.sha256(f"csr_result:{fingerprint}".encode()).hexdigest()
            _carry("csr_result", entry, result=result, msg_id=msg_id)
            counts["rejections"] += 1
            _forget(fingerprint)
        else:
            counts["pending"] += 1
    return counts


def exchange(peer: Dict[str, Any]) -> Dict[str, int]:
    """Contact handler (WAN only): hand carried requests over, then follow up the ones handed over earlier."""
    if peer["kind"] != contact.WAN or certs.get_store().ca() is None:
        return {}
    return {**hand_over(peer), **collect(peer)}


def _queued(item: Dict[str, Any]) -> None:
    """A CSR has just been queued here: if the portal is reachable now, hand it over without waiting for a contact."""
    if item["type"] != "csr" or certs.get_store().ca() is None:
        return
    try:
        hand_over(contact.portal_peer())
    except RelayError:
        print(f"[RELAY] portal unreachable - CSR of {item['origin_id']} waits for a WAN contact or a neighbour")


exchange.__name__ = "relay"
contact.register(exchange)
saf.on_queued(_queued)
