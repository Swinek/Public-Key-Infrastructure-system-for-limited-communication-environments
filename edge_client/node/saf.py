"""Store-and-forward of messages and files for nodes that are not in radio range (epidemic routing).

A message or file for a node that is not a neighbour right now is not rejected: it is put into a persistent queue
and travels with the neighbours. On every radio contact (contact.py) each side pulls from the other:

    POST /api/saf/offer {"known": [<16-hex prefixes of msg_id>]}   ->  {"items": [...]}  (only the missing ones)
    GET  /api/saf/items/<msg_id>/content                            raw bytes of a file item (size + SHA-256 checked)

Decision (2026-10-24): epidemic - every node keeps a copy and offers it to every neighbour that does not know it
yet, instead of handing the custody to a single neighbour. Without knowledge of the topology a copy per neighbour
is the only way to reach a node whose path is unknown; duplicates are prevented by the exchanged id lists, and the
spread is bounded by TTL (SAF_TTL_HOURS from creation) and the hop limit (P2P_MAX_HOPS).

Every node remembers the ids it has ever held or received (seen.json), so an item does not come back after it was
delivered or expired. The destination delivers the item to its inbox / received_files and does not offer it again.

Stage 3c: the certificate request of a node without internet and the certificate issued for it travel the same way
(relay.py). Both are public data checked by every carrier before it queues them, so garbage does not take the link
on later hops:
    csr         destination "portal", content = CSR (DER), msg_id = SHA-256 of the key; CSR signature valid, CN = origin
    cert        destination = CN of the certificate, content = certificate (DER), msg_id = its SHA-256; signed by the
                pinned Root CA - the destination installs it only for its own pending key (certs.install_issued)
    csr_result  "rejected according to a carrier" - not signed, so only a hint; the node's own WAN contact decides
The msg_id is deterministic: copies made by different carriers are one item (no duplicates in the network or portal).

Layout of DATA_DIR/saf/:
    queue.json        items carried for other nodes (metadata, message text inline)
    blobs/<msg_id>    content of file / csr / cert items
    seen.json         every msg_id ever held or delivered here
    relayed.json      requests this node handed to the portal for others (relay.py)
"""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID

import certs
import config
import contact
import state
import transfers
import utils
import wire

ID_PREFIX = 16  # hex characters of msg_id sent in the "known" list (64 bits - no collisions at this scale)
MAX_MESSAGE_CHARS = 10_000
MAX_CSR_BYTES = 4096
KINDS = ("msg", "file", "csr", "cert", "csr_result")
BLOB_KINDS = ("file", "csr", "cert")  # content fetched separately (GET /api/saf/items/<msg_id>/content)
PORTAL = "portal"  # destination of csr items: the first carrier with a WAN link hands them over (relay.py)

_LOCK = threading.Lock()
_ON_QUEUED: List[Callable[[Dict[str, Any]], None]] = []


class SafError(ValueError):
    pass


def _dir() -> Path:
    return config.DATA_DIR / "saf"


def _load(name: str, default):
    try:
        return json.loads((_dir() / name).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except (OSError, ValueError) as exc:
        print(f"[SAF] Cannot read {name}: {exc} - starting empty")
        return default


def _save(name: str, data) -> None:
    utils.atomic_write_bytes(_dir() / name, json.dumps(data, ensure_ascii=False).encode("utf-8"))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: str) -> Optional[datetime]:
    try:
        value = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _blob(msg_id: str) -> Path:
    return _dir() / "blobs" / msg_id


def _valid_id(msg_id: Any) -> bool:
    return isinstance(msg_id, str) and 16 <= len(msg_id) <= 64 and all(c in "0123456789abcdef" for c in msg_id)


def queue() -> List[Dict[str, Any]]:
    with _LOCK:
        return list(_load("queue.json", []))


def seen() -> Set[str]:
    with _LOCK:
        return set(_load("seen.json", []))


def known_prefixes() -> List[str]:
    """Ids this node already has (carried, delivered, expired) - sent to a neighbour so it offers only new items."""
    with _LOCK:
        ids = set(_load("seen.json", [])) | {i["msg_id"] for i in _load("queue.json", [])}
    return sorted(i[:ID_PREFIX] for i in ids)


def on_queued(hook: Callable[[Dict[str, Any]], None]) -> None:
    """Called for every item queued here (relay.py: a carried CSR goes to the portal at once if it is reachable)."""
    if hook not in _ON_QUEUED:
        _ON_QUEUED.append(hook)


def _purge_expired(items: List[Dict[str, Any]], now: datetime) -> List[Dict[str, Any]]:
    kept = []
    for item in items:
        expires = _parse(item.get("expires_at", ""))
        if expires is not None and expires > now:
            kept.append(item)
        else:
            _blob(item["msg_id"]).unlink(missing_ok=True)
            print(f"[SAF] {item['msg_id']} for {item.get('destination_id')} expired - dropped")
    return kept


def _max_size(kind: str) -> int:
    return {"file": config.SAF_MAX_FILE_BYTES, "csr": MAX_CSR_BYTES, "cert": config.MAX_PKI_OBJECT_BYTES}[kind]


def new_item(kind: str, destination_id: str, *, message: Optional[str] = None, filename: Optional[str] = None,
             content: Optional[bytes] = None, content_type: Optional[str] = None,
             msg_id: Optional[str] = None, result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Item created by this node (origin)."""
    now = _now()
    item = {
        "msg_id": msg_id or uuid.uuid4().hex, "type": kind,
        "origin_id": config.NODE_ID, "origin_name": config.NODE_NAME, "destination_id": destination_id,
        "hops": [config.NODE_ID], "created_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=config.SAF_TTL_HOURS)).isoformat(),
    }
    if kind == "msg":
        item["message"] = message
    elif kind == "csr_result":
        item["result"] = result
    else:
        item.update({"size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
        if kind == "file":
            item.update({"filename": filename, "content_type": content_type})
    return item


def common_name(name: x509.Name) -> str:
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(values[0].value) if values else ""


def _check_pki(item: Dict[str, Any], content: bytes) -> None:
    """Content of a csr / cert item, checked by every carrier (not only by the destination)."""
    if item["type"] == "csr":
        try:
            csr = x509.load_der_x509_csr(content)
        except ValueError:
            raise SafError("niepoprawny wniosek CSR") from None
        if not csr.is_signature_valid:
            raise SafError("niepoprawny podpis wniosku CSR")
        if common_name(csr.subject) != item["origin_id"]:
            raise SafError("CN wniosku różny od nadawcy")
        if certs.key_fingerprint(csr.public_key()) != item["msg_id"]:
            raise SafError("msg_id różny od odcisku klucza z wniosku")
        return
    ca = certs.get_store().ca()
    if ca is None:
        raise SafError("brak Root CA – nie można sprawdzić certyfikatu")
    try:
        cert = x509.load_der_x509_certificate(content)
        cert.verify_directly_issued_by(ca)
    except (ValueError, TypeError, InvalidSignature):
        raise SafError("certyfikat nie został wystawiony przez przypięty Root CA") from None
    if common_name(cert.subject) != item["destination_id"]:
        raise SafError("CN certyfikatu różny od adresata")
    if item["msg_id"] != item["sha256"]:
        raise SafError("msg_id różny od SHA-256 certyfikatu")


def _check_result(item: Dict[str, Any]) -> None:
    result = item.get("result")
    reason = result.get("reason") if isinstance(result, dict) else None
    if (not isinstance(result, dict) or not _valid_id(result.get("key_fingerprint"))
            or result.get("status") != "REJECTED" or not isinstance(reason or "", str) or len(reason or "") > 255):
        raise SafError("niepoprawny wynik wniosku")


def validate(item: Dict[str, Any], content: Optional[bytes] = None) -> None:
    """Checks an item received from a neighbour (untrusted) before it is stored or delivered."""
    if not isinstance(item, dict) or not _valid_id(item.get("msg_id")):
        raise SafError("niepoprawny msg_id")
    kind = item.get("type")
    if kind not in KINDS:
        raise SafError("nieznany typ elementu")
    hops = item.get("hops")
    if not isinstance(hops, list) or not hops or not all(isinstance(h, str) for h in hops):
        raise SafError("niepoprawna lista skoków")
    if config.NODE_ID in hops:
        raise SafError(f"pętla: {config.NODE_ID} jest już w {hops}")
    if len(hops) >= config.P2P_MAX_HOPS:
        raise SafError(f"przekroczony limit skoków ({config.P2P_MAX_HOPS})")
    if not isinstance(item.get("destination_id"), str) or not item["destination_id"]:
        raise SafError("brak adresata")
    expires, created = _parse(item.get("expires_at", "")), _parse(item.get("created_at", ""))
    if expires is None or created is None or expires <= _now():
        raise SafError("element wygasł albo nie ma poprawnego TTL")
    if kind == "msg":
        if not isinstance(item.get("message"), str) or len(item["message"]) > MAX_MESSAGE_CHARS:
            raise SafError("niepoprawna treść wiadomości")
    elif kind == "csr_result":
        _check_result(item)
    else:
        if kind == "csr" and (item["destination_id"] != PORTAL or item.get("origin_id") != hops[0]):
            raise SafError("wniosek CSR musi iść od swojego węzła do portalu")
        size = wire.optional_int(item.get("size"))
        if size is None or size < 0 or size > _max_size(kind):
            raise SafError("niepoprawny rozmiar treści")
        if kind == "file":
            name = Path(str(item.get("filename") or "")).name
            if not name or name.startswith("."):
                raise SafError("niepoprawna nazwa pliku")
        if content is not None:
            if len(content) != size or hashlib.sha256(content).hexdigest() != item.get("sha256"):
                raise SafError("treść nie zgadza się z rozmiarem / SHA-256")
            if kind in ("csr", "cert"):
                _check_pki(item, content)


def _limit_ttl(item: Dict[str, Any]) -> None:
    """A neighbour cannot extend the life of an item beyond SAF_TTL_HOURS from its creation."""
    created = _parse(item["created_at"])
    cap = created + timedelta(hours=config.SAF_TTL_HOURS)
    if _parse(item["expires_at"]) > cap:
        item["expires_at"] = cap.isoformat()


def _install_cert(item: Dict[str, Any], content: bytes, route: List[str]) -> Dict[str, Any]:
    """A certificate carried to this node: installed only for its own pending key, whoever delivered it."""
    store = certs.get_store()
    current = store.certificate()
    if current is not None and certs.fingerprint(current) == item["msg_id"]:
        return {"status": "ALREADY_INSTALLED", "route": route}  # e.g. it came over WAN first
    try:
        installed = store.install_issued(content)
    except certs.CertStoreError as exc:
        print(f"[SAF] certificate from {item['origin_id']} not installed: {exc}")
        installed = False
    if installed:
        print(f"[SAF DELIVERED] own certificate via {' -> '.join(route)} installed (previous one replaced)")
    return {"status": "INSTALLED" if installed else "NOT_OURS", "route": route}


def _result_hint(item: Dict[str, Any], route: List[str]) -> Dict[str, Any]:
    """'Rejected' reported by a carrier: shown to the operator, but the request stays open for the own WAN check."""
    result, store = item["result"], certs.get_store()
    pending = store.pending()
    if (pending is None or pending["key_fingerprint"] != result["key_fingerprint"]
            or pending.get("status") not in ("NEW", "RELAYED")):
        return {"status": "IGNORED", "route": route}
    reason = f"odrzucony wg pośrednika {item['origin_id']} (niepotwierdzone): {result.get('reason') or ''}"
    store.set_pending_status("RELAYED", reason[:255])
    return {"status": "HINT", "route": route}


def _deliver(item: Dict[str, Any], content: Optional[bytes]) -> Dict[str, Any]:
    route, hops = item["hops"], item["hops"][:-1]
    if item["type"] == "cert":
        return _install_cert(item, content, route)
    if item["type"] == "csr_result":
        return _result_hint(item, route)
    if item["type"] == "msg":
        entry, created = state.add_inbox_entry({
            "msg_id": item["msg_id"], "sender_id": hops[-1], "sender_name": hops[-1],
            "origin_id": item["origin_id"], "origin_name": item.get("origin_name") or item["origin_id"],
            "hops": hops, "route": route, "message": item["message"], "sent_at": item["created_at"],
            "received_at": _now().isoformat(), "store_and_forward": True,
        })
        if created:
            print(f"[SAF DELIVERED] message from {item['origin_id']} via {' -> '.join(route)}: {item['message']}")
        return {"status": "DELIVERED" if created else "DUPLICATE", "route": route}
    name = state.save_received_file(item["filename"], content)
    print(f"[SAF DELIVERED] file '{name}' ({len(content)} B) from {item['origin_id']} via {' -> '.join(route)}")
    return {"status": "SAVED", "filename": name, "route": route}


def accept(item: Dict[str, Any], content: Optional[bytes] = None) -> Tuple[str, Dict[str, Any]]:
    """Stores an item from a neighbour (or created here): delivers it if addressed to this node, otherwise queues it.

    Returns (outcome, details); outcome is 'delivered', 'queued' or 'duplicate'."""
    if item["hops"][-1] != config.NODE_ID:  # this node is the next hop on the item's route
        item = {**item, "hops": item["hops"] + [config.NODE_ID]}
    for_me = item["destination_id"] == config.NODE_ID
    with _LOCK:
        seen_ids = set(_load("seen.json", []))
        items = _load("queue.json", [])
        if item["msg_id"] in seen_ids or any(i["msg_id"] == item["msg_id"] for i in items):
            return "duplicate", {}
        if not for_me:
            _limit_ttl(item)
            if content is not None:
                utils.atomic_write_bytes(_blob(item["msg_id"]), content)  # blob first: a queued file has content
            items = _purge_expired(items, _now())
            items.append(item)
            _save("queue.json", items)
        _save("seen.json", sorted(seen_ids | {item["msg_id"]}))
    if for_me:
        return "delivered", _deliver(item, content)
    print(f"[SAF] queued {item['type']} {item['msg_id']} for {item['destination_id']} (hops {item['hops']})")
    for hook in list(_ON_QUEUED):
        try:
            hook(item)
        except Exception as exc:  # the item stays queued; the hook is only a shortcut
            print(f"[SAF] hook {getattr(hook, '__name__', hook)} failed: {type(exc).__name__} ({exc})")
    return "queued", {"status": "QUEUED", "hops": item["hops"]}


def drop(msg_id: str) -> bool:
    """Removes a carried item that reached its destination outside the radio links (a CSR handed to the portal).

    The id stays in seen.json, so a neighbour carrying a copy does not bring it back."""
    with _LOCK:
        items = _load("queue.json", [])
        kept = [i for i in items if i["msg_id"] != msg_id]
        if len(kept) == len(items):
            return False
        _save("queue.json", kept)
        _blob(msg_id).unlink(missing_ok=True)
        _save("seen.json", sorted(set(_load("seen.json", [])) | {msg_id}))
    return True


def mark_seen(msg_id: str) -> None:
    """A message delivered directly (neighbour in range): neighbours carrying a copy will not offer it again."""
    if not _valid_id(msg_id):
        return
    with _LOCK:
        ids = set(_load("seen.json", []))
        if msg_id not in ids:
            _save("seen.json", sorted(ids | {msg_id}))


def enqueue_local(item: Dict[str, Any], content: Optional[bytes] = None) -> Dict[str, Any]:
    """A message / file created here for a node out of range: queue it and tell the neighbours."""
    outcome, details = accept(item, content)
    announced = contact.announce(f"saf-{item['msg_id'][:8]}") if outcome == "queued" else []
    return {**details, "msg_id": item["msg_id"], "announced_to": announced}


def offer(known: Iterable[str], peer_id: str) -> Tuple[List[Dict[str, Any]], int]:
    """Items a neighbour does not have yet (message text inline, file content fetched separately).

    Returns (items, saved_bytes): saved = payload of the items not sent because the neighbour already knew them."""
    known = {str(k)[:ID_PREFIX] for k in known}
    with _LOCK:
        items = _purge_expired(_load("queue.json", []), _now())
        _save("queue.json", items)
    result, saved = [], 0
    for item in items:
        if peer_id in item["hops"] or len(item["hops"]) >= config.P2P_MAX_HOPS:
            continue
        if item["msg_id"][:ID_PREFIX] in known:
            saved += _payload(item)
            continue
        result.append(item)
    return result, saved


def carried(msg_id: str) -> Optional[Dict[str, Any]]:
    return next((i for i in queue() if i["msg_id"] == msg_id), None)


def content(msg_id: str) -> Optional[bytes]:
    if not _valid_id(msg_id):
        return None
    try:
        return _blob(msg_id).read_bytes()
    except FileNotFoundError:
        return None


def _payload(item: Dict[str, Any]) -> int:
    if item["type"] in BLOB_KINDS:
        return item.get("size") or 0
    if item["type"] == "csr_result":
        return wire.json_payload_size(item.get("result"))
    return len(item.get("message", "").encode())


def transfer_kind(item: Dict[str, Any]) -> str:
    """Kind in the transfer register: a rejection hint counts as CSR traffic."""
    return "csr" if item.get("type") == "csr_result" else item.get("type")


def exchange(peer: Dict[str, Any]) -> Dict[str, int]:
    """Contact handler (radio neighbours only): pull the items this node does not know yet."""
    if peer["kind"] != contact.NEIGHBOUR:
        return {}
    request = {"node_id": config.NODE_ID, "known": known_prefixes()}
    fetched = wire.post_json(wire.peer_url(peer, "/api/saf/offer"), request, config.SAF_MAX_OFFER_BYTES)
    items = fetched.json().get("items", [])
    if not isinstance(items, list):
        raise SafError("odpowiedź offer bez listy items")
    inline = sum(wire.json_payload_size(i) for i in items)
    transfers.record("saf_offer", "in", peer["id"], wire.json_payload_size(request) + len(fetched.body) - inline,
                     fetched.wire_bytes - inline, encoding="JSON", note=f"{len(items)} new item(s)")
    counts = {"delivered": 0, "queued": 0, "duplicate": 0, "rejected": 0}
    for item in items:
        kind = transfer_kind(item) if isinstance(item, dict) and item.get("type") in KINDS else "msg"
        body, wire_bytes = None, wire.json_payload_size(item)
        try:
            validate(item)
            if item["type"] in BLOB_KINDS:
                got = wire.get(wire.peer_url(peer, f"/api/saf/items/{item['msg_id']}/content"), int(item["size"]))
                body, wire_bytes = got.body, wire_bytes + got.wire_bytes
                validate(item, body)
        except (SafError, wire.WireError) as exc:
            counts["rejected"] += 1
            transfers.record(kind, "in", peer["id"], len(body or b""), wire_bytes, status="rejected",
                             number=item.get("msg_id") if isinstance(item, dict) else None, note=str(exc)[:200])
            print(f"[SAF] item {item.get('msg_id') if isinstance(item, dict) else '?'} from {peer['id']} "
                  f"rejected: {exc}")
            continue
        outcome, details = accept(item, body)
        counts[outcome] += 1
        status = "skipped" if outcome == "duplicate" else "rejected" if details.get("status") == "NOT_OURS" else "ok"
        transfers.record(kind, "in", peer["id"], _payload(item), wire_bytes, status=status,
                         encoding="DER" if item["type"] in ("csr", "cert") else None, number=item["msg_id"],
                         note=f"{details.get('status', outcome).lower()} (for {item['destination_id']})")
    if counts["queued"]:
        contact.announce(f"saf-{counts['queued']}", exclude=peer["id"])
    return counts


exchange.__name__ = "saf_exchange"
contact.register(exchange)
