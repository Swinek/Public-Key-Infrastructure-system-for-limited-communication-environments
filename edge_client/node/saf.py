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

Layout of DATA_DIR/saf/:
    queue.json        items carried for other nodes (metadata, message text inline)
    blobs/<msg_id>    content of file items
    seen.json         every msg_id ever held or delivered here
"""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import config
import contact
import state
import transfers
import utils
import wire

ID_PREFIX = 16  # hex characters of msg_id sent in the "known" list (64 bits - no collisions at this scale)
MAX_MESSAGE_CHARS = 10_000

_LOCK = threading.Lock()


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


def new_item(kind: str, destination_id: str, *, message: Optional[str] = None, filename: Optional[str] = None,
             content: Optional[bytes] = None, content_type: Optional[str] = None,
             msg_id: Optional[str] = None) -> Dict[str, Any]:
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
    else:
        item.update({"filename": filename, "content_type": content_type, "size": len(content),
                     "sha256": hashlib.sha256(content).hexdigest()})
    return item


def validate(item: Dict[str, Any], content: Optional[bytes] = None) -> None:
    """Checks an item received from a neighbour (untrusted) before it is stored or delivered."""
    if not isinstance(item, dict) or not _valid_id(item.get("msg_id")):
        raise SafError("niepoprawny msg_id")
    if item.get("type") not in ("msg", "file"):
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
    if item["type"] == "msg":
        if not isinstance(item.get("message"), str) or len(item["message"]) > MAX_MESSAGE_CHARS:
            raise SafError("niepoprawna treść wiadomości")
    else:
        size = wire.optional_int(item.get("size"))
        if size is None or size < 0 or size > config.SAF_MAX_FILE_BYTES:
            raise SafError("niepoprawny rozmiar pliku")
        name = Path(str(item.get("filename") or "")).name
        if not name or name.startswith("."):
            raise SafError("niepoprawna nazwa pliku")
        if content is not None and (len(content) != size or hashlib.sha256(content).hexdigest() != item.get("sha256")):
            raise SafError("treść pliku nie zgadza się z rozmiarem / SHA-256")


def _limit_ttl(item: Dict[str, Any]) -> None:
    """A neighbour cannot extend the life of an item beyond SAF_TTL_HOURS from its creation."""
    created = _parse(item["created_at"])
    cap = created + timedelta(hours=config.SAF_TTL_HOURS)
    if _parse(item["expires_at"]) > cap:
        item["expires_at"] = cap.isoformat()


def _deliver(item: Dict[str, Any], content: Optional[bytes]) -> Dict[str, Any]:
    route, hops = item["hops"], item["hops"][:-1]
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
    return "queued", {"status": "QUEUED", "hops": item["hops"]}


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
            saved += item.get("size") or len(item.get("message", "").encode())
            continue
        result.append(item)
    return result, saved


def content(msg_id: str) -> Optional[bytes]:
    if not _valid_id(msg_id):
        return None
    try:
        return _blob(msg_id).read_bytes()
    except FileNotFoundError:
        return None


def _payload(item: Dict[str, Any]) -> int:
    return item.get("size") if item["type"] == "file" else len(item.get("message", "").encode())


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
        kind = item.get("type") if item.get("type") in ("msg", "file") else "msg"
        body, wire_bytes = None, wire.json_payload_size(item)
        try:
            validate(item)
            if kind == "file":
                got = wire.get(wire.peer_url(peer, f"/api/saf/items/{item['msg_id']}/content"), int(item["size"]))
                body, wire_bytes = got.body, wire_bytes + got.wire_bytes
                validate(item, body)
        except (SafError, wire.WireError) as exc:
            counts["rejected"] += 1
            transfers.record(kind, "in", peer["id"], len(body or b""), wire_bytes, status="rejected",
                             number=item.get("msg_id"), note=str(exc)[:200])
            print(f"[SAF] item {item.get('msg_id')} from {peer['id']} rejected: {exc}")
            continue
        outcome, _ = accept(item, body)
        counts[outcome] += 1
        transfers.record(kind, "in", peer["id"], _payload(item), wire_bytes,
                         status="skipped" if outcome == "duplicate" else "ok", number=item["msg_id"],
                         note=f"{outcome} (for {item['destination_id']})")
    if counts["queued"]:
        contact.announce(f"saf-{counts['queued']}", exclude=peer["id"])
    return counts


exchange.__name__ = "saf_exchange"
contact.register(exchange)
