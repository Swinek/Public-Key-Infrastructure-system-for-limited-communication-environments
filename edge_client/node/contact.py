"""Contact triggers: the moments when this node may exchange data with someone else.

There are no timers and no polling - data is exchanged only when Łączność (client.sh) creates contact:
    wan        `client.sh internet on` -> POST /api/contact/wan; the peer is the portal (PORTAL_URL)
    neighbour  a hello or hello-ack received on a radio link (neighbours.py); the peer is that neighbour

A hello exchange triggers both sides once: the receiver of the hello and the receiver of the hello-ack
each start their own exchange with the other. Stage 3 work (CRL/CA sync, store-and-forward) registers
handlers here; each handler gets the peer and its base URL and runs in a background thread, so the
hello listener and the HTTP request are never blocked by a slow radio link.

Only one exchange per peer runs at a time; a trigger for a peer that is still busy is not lost: the exchange
runs once more right after the current one ends (the peer may have got new data in the meantime).

announce: when this node gets new data (a newer CRL, a store-and-forward item), it tells its current neighbours
(POST /api/contact/announce, a few bytes). Each of them treats it as a contact and pulls from this node - the data
itself is always pulled by the receiver, which verifies it before storing.
"""
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, List, Optional, Set

import peer_state
import config
import transfers
import wire

WAN = "wan"
NEIGHBOUR = "neighbour"
PORTAL_ID = "portal"

Handler = Callable[[Dict[str, Any]], Any]

_LOCK = threading.Lock()
_HANDLERS: List[Handler] = []
_BUSY: Set[str] = set()
_PENDING: Set[str] = set()
_EVENTS: Deque[Dict[str, Any]] = deque(maxlen=100)
_next_id = 0


def register(handler: Handler) -> None:
    """Adds an exchange run on every contact (called at import time by Stage 3 modules)."""
    with _LOCK:
        if handler not in _HANDLERS:
            _HANDLERS.append(handler)


def portal_peer() -> Dict[str, Any]:
    return {"kind": WAN, "id": PORTAL_ID, "url": config.PORTAL_URL.rstrip("/")}


def neighbour_peer(entry: Dict[str, Any]) -> Dict[str, Any]:
    port = entry.get("port", config.PORT)
    return {"kind": NEIGHBOUR, "id": entry["id"], "name": entry.get("name"), "ip": entry["ip"],
            "url": f"http://{entry['ip']}:{port}"}


def _run(event: Dict[str, Any], peer: Dict[str, Any], handlers: List[Handler]) -> None:
    started = time.monotonic()
    errors = []
    rounds = 0
    try:
        while True:
            rounds += 1
            for handler in handlers:
                try:
                    handler(peer)
                except Exception as exc:  # one failed exchange must not stop the others
                    errors.append(f"{getattr(handler, '__name__', handler)}: {type(exc).__name__} ({exc})")
                    print(f"[CONTACT] {peer['id']}: {errors[-1]}")
            with _LOCK:
                if peer["id"] not in _PENDING:
                    _BUSY.discard(peer["id"])
                    break
                _PENDING.discard(peer["id"])  # triggered again while running: one more round
    except BaseException:
        with _LOCK:
            _BUSY.discard(peer["id"])
            _PENDING.discard(peer["id"])
        raise
    finally:
        with _LOCK:
            event.update({"status": "failed" if errors else "done", "errors": errors, "rounds": rounds,
                          "duration_ms": round((time.monotonic() - started) * 1000, 1)})


def trigger(peer: Dict[str, Any], wait: bool = False) -> Dict[str, Any]:
    """Starts the exchange with `peer` unless one is already running. Returns the logged event.

    wait=True runs the handlers in the calling thread (tests)."""
    global _next_id
    with _LOCK:
        _next_id += 1
        event = {"id": _next_id, "at": datetime.now(timezone.utc).isoformat(), "kind": peer["kind"],
                 "peer": peer["id"], "handlers": len(_HANDLERS)}
        _EVENTS.append(event)
        if peer["id"] in _BUSY:
            _PENDING.add(peer["id"])
            event["status"] = "queued"
            print(f"[CONTACT] {peer['kind']} {peer['id']}: exchange already running - one more round queued")
            return dict(event)
        _BUSY.add(peer["id"])
        handlers = list(_HANDLERS)
        event["status"] = "running"
    print(f"[CONTACT] {peer['kind']} {peer['id']} ({peer['url']}): {len(handlers)} exchange(s)")
    if wait:
        _run(event, peer, handlers)
    else:
        threading.Thread(target=_run, args=(event, peer, handlers), name=f"contact-{peer['id']}",
                         daemon=True).start()
    with _LOCK:
        return dict(event)


def on_wan(wait: bool = False) -> Dict[str, Any]:
    return trigger(portal_peer(), wait)


def on_neighbour(entry: Dict[str, Any]) -> Dict[str, Any]:
    event = trigger(neighbour_peer(entry))
    pending = peer_state.read().get(entry["id"], {}).get("pending")
    if pending is not None:
        threading.Thread(target=_announce_to, args=(entry, f"crl-{pending}"), daemon=True).start()
    return event


def _announce_to(neighbour: Dict[str, Any], reason: str) -> None:
    if reason.startswith("crl-") and reason[4:].isdigit():
        peer_state.pending(neighbour["id"], int(reason[4:]))
    try:
        fetched = wire.post_json(f"{neighbour_peer(neighbour)['url']}/api/contact/announce", {"reason": reason}, 1024)
        transfers.record("announce", "out", neighbour["id"], 0, fetched.wire_bytes, note=reason)
    except wire.WireError as exc:
        print(f"[CONTACT] announce to {neighbour['id']} failed: {exc}")


def announce(reason: str, exclude: Optional[str] = None, wait: bool = False) -> List[str]:
    """Tells the current neighbours (except `exclude`, the source of the data) that this node has new data."""
    import neighbours  # neighbours imports this module
    targets = [n for n in neighbours.current() if n["id"] != exclude]
    if reason.startswith("crl-") and reason[4:].isdigit():
        # Zaległość również dla wcześniej spotkanych, obecnie odłączonych sąsiadów.
        known = set(peer_state.read()) | {n["id"] for n in targets}
        for peer in known - {exclude, PORTAL_ID}:
            peer_state.pending(peer, int(reason[4:]))
    for n in targets:
        print(f"[CONTACT] announce '{reason}' -> {n['id']}")
        if wait:
            _announce_to(n, reason)
        else:
            threading.Thread(target=_announce_to, args=(n, reason), name=f"announce-{n['id']}", daemon=True).start()
    return [n["id"] for n in targets]


def events(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Latest contacts, newest first."""
    with _LOCK:
        items = [dict(e) for e in reversed(_EVENTS)]
    return items[:limit] if limit else items
