"""Trwała pamięć obserwowanych i potwierdzonych wersji sąsiadów; dane pomocnicze, nie zaufanie."""
import json
import threading
from datetime import datetime, timezone
import config
from utils import atomic_write_bytes

_LOCK = threading.RLock()


def _path():
    return config.DATA_DIR / "pki_peers.json"


def read():
    with _LOCK:
        try:
            return json.loads(_path().read_bytes())
        except (FileNotFoundError, ValueError):
            return {}


def update(peer, **values):
    with _LOCK:
        state = read()
        state.setdefault(peer, {}).update(values, updated_at=datetime.now(timezone.utc).isoformat())
        atomic_write_bytes(_path(), json.dumps(state, separators=(",", ":")).encode())


def observe(peer, number):
    # Każdy kontakt odczytuje rzeczywisty stan. Sąsiad może utracić dane lub dostać nowsze skądinąd.
    current = read().get(peer, {})
    confirmed = current.get("confirmed")
    if number is None or (confirmed is not None and number < confirmed):
        confirmed = None
    update(peer, observed=number, confirmed=confirmed)


def confirm(peer, number):
    current = read().get(peer, {})
    number = max(number, current.get("confirmed") or 0)
    pending = current.get("pending")
    if pending is not None and number >= pending:
        pending = None
    update(peer, confirmed=number, observed=number, pending=pending)


def pending(peer, number):
    old = read().get(peer, {}).get("pending")
    update(peer, pending=max(number, old if old is not None else number))
