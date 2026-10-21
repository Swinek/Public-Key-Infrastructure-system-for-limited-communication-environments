import json
import os
import threading
import time
from typing import Any, Dict, List, Tuple

import config

START_TIME: float = time.time()

_LOCK = threading.Lock()


def _load_inbox() -> List[Dict[str, Any]]:
    try:
        with open(config.INBOX_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as e:
        print(f"[STATE] Cannot read {config.INBOX_FILE}: {e}. Starting with an empty inbox.")
        return []


def _save_inbox() -> None:
    """Atomic write: tmp file + fsync + os.replace (no half-written inbox after a crash)."""
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = config.INBOX_FILE.with_suffix(".json.tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(INBOX, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, config.INBOX_FILE)


INBOX: List[Dict[str, Any]] = _load_inbox()


def add_inbox_entry(entry: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """Assigns a local id (max + 1) and persists the inbox.
    Returns (entry, created). A duplicate msg_id (retransmission) returns the stored entry and False."""
    with _LOCK:
        msg_id = entry.get("msg_id")
        if msg_id:
            for existing in INBOX:
                if existing.get("msg_id") == msg_id:
                    return existing, False
        entry["id"] = max((e.get("id", 0) for e in INBOX), default=0) + 1
        INBOX.append(entry)
        _save_inbox()
        return entry, True


def inbox_snapshot() -> List[Dict[str, Any]]:
    with _LOCK:
        return list(INBOX)
