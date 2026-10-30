"""Register of data sent and received by this edge client (measurements for the thesis, Stage 3/5).

Every exchange calls record(...) once per object - on the side that downloads ("in") and on the side that serves
("out"). Each record has two sizes:
    payload_bytes  the object itself (CRL in DER, certificate, message text, file)
    wire_bytes     what went over the link for it (HTTP request + response with headers, JSON/base64 overhead)
and status:
    ok        transferred
    skipped   not transferred because the peer already had this version (saved_bytes = its size)
    rejected  transferred but refused by verification (CA signature, CRLNumber, SHA-256)
    aborted   download stopped (size limit, link lost)

Records are appended to DATA_DIR/transfers.jsonl (one JSON per line) and printed as a log line.
"""
from __future__ import annotations

import csv
import io
import json
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import config

KINDS = ("crl_ack", "summary", "crl_full", "crl_delta", "ca_cert", "cert", "csr", "msg", "file", "saf_offer", "announce")
DIRECTIONS = ("in", "out")
STATUSES = ("ok", "skipped", "rejected", "aborted")

FIELDS = ("node_id", "at", "kind", "direction", "peer", "status", "payload_bytes", "wire_bytes", "saved_bytes",
          "encoding", "signature", "number", "note")

_LOCK = threading.Lock()


def _file():
    return config.DATA_DIR / "transfers.jsonl"


def record(kind: str, direction: str, peer: str, payload_bytes: int = 0, wire_bytes: int = 0, *,
           status: str = "ok", saved_bytes: int = 0, encoding: Optional[str] = None,
           signature: Optional[str] = None, number: Optional[Any] = None, note: Optional[str] = None) -> Dict[str, Any]:
    if kind not in KINDS or direction not in DIRECTIONS or status not in STATUSES:
        raise ValueError(f"Unknown transfer record: {kind}/{direction}/{status}")
    entry = {
        "at": datetime.now(timezone.utc).isoformat(), "kind": kind, "direction": direction, "peer": peer,
        "status": status, "payload_bytes": int(payload_bytes), "wire_bytes": int(wire_bytes),
        "saved_bytes": int(saved_bytes), "encoding": encoding, "signature": signature,
        "number": None if number is None else str(number), "note": note,
    }
    line = json.dumps(entry, ensure_ascii=False)
    with _LOCK:
        _file().parent.mkdir(parents=True, exist_ok=True)
        with open(_file(), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    arrow = "<-" if direction == "in" else "->"
    extra = f" saved={saved_bytes}" if saved_bytes else ""
    print(f"[TRANSFER] {kind} {arrow} {peer} {status} payload={payload_bytes} wire={wire_bytes}{extra}"
          + (f" #{number}" if number is not None else "") + (f" ({note})" if note else ""))
    return entry


def entries() -> List[Dict[str, Any]]:
    with _LOCK:
        try:
            lines = _file().read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
    result = []
    for line in lines:
        try:
            result.append(json.loads(line))
        except ValueError:  # a line cut by a crash is skipped
            continue
    return result


def reset() -> int:
    """Removes all records (before a measurement scenario). Returns how many were removed."""
    count = len(entries())
    with _LOCK:
        _file().unlink(missing_ok=True)
    return count


def _sums() -> Dict[str, int]:
    return {"count": 0, "payload_bytes": 0, "wire_bytes": 0, "saved_bytes": 0}


def summary() -> Dict[str, Any]:
    """Totals by kind, by peer and by direction (each with counts per status)."""
    items = entries()
    total = _sums()
    groups: Dict[str, Dict[str, Dict[str, Any]]] = {"by_kind": defaultdict(_sums), "by_peer": defaultdict(_sums),
                                                     "by_direction": defaultdict(_sums)}
    for e in items:
        targets = (total, groups["by_kind"][e["kind"]], groups["by_peer"][e["peer"]],
                   groups["by_direction"][e["direction"]])
        status_key = f"status_{e.get('status', 'ok')}"
        for target in targets:
            target["count"] += 1
            for field in ("payload_bytes", "wire_bytes", "saved_bytes"):
                target[field] += e.get(field, 0)
            target[status_key] = target.get(status_key, 0) + 1
    return {"node_id": config.NODE_ID, "records": len(items), "total": total,
            **{k: dict(sorted(v.items())) for k, v in groups.items()}}


def to_csv() -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=FIELDS, extrasaction="ignore")
    writer.writeheader()
    for e in entries():
        writer.writerow({"node_id": config.NODE_ID, **e})
    return out.getvalue()
