"""Neighbour discovery over the radio links (UDP broadcast beacon).

The node does not know the topology in advance. Every BEACON_INTERVAL seconds it broadcasts a small
beacon ("I am <id>, port <port>") on each of its P2P interfaces; whoever hears it is a neighbour
(in radio range). A neighbour that has not been heard for NEIGHBOUR_TIMEOUT seconds is dropped,
so `client.sh link down` removes it from the table without any configuration change.

Beacons are not authenticated - they only say who is in range. Data exchanged with a neighbour
is verified separately (CA signature); authenticating the neighbour itself is Stage 4.
"""
import ipaddress
import json
import socket
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

import config

_LOCK = threading.Lock()
_TABLE: Dict[str, Dict[str, Any]] = {}
_started = False

_P2P_NET = ipaddress.ip_network(config.P2P_CIDR)


def parse_ip_addr(output: str) -> List[Dict[str, str]]:
    """Parses `ip -4 -o addr show` into P2P interfaces: [{"ifname", "ip", "broadcast"}]."""
    result = []
    for line in output.splitlines():
        parts = line.split()
        if "inet" not in parts:
            continue
        try:
            iface = ipaddress.ip_interface(parts[parts.index("inet") + 1])
        except (ValueError, IndexError):
            continue
        if iface.ip not in _P2P_NET:
            continue
        result.append({
            "ifname": parts[1],
            "ip": str(iface.ip),
            "broadcast": str(iface.network.broadcast_address),
        })
    return result


def p2p_interfaces() -> List[Dict[str, str]]:
    """Current P2P interfaces of this node (changes with `client.sh link up/down`)."""
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=2).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return parse_ip_addr(out)


def beacon_payload() -> bytes:
    return json.dumps(
        {"v": 1, "id": config.NODE_ID, "name": config.NODE_NAME, "port": config.PORT},
        separators=(",", ":"),
    ).encode()


def handle_beacon(data: bytes, src_ip: str, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """Registers a received beacon. Returns the neighbour entry, or None when the beacon is ignored."""
    now = time.time() if now is None else now
    try:
        if ipaddress.ip_address(src_ip) not in _P2P_NET:
            return None
        beacon = json.loads(data.decode())
        node_id = str(beacon["id"])
        port = int(beacon.get("port", config.PORT))
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        return None
    if node_id == config.NODE_ID:
        return None
    with _LOCK:
        entry = _TABLE.get(node_id)
        if entry is None or entry["ip"] != src_ip:
            entry = {"id": node_id, "first_seen": now}
            _TABLE[node_id] = entry
        entry.update({"name": str(beacon.get("name") or node_id), "ip": src_ip, "port": port, "last_seen": now})
        return dict(entry)


def current(now: Optional[float] = None) -> List[Dict[str, Any]]:
    """Neighbours heard within NEIGHBOUR_TIMEOUT, sorted by id; stale entries are removed."""
    now = time.time() if now is None else now
    with _LOCK:
        for node_id in [k for k, v in _TABLE.items() if now - v["last_seen"] > config.NEIGHBOUR_TIMEOUT]:
            del _TABLE[node_id]
        neighbours = [dict(v) for v in _TABLE.values()]
    for n in neighbours:
        n["last_seen_ago_s"] = round(now - n["last_seen"], 1)
    return sorted(neighbours, key=lambda n: n["id"])


def get(node_id: str) -> Optional[Dict[str, Any]]:
    for n in current():
        if n["id"] == node_id:
            return n
    return None


def _send_loop() -> None:
    payload = beacon_payload()
    while True:
        for iface in p2p_interfaces():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    s.bind((iface["ip"], 0))
                    s.sendto(payload, (iface["broadcast"], config.BEACON_PORT))
            except OSError as e:
                print(f"[BEACON] Send on {iface['ifname']} ({iface['ip']}) failed: {e}")
        time.sleep(config.BEACON_INTERVAL)


def _receive_loop() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", config.BEACON_PORT))
        while True:
            data, (src_ip, _) = s.recvfrom(1024)
            handle_beacon(data, src_ip)


def start() -> None:
    """Starts beacon sender and receiver threads (once per process)."""
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_receive_loop, name="beacon-rx", daemon=True).start()
    threading.Thread(target=_send_loop, name="beacon-tx", daemon=True).start()
