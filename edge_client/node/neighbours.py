"""Neighbour discovery over the radio links: a one-time hello when a link is established.

The node does not know the topology in advance and there is no periodic traffic on the radio links.
When a link comes up (`client.sh link up`, or node start for the initial links) the node sends ONE
hello broadcast on each of its P2P interfaces; every node that hears it registers the sender and
answers with ONE unicast hello-ack. Two packets per link establishment, nothing afterwards.

A neighbour stays a neighbour as long as the link exists: an entry is valid only while its address
lies in a subnet of one of this node's current P2P interfaces. `client.sh link down` removes the
interface, so the neighbour disappears immediately - checked locally, without any radio traffic.

Hello packets are not authenticated - they only say who is on the link. Data exchanged with a
neighbour is verified separately (CA signature); authenticating the neighbour itself is Stage 4.
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

HELLO = "hello"
HELLO_ACK = "hello-ack"


def parse_ip_addr(output: str) -> List[Dict[str, str]]:
    """Parses `ip -4 -o addr show` into P2P interfaces: [{"ifname", "ip", "network", "broadcast"}]."""
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
            "network": str(iface.network),
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


def packet(kind: str) -> bytes:
    return json.dumps(
        {"t": kind, "id": config.NODE_ID, "name": config.NODE_NAME, "port": config.PORT},
        separators=(",", ":"),
    ).encode()


def handle_packet(data: bytes, src_ip: str, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """Registers the sender of a hello / hello-ack. Returns the neighbour entry (with "reply": True
    for a hello, which must be answered with a hello-ack), or None when the packet is ignored."""
    now = time.time() if now is None else now
    try:
        if ipaddress.ip_address(src_ip) not in _P2P_NET:
            return None
        msg = json.loads(data.decode())
        kind = msg["t"]
        node_id = str(msg["id"])
        port = int(msg.get("port", config.PORT))
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        return None
    if kind not in (HELLO, HELLO_ACK) or node_id == config.NODE_ID:
        return None
    with _LOCK:
        entry = _TABLE.get(node_id)
        if entry is None or entry["ip"] != src_ip:
            entry = {"id": node_id, "connected_since": now}
            _TABLE[node_id] = entry
        entry.update({"name": str(msg.get("name") or node_id), "ip": src_ip, "port": port})
        return {**entry, "reply": kind == HELLO}


def current(interfaces: Optional[List[Dict[str, str]]] = None) -> List[Dict[str, Any]]:
    """Neighbours on links that exist right now, sorted by id. Entries whose link is gone are removed."""
    interfaces = p2p_interfaces() if interfaces is None else interfaces
    networks = [ipaddress.ip_network(i["network"]) for i in interfaces]
    with _LOCK:
        for node_id in [k for k, v in _TABLE.items()
                        if not any(ipaddress.ip_address(v["ip"]) in net for net in networks)]:
            del _TABLE[node_id]
        return sorted((dict(v) for v in _TABLE.values()), key=lambda n: n["id"])


def get(node_id: str) -> Optional[Dict[str, Any]]:
    for n in current():
        if n["id"] == node_id:
            return n
    return None


def _send(payload: bytes, local_ip: str, target: str, broadcast: bool = False) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        if broadcast:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind((local_ip, 0))
        s.sendto(payload, (target, config.HELLO_PORT))


def discover() -> List[str]:
    """Sends one hello on every P2P interface (called once per link establishment). Returns used IPs."""
    used = []
    for iface in p2p_interfaces():
        try:
            _send(packet(HELLO), iface["ip"], iface["broadcast"], broadcast=True)
            used.append(iface["ip"])
        except OSError as e:
            print(f"[HELLO] Send on {iface['ifname']} ({iface['ip']}) failed: {e}")
    return used


def _receive_loop() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", config.HELLO_PORT))
        while True:
            data, (src_ip, _) = s.recvfrom(1024)
            entry = handle_packet(data, src_ip)
            if not entry or not entry["reply"]:
                continue
            src = ipaddress.ip_address(src_ip)
            local = next((i["ip"] for i in p2p_interfaces() if src in ipaddress.ip_network(i["network"])), None)
            if local:
                try:
                    _send(packet(HELLO_ACK), local, src_ip)
                except OSError as e:
                    print(f"[HELLO] Ack to {src_ip} failed: {e}")


def start() -> None:
    """Starts the listener and greets neighbours on the links that exist at node start (once per process)."""
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_receive_loop, name="hello-rx", daemon=True).start()
    time.sleep(0.2)  # listener ready before our own hello can be answered
    discover()
