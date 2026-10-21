import os
from pathlib import Path
from typing import Dict, List

BASE_DIR = Path(__file__).resolve().parent

NODE_NAME = os.getenv("NODE_NAME", "Client 1")
NODE_ID = os.getenv("NODE_ID", "client_1")
PORT = int(os.getenv("PORT", "8000"))


def _parse_list(raw: str) -> List[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def _parse_peers(raw: str) -> List[Dict[str, str]]:
    """PEERS="id:Name:ip,id:Name:ip" -> [{"id", "name", "ip"}]. Name may contain ':' (split from both ends)."""
    peers = []
    for item in _parse_list(raw):
        try:
            peer_id, rest = item.split(":", 1)
            name, ip = rest.rsplit(":", 1)
        except ValueError:
            raise ValueError(f"Invalid PEERS entry '{item}', expected 'id:Name:ip'")
        peers.append({"id": peer_id.strip(), "name": name.strip() or peer_id.strip(), "ip": ip.strip()})
    return peers


def _parse_routes(raw: str):
    """ROUTES="dest[:Name]=next_hop,..." -> ({dest: next_hop}, {dest: Name}). next_hop must be a direct neighbour."""
    routes, names = {}, {}
    for item in _parse_list(raw):
        try:
            dest, next_hop = item.rsplit("=", 1)
        except ValueError:
            raise ValueError(f"Invalid ROUTES entry '{item}', expected 'destination[:Name]=next_hop'")
        dest_id, _, name = dest.partition(":")
        routes[dest_id.strip()] = next_hop.strip()
        names[dest_id.strip()] = name.strip() or dest_id.strip()
    return routes, names


# Direct radio neighbours (physical topology). Default: local run against a single peer.
PEERS: List[Dict[str, str]] = _parse_peers(os.getenv("PEERS", "client_2:Client 2:127.0.0.1"))
# Static routing table for non-neighbours: destination -> next hop (neighbour id).
ROUTES, ROUTE_NAMES = _parse_routes(os.getenv("ROUTES", ""))
# Own P2P addresses (display only).
LOCAL_IPS: List[str] = _parse_list(os.getenv("LOCAL_IPS", "127.0.0.1"))

_unknown_hops = {hop for hop in ROUTES.values() if hop not in {p["id"] for p in PEERS}}
if _unknown_hops:
    raise ValueError(f"ROUTES uses next hops that are not in PEERS: {sorted(_unknown_hops)}")

# P2P request timeouts (connect, read). Read timeout is long because forwarding is synchronous:
# the sender waits until every hop on the path has delivered the message.
P2P_CONNECT_TIMEOUT = float(os.getenv("P2P_CONNECT_TIMEOUT", "3"))
P2P_READ_TIMEOUT = float(os.getenv("P2P_READ_TIMEOUT", "60"))
P2P_MAX_HOPS = int(os.getenv("P2P_MAX_HOPS", "16"))

# Client portal (centre) reachable over internet_net. Not used yet - reserved for Stage 3 (CRL/certs over WAN).
PORTAL_URL = os.getenv("PORTAL_URL", "http://pki-client-backend:5001")

CLOCK_API_PRIMARY = "https://timeapi.io/api/time/current/zone?timeZone=UTC"
CLOCK_API_FALLBACK = "http://worldtimeapi.org/api/timezone/Etc/UTC"

# Persistent node data (Docker volume in container, edges/data locally):
#   DATA_DIR/inbox.json       - P2P messages inbox
#   DATA_DIR/received_files/  - files delivered to this node
#   DATA_DIR/pki/             - reserved for Stage 2 (CA cert, node cert/key, CRL store)
_default_data = "/app/data" if Path("/app").exists() else str(BASE_DIR / "data")
DATA_DIR = Path(os.getenv("DATA_DIR", _default_data))
STORAGE_DIR = DATA_DIR / "received_files"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
INBOX_FILE = DATA_DIR / "inbox.json"

_default_static = "/app/static" if Path("/app/static").exists() else str(BASE_DIR / "static")
STATIC_DIR = Path(os.getenv("STATIC_DIR", _default_static))
