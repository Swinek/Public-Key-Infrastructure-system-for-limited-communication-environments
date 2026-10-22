import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

NODE_NAME = os.getenv("NODE_NAME", "Edge App #1")
NODE_ID = os.getenv("NODE_ID", "client_1")
PORT = int(os.getenv("PORT", "8000"))

# Neighbours are not configured - they are discovered by UDP beacons on the radio links (neighbours.py).
# P2P_CIDR: address range of radio links (p2p_<ab> = 192.168.<ab>.0/24); mgmt_N (192.168.20N.0/24)
# and internet_net are outside it, so beacons never go there.
P2P_CIDR = os.getenv("P2P_CIDR", "192.168.0.0/17")
BEACON_PORT = int(os.getenv("BEACON_PORT", "8999"))
BEACON_INTERVAL = float(os.getenv("BEACON_INTERVAL", "2"))
# A neighbour not heard for this long is out of range (a few missed beacons).
NEIGHBOUR_TIMEOUT = float(os.getenv("NEIGHBOUR_TIMEOUT", "7"))

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
