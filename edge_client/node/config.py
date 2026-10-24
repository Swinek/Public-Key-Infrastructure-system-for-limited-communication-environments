import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

NODE_NAME = os.getenv("NODE_NAME", "Edge client #1")
NODE_ID = os.getenv("NODE_ID", "client_1")
PORT = int(os.getenv("PORT", "8000"))

# Neighbours are not configured - they are discovered by a one-time hello when a link comes up (neighbours.py).
# P2P_CIDR: address range of radio links (p2p_<ab> = 192.168.<ab>.0/24); mgmt_N (192.168.20N.0/24)
# and internet_net are outside it, so hello packets never go there.
P2P_CIDR = os.getenv("P2P_CIDR", "192.168.0.0/17")
HELLO_PORT = int(os.getenv("HELLO_PORT", "8999"))

# P2P request timeouts (connect, read). Read timeout is long because forwarding is synchronous:
# the sender waits until every hop on the path has delivered the message.
P2P_CONNECT_TIMEOUT = float(os.getenv("P2P_CONNECT_TIMEOUT", "3"))
P2P_READ_TIMEOUT = float(os.getenv("P2P_READ_TIMEOUT", "60"))
P2P_MAX_HOPS = int(os.getenv("P2P_MAX_HOPS", "16"))

# Client portal (centre) reachable over internet_net: the peer of a WAN contact (contact.py, `client.sh internet on`).
PORTAL_URL = os.getenv("PORTAL_URL", "http://pki-edge-client-backend:5001")

# Pinned Root CA (SHA-256 fingerprint, hex), set at deployment (client.sh up reads it from the CA certificate).
# Only this CA is accepted - from the portal or from a neighbour (pki_sync.py). Without it no CA is accepted at all
# (no trust on first use) and the node cannot verify anything.
CA_FINGERPRINT = os.getenv("CA_FINGERPRINT", "").replace(":", "").strip().lower()

# Own certificate (enroll.py): a new key + CSR this many days before the certificate expires.
RENEW_BEFORE_DAYS = int(os.getenv("RENEW_BEFORE_DAYS", "30"))

# Hard limits for objects downloaded from a peer (the size declared in /pki/summary is untrusted).
MAX_PKI_OBJECT_BYTES = int(os.getenv("MAX_PKI_OBJECT_BYTES", str(256 * 1024)))
MAX_SUMMARY_BYTES = int(os.getenv("MAX_SUMMARY_BYTES", str(16 * 1024)))

# Store-and-forward (saf.py): messages/files for nodes out of range travel with neighbours.
SAF_TTL_HOURS = float(os.getenv("SAF_TTL_HOURS", "168"))  # a copy is dropped after this time (7 days)
SAF_MAX_FILE_BYTES = int(os.getenv("SAF_MAX_FILE_BYTES", str(5 * 1024 * 1024)))
SAF_MAX_OFFER_BYTES = int(os.getenv("SAF_MAX_OFFER_BYTES", str(1024 * 1024)))

# Edge app of this node (diagram arrow "cert"): reachable only over the node's own mgmt_N network.
# Only this host may download a certificate together with its private key (GET /api/certs/bundle).
EDGE_APP_URL = os.getenv("EDGE_APP_URL", "http://app_1:8000")

CLOCK_API_PRIMARY = "https://timeapi.io/api/time/current/zone?timeZone=UTC"
CLOCK_API_FALLBACK = "http://worldtimeapi.org/api/timezone/Etc/UTC"

# Persistent node data (Docker volume in container, edge_client/node/data locally):
#   DATA_DIR/inbox.json       - P2P messages inbox
#   DATA_DIR/received_files/  - files delivered to this node
#   DATA_DIR/certs/           - the certificate, Root CA and CRL, see certs.py
#   DATA_DIR/saf/             - store-and-forward queue, see saf.py
#   DATA_DIR/transfers.jsonl  - register of transferred data, see transfers.py
_default_data = "/app/data" if Path("/app").exists() else str(BASE_DIR / "data")
DATA_DIR = Path(os.getenv("DATA_DIR", _default_data))
STORAGE_DIR = DATA_DIR / "received_files"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
INBOX_FILE = DATA_DIR / "inbox.json"
CERTS_DIR = DATA_DIR / "certs"

_default_static = "/app/static" if Path("/app/static").exists() else str(BASE_DIR / "static")
STATIC_DIR = Path(os.getenv("STATIC_DIR", _default_static))
