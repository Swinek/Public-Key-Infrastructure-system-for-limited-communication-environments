import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

NODE_NAME = os.getenv("NODE_NAME", "Edge App #1")
# Identity of the node = CN of its certificate (same as the edge client of this node, e.g. client_1).
NODE_ID = os.getenv("NODE_ID", "client_1")
APP_ID = os.getenv("APP_ID", "app_1")
PORT = int(os.getenv("PORT", "8000"))

# Edge client of this node (diagram arrow "cert"): the app takes its certificate from there, over mgmt_N.
EDGE_CLIENT_URL = os.getenv("EDGE_CLIENT_URL", "http://client_1:8000")
EDGE_CLIENT_TIMEOUT = float(os.getenv("EDGE_CLIENT_TIMEOUT", "10"))

# Separate channel between edge apps (diagram: optional isolated network): peers are app_<N> on app_net.
PEER_URL_TEMPLATE = os.getenv("PEER_URL_TEMPLATE", "http://{peer}:8000")
PEER_TIMEOUT = float(os.getenv("PEER_TIMEOUT", "5"))
# Lifetime of an issued authentication challenge (single use).
CHALLENGE_TTL_SECONDS = int(os.getenv("CHALLENGE_TTL_SECONDS", "60"))

# Persistent data (Docker volume in container, edge_app/data locally):
#   DATA_DIR/pki/ - PKI store (CA cert, own cert/key, last CRL) taken from the edge client, see pki/store.py
_default_data = "/app/data" if Path("/app").exists() else str(BASE_DIR / "data")
DATA_DIR = Path(os.getenv("DATA_DIR", _default_data))
PKI_DIR = DATA_DIR / "pki"

# Pinned SHA-256 fingerprint of the Root CA certificate (hex, colons allowed), set at installation.
# Empty = trust on first install: the first installed CA is pinned in PKI_DIR and cannot be replaced later.
CA_FINGERPRINT = os.getenv("CA_FINGERPRINT", "")

_default_static = "/app/static" if Path("/app/static").exists() else str(BASE_DIR / "static")
STATIC_DIR = Path(os.getenv("STATIC_DIR", _default_static))
