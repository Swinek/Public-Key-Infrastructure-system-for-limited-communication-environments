import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

NODE_NAME = os.getenv("NODE_NAME", "Client 1")
NODE_ID = os.getenv("NODE_ID", "client_1")
LOCAL_IP = os.getenv("LOCAL_IP", "127.0.0.1")
PEER_NAME = os.getenv("PEER_NAME", "Client 2")
PEER_ID = os.getenv("PEER_ID", "client_2")
PEER_IP = os.getenv("PEER_IP", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))

CLOCK_API_PRIMARY = "https://timeapi.io/api/time/current/zone?timeZone=UTC"
CLOCK_API_FALLBACK = "http://worldtimeapi.org/api/timezone/Etc/UTC"

_default_storage = "/app/received_files" if Path("/app").exists() else str(BASE_DIR / "received_files")
STORAGE_DIR = Path(os.getenv("STORAGE_DIR", _default_storage))
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

_default_static = "/app/static" if Path("/app/static").exists() else str(BASE_DIR / "static")
STATIC_DIR = Path(os.getenv("STATIC_DIR", _default_static))
