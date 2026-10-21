#!/usr/bin/env python3

import sys
from pathlib import Path

# Ensure edges directory is on sys.path for both direct run and module imports
EDGES_DIR = Path(__file__).resolve().parent
if str(EDGES_DIR) not in sys.path:
    sys.path.insert(0, str(EDGES_DIR))

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

import config
from routers import network, p2p

_peers_desc = ", ".join(f"{p['name']} ({p['ip']}:{config.PORT})" for p in config.PEERS) or "none"
_routes_desc = ", ".join(f"{dest} via {hop}" for dest, hop in config.ROUTES.items()) or "none"

app = FastAPI(
    title=f"Node API: {config.NODE_NAME}",
    description=(
        f"Node {config.NODE_NAME} ({config.NODE_ID}). P2P: {', '.join(config.LOCAL_IPS)} (port {config.PORT}). "
        f"Neighbours: {_peers_desc}. Routes: {_routes_desc}."
    ),
    version="1.0.0"
)

if config.STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(config.STATIC_DIR)), name="static")


@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
def root_page():
    index_path = config.STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {
        "service": "Node API",
        "node_id": config.NODE_ID,
        "node_name": config.NODE_NAME,
        "local_ips": [f"{ip}:{config.PORT}" for ip in config.LOCAL_IPS],
        "peers": [f"{p['name']} ({p['ip']}:{config.PORT})" for p in config.PEERS],
        "routes": config.ROUTES,
        "documentation": "/docs"
    }


# Register modular routers
app.include_router(network.router)
app.include_router(p2p.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=config.PORT)
