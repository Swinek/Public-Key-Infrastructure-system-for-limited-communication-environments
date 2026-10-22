#!/usr/bin/env python3

import sys
from contextlib import asynccontextmanager
from pathlib import Path

# Ensure edges directory is on sys.path for both direct run and module imports
EDGES_DIR = Path(__file__).resolve().parent
if str(EDGES_DIR) not in sys.path:
    sys.path.insert(0, str(EDGES_DIR))

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

import config
import neighbours
from routers import network, p2p


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Neighbour discovery: beacons on the radio links (no static PEERS/ROUTES).
    neighbours.start()
    yield


app = FastAPI(
    title=f"Node API: {config.NODE_NAME}",
    description=(
        f"Node {config.NODE_NAME} ({config.NODE_ID}), port {config.PORT}. "
        f"Neighbours are discovered by UDP beacons (port {config.BEACON_PORT}) on radio links {config.P2P_CIDR}."
    ),
    version="1.0.0",
    lifespan=lifespan
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
        "local_ips": [f"{i['ip']}:{config.PORT}" for i in neighbours.p2p_interfaces()],
        "peers": [f"{n['name']} ({n['ip']}:{n['port']})" for n in neighbours.current()],
        "documentation": "/docs"
    }


# Register modular routers
app.include_router(network.router)
app.include_router(p2p.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=config.PORT)
