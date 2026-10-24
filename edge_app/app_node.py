#!/usr/bin/env python3
"""Edge app: the end user of the certificate.

It only receives PKI data from the edge client of its node (diagram arrow "cert"), verifies certificates
offline and uses its own certificate to authenticate with other edge apps over a separate channel.
Distribution of PKI data (WAN, radio links, CRL exchange) is the edge client's job, not the app's.
"""

import sys
from pathlib import Path

# Ensure edge_app directory is on sys.path for both direct run and module imports
APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

import config
from routers import auth
from routers import pki as pki_api

app = FastAPI(
    title=f"Edge app API: {config.NODE_NAME}",
    description=(
        f"Edge app {config.APP_ID} of node {config.NODE_ID}: offline certificate verification and "
        f"challenge-response authentication with other edge apps."
    ),
    version="1.0.0",
)

if config.STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(config.STATIC_DIR)), name="static")


@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
def root_page():
    index_path = config.STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"service": "Edge app", "app_id": config.APP_ID, "node_id": config.NODE_ID, "documentation": "/docs"}


app.include_router(pki_api.router)
app.include_router(auth.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=config.PORT)
