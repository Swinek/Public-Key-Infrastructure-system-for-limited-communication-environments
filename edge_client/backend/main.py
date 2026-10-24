import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import announce
from database import DATABASE_URL, close_db, init_db
from routers import certificates, csr, health, pki, users

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("pki_edge_client_backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for DB pool startup and shutdown."""
    logger.info("Starting PKI Client/Node Backend with FastAPI...")
    await init_db()
    # Nowa CRL w bazie -> impuls do węzłów online (announce.py), bez odpytywania przez węzły.
    listener = asyncio.create_task(announce.listen(DATABASE_URL))
    yield
    logger.info("Shutting down PKI Client Backend...")
    listener.cancel()
    await close_db()


app = FastAPI(
    title="PKI Client & Edge Node Backend API",
    description="Read-only Client Portal and Verification API (No CA Private Key access)",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(users.router, prefix="/api")
app.include_router(certificates.router, prefix="/api")
app.include_router(health.router, prefix="/api")
app.include_router(pki.router)  # /pki/* - API dla węzłów brzegowych (bez prefiksu /api)
app.include_router(csr.router)  # /pki/csr - wnioski CSR węzłów (jedyny zapis portalu w bazie)


@app.get("/", tags=["System"])
async def root():
    return {
        "message": "PKI Client Backend is operational",
        "docs": "/docs",
        "health": "/api/health"
    }
