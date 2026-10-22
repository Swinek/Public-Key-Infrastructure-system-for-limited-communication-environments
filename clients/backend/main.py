import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import close_db, init_db
from routers import certificates, health, pki, users

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("pki_client_backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for DB pool startup and shutdown."""
    logger.info("Starting PKI Client/Node Backend with FastAPI...")
    await init_db()
    yield
    logger.info("Shutting down PKI Client Backend...")
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


@app.get("/", tags=["System"])
async def root():
    return {
        "message": "PKI Client Backend is operational",
        "docs": "/docs",
        "health": "/api/health"
    }
