import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import close_db, init_db
from pki.ca import initialize_ca
from routers import certificates, health, users

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("pki_backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager to handle Root CA setup and DB pool startup/shutdown."""
    logger.info("Starting PKI Backend with FastAPI...")
    initialize_ca()
    await init_db()
    yield
    logger.info("Shutting down PKI Backend...")
    await close_db()


app = FastAPI(
    title="PKI Management Backend API",
    description="REST API for PKI Certificate and User Management in limited communication environments",
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


@app.get("/", tags=["System"])
async def root():
    return {
        "message": "PKI FastAPI Backend is running operational",
        "docs": "/docs",
        "health": "/api/health"
    }
