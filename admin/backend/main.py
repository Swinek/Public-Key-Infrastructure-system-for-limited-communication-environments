import asyncio
import logging
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import close_db, get_pool, init_db
from pki.ca import initialize_ca
from pki.store import crl_scheduler, ensure_csr_schema
from routers import certificates, csr, health, pki_admin, users

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("pki_backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager to handle Root CA setup, DB pool and periodic CRL issuing."""
    logger.info("Starting PKI Backend with FastAPI...")
    initialize_ca()
    await init_db()
    async with get_pool().acquire() as conn:
        await ensure_csr_schema(conn)
    # Pierwsze wywołanie zapisuje certyfikat CA w bazie i w razie potrzeby wystawia CRL nr 1.
    scheduler = asyncio.create_task(crl_scheduler(get_pool()))
    yield
    logger.info("Shutting down PKI Backend...")
    scheduler.cancel()
    with suppress(asyncio.CancelledError):
        await scheduler
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
app.include_router(pki_admin.router, prefix="/api")
app.include_router(csr.router, prefix="/api")
app.include_router(health.router, prefix="/api")


@app.get("/", tags=["System"])
async def root():
    return {
        "message": "PKI FastAPI Backend is running operational",
        "docs": "/docs",
        "health": "/api/health"
    }
