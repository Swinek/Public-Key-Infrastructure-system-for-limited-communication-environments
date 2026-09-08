import logging
import os
import random
from contextlib import asynccontextmanager
from typing import Optional

import asyncpg
from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from database import close_db, get_pool, init_db, record_to_dict, records_to_list

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("pki_backend")


# Lifespan context manager to handle DB pool startup and shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting PKI Backend with FastAPI...")
    await init_db()
    yield
    logger.info("Shutting down PKI Backend...")
    await close_db()


app = FastAPI(
    title="PKI Management Backend API",
    description="REST API for PKI Certificate and User Management",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS - frontend communicates with this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api_router = APIRouter(prefix="/api")


# --- PYDANTIC MODELS ---

class UserCreate(BaseModel):
    username: str
    email: str
    role: Optional[str] = "user"


class CertificateCreate(BaseModel):
    userId: int


class CertificateRevoke(BaseModel):
    certId: int
    reason: Optional[str] = None


# --- USER ENDPOINTS ---

@api_router.get("/users")
async def get_users():
    """Retrieve all users with information about their active certificate."""
    query = """
        SELECT u.id, u.username, u.email, u.role, u.created_at,
               c.id AS cert_id,
               c.serial_number,
               c.status AS cert_status
        FROM users u
        LEFT JOIN certificates c ON u.id = c.user_id AND c.status = 'ACTIVE'
        ORDER BY u.id ASC
    """
    try:
        pool = get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(query)
            return records_to_list(rows)
    except Exception as exc:
        logger.exception("Server error while retrieving users: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Server error while retrieving users"}
        )


@api_router.post("/users", status_code=201)
async def create_user(payload: UserCreate):
    """Add a new user."""
    username = payload.username.strip()
    email = payload.email.strip()
    role = payload.role.strip() if payload.role else "user"

    if not username or not email:
        return JSONResponse(
            status_code=400,
            content={"error": "Username and email are required"}
        )

    query = "INSERT INTO users (username, email, role) VALUES ($1, $2, $3) RETURNING *"
    try:
        pool = get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, username, email, role)
            return record_to_dict(row)
    except asyncpg.UniqueViolationError:
        return JSONResponse(
            status_code=400,
            content={"error": "Error creating user. Username or email may already be taken."}
        )
    except Exception as exc:
        logger.exception("Error creating user: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Error creating user"}
        )


@api_router.delete("/users/{user_id}")
async def delete_user(user_id: int):
    """Delete a user and cascade-delete their certificates."""
    query = "DELETE FROM users WHERE id = $1"
    try:
        pool = get_pool()
        async with pool.acquire() as conn:
            await conn.execute(query, user_id)
            return {"message": "User deleted successfully"}
    except Exception as exc:
        logger.exception("Error deleting user: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Error deleting user"}
        )


# --- CERTIFICATE ENDPOINTS (PKI) ---

@api_router.get("/certificates")
async def get_certificates():
    """Retrieve all certificates with certificate owner details."""
    query = """
        SELECT c.id, c.user_id, c.serial_number, c.status, c.issued_at, c.revoked_at, c.revocation_reason,
               u.username, u.email
        FROM certificates c
        JOIN users u ON c.user_id = u.id
        ORDER BY c.issued_at DESC
    """
    try:
        pool = get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(query)
            return records_to_list(rows)
    except Exception as exc:
        logger.exception("Server error while retrieving certificates: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Server error while retrieving certificates"}
        )


@api_router.post("/certificates", status_code=201)
async def issue_certificate(payload: CertificateCreate):
    """Issue a new certificate to a user."""
    try:
        pool = get_pool()
        async with pool.acquire() as conn:
            # Check if user already has an active certificate
            check_active = await conn.fetchval(
                "SELECT id FROM certificates WHERE user_id = $1 AND status = 'ACTIVE'",
                payload.userId
            )
            if check_active is not None:
                return JSONResponse(
                    status_code=400,
                    content={"error": "User already possesses an active certificate/signature."}
                )

            # Generate serial number
            serial_number = f"SN-{random.randint(1000000000, 9999999999)}"

            row = await conn.fetchrow(
                "INSERT INTO certificates (user_id, serial_number, status) VALUES ($1, $2, 'ACTIVE') RETURNING *",
                payload.userId,
                serial_number
            )
            return record_to_dict(row)
    except Exception as exc:
        logger.exception("Error generating certificate: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Error generating certificate"}
        )


@api_router.post("/certificates/revoke")
async def revoke_certificate(payload: CertificateRevoke):
    """Revoke a certificate (Certificate Revocation List - CRL)."""
    reason = payload.reason or "Administrative access revocation"
    query = """
        UPDATE certificates
        SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP, revocation_reason = $1
        WHERE id = $2 AND status = 'ACTIVE'
        RETURNING *
    """
    try:
        pool = get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, reason, payload.certId)
            if row is None:
                return JSONResponse(
                    status_code=400,
                    content={"error": "Certificate does not exist or has already been revoked."}
                )
            return record_to_dict(row)
    except Exception as exc:
        logger.exception("Error revoking certificate: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Error revoking certificate"}
        )


@api_router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "pki-backend-fastapi"}


app.include_router(api_router)


@app.get("/")
async def root():
    return {
        "message": "PKI FastAPI Backend is running operational",
        "docs": "/docs",
        "health": "/api/health"
    }
