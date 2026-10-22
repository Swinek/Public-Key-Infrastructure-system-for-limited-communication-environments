import logging
import asyncpg
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from database import get_pool, record_to_dict, records_to_list
from pki.store import issue_crl
from schemas import UserCreate

logger = logging.getLogger("pki_backend.users")

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("")
@router.get("/", include_in_schema=False)
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


@router.post("", status_code=201)
@router.post("/", status_code=201, include_in_schema=False)
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


@router.delete("/{user_id}")
async def delete_user(user_id: int):
    """Delete a user. Active certificates are revoked first and all certificates are kept
    (detached from the user) - a revoked serial must never disappear from the CRL."""
    try:
        pool = get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                revoked = await conn.execute(
                    """
                    UPDATE certificates
                    SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP, revocation_reason = 'User deleted'
                    WHERE user_id = $1 AND status = 'ACTIVE'
                    """,
                    user_id
                )
                await conn.execute("UPDATE certificates SET user_id = NULL WHERE user_id = $1", user_id)
                await conn.execute("DELETE FROM users WHERE id = $1", user_id)
                if revoked != "UPDATE 0":
                    await issue_crl(conn, "revocation")
            return {"message": "User deleted successfully"}
    except Exception as exc:
        logger.exception("Error deleting user: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Error deleting user"}
        )
