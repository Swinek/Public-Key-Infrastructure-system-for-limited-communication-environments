import logging
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from database import get_pool, record_to_dict, records_to_list

logger = logging.getLogger("pki_edge_client_backend.users")

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("")
@router.get("/", include_in_schema=False)
async def get_users():
    """Retrieve all users with their active certificate status for identity selection."""
    query = """
        SELECT u.id, u.username, u.email, u.role, u.created_at,
               c.status as cert_status, c.serial_number, c.valid_to
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
        logger.exception("Error retrieving users in client backend: %s", exc)
        return JSONResponse(status_code=500, content={"error": "Database error while fetching users"})


@router.get("/{id}")
async def get_user_by_id(id: int):
    """Retrieve details of a single user."""
    query = """
        SELECT u.id, u.username, u.email, u.role, u.created_at,
               c.status as cert_status, c.serial_number, c.valid_to
        FROM users u
        LEFT JOIN certificates c ON u.id = c.user_id AND c.status = 'ACTIVE'
        WHERE u.id = $1
    """
    try:
        pool = get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, id)
            if row is None:
                return JSONResponse(status_code=404, content={"error": "User not found"})
            return record_to_dict(row)
    except Exception as exc:
        logger.exception("Error retrieving user %d: %s", id, exc)
        return JSONResponse(status_code=500, content={"error": "Database error while fetching user"})
