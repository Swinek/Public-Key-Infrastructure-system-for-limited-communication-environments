import asyncio
import logging
import os
from typing import Any, List, Optional
import asyncpg

logger = logging.getLogger("pki_client_backend")

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://pki_admin:pki_secure_password@localhost:5433/pki_db"
)

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]

_pool: Optional[asyncpg.Pool] = None


async def init_db(max_retries: int = 15, retry_delay: float = 2.0) -> asyncpg.Pool:
    """Initialize asyncpg connection pool with retry mechanism."""
    global _pool
    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"Connecting to database (attempt {attempt}/{max_retries})...")
            _pool = await asyncpg.create_pool(
                dsn=DATABASE_URL,
                min_size=2,
                max_size=10,
                command_timeout=60
            )
            logger.info("Client database connection pool established successfully.")
            return _pool
        except Exception as exc:
            logger.warning(f"Database connection failed: {exc}. Retrying in {retry_delay}s...")
            if attempt == max_retries:
                logger.error("Could not connect to database after maximum retries.")
                raise
            await asyncio.sleep(retry_delay)
    raise RuntimeError("Failed to connect to database")


async def close_db() -> None:
    """Close asyncpg connection pool."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("Client database connection pool closed.")


def get_pool() -> asyncpg.Pool:
    """Retrieve active connection pool."""
    if _pool is None:
        raise RuntimeError("Database pool has not been initialized.")
    return _pool


def record_to_dict(record: Optional[asyncpg.Record]) -> Optional[dict]:
    """Convert an asyncpg Record to a JSON-serializable Python dictionary."""
    if record is None:
        return None
    d = dict(record)
    for key, value in d.items():
        if hasattr(value, "isoformat"):
            d[key] = value.isoformat()
    return d


def records_to_list(records: List[asyncpg.Record]) -> List[dict]:
    """Convert a list of asyncpg Records to a list of dictionaries."""
    return [record_to_dict(r) for r in records if r is not None]
