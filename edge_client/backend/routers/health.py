import logging
from fastapi import APIRouter

logger = logging.getLogger("pki_edge_client_backend.health")

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("")
@router.get("/", include_in_schema=False)
async def health_check():
    """Health check endpoint for monitoring."""
    return {"status": "ok", "service": "pki-edge-client-backend-fastapi"}
