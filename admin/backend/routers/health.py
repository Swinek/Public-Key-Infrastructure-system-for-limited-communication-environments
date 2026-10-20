from fastapi import APIRouter

router = APIRouter(tags=["System"])


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "pki-backend-fastapi"}
