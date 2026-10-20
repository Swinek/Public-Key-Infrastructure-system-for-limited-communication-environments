import logging
import os
from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse
import httpx

from database import get_pool, record_to_dict, records_to_list

logger = logging.getLogger("pki_client_backend.certificates")

router = APIRouter(prefix="/certificates", tags=["Certificates"])

ADMIN_BACKEND_URL = os.getenv("ADMIN_BACKEND_URL", "http://admin-backend:5000")


@router.get("")
@router.get("/", include_in_schema=False)
async def get_certificates():
    """Retrieve all certificates with certificate owner details (read-only)."""
    query = """
        SELECT c.id, c.user_id, c.serial_number, c.status, c.issued_at, c.revoked_at, c.revocation_reason,
               c.certificate_pem, c.fingerprint, c.valid_from, c.valid_to,
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
        logger.exception("Error while retrieving certificates in client backend: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Server error while retrieving certificates"}
        )


@router.get("/user/{user_id}")
async def get_user_certificate(user_id: int):
    """Retrieve active or latest certificate credentials for a specific user/node."""
    query = """
        SELECT c.id, c.user_id, c.serial_number, c.status, c.issued_at, c.revoked_at, c.revocation_reason,
               c.certificate_pem, c.fingerprint, c.valid_from, c.valid_to,
               u.username, u.email
        FROM certificates c
        JOIN users u ON c.user_id = u.id
        WHERE c.user_id = $1
        ORDER BY c.issued_at DESC
        LIMIT 1
    """
    try:
        pool = get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, user_id)
            if row is None:
                return JSONResponse(
                    status_code=404,
                    content={"error": "No certificate found for this user/node."}
                )
            return record_to_dict(row)
    except Exception as exc:
        logger.exception("Error retrieving user certificate: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Database error while fetching user certificate"}
        )


@router.get("/ca/download")
@router.get("/ca")
async def download_ca_certificate():
    """Proxy request to fetch the Root CA certificate (PEM) from Admin CA backend."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{ADMIN_BACKEND_URL}/api/certificates/ca/download")
            if resp.status_code == 200:
                return Response(
                    content=resp.content,
                    media_type="application/x-pem-file",
                    headers={"Content-Disposition": 'attachment; filename="ca_certificate.pem"'}
                )
            return JSONResponse(status_code=resp.status_code, content={"error": "Upstream CA unavailable"})
    except Exception as exc:
        logger.warning("Could not reach upstream Admin CA backend for Root CA: %s", exc)
        return JSONResponse(
            status_code=503,
            content={"error": "Root CA download temporarily unavailable from upstream CA"}
        )


@router.get("/crl/download")
@router.get("/crl")
async def download_crl():
    """Proxy request to fetch the latest Certificate Revocation List (CRL) from Admin CA backend."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{ADMIN_BACKEND_URL}/api/certificates/crl/download")
            if resp.status_code == 200:
                return Response(
                    content=resp.content,
                    media_type="application/x-pem-file",
                    headers={"Content-Disposition": 'attachment; filename="crl.pem"'}
                )
            return JSONResponse(status_code=resp.status_code, content={"error": "Upstream CRL unavailable"})
    except Exception as exc:
        logger.warning("Could not reach upstream Admin CA backend for CRL: %s", exc)
        return JSONResponse(
            status_code=503,
            content={"error": "CRL download temporarily unavailable from upstream CA"}
        )
