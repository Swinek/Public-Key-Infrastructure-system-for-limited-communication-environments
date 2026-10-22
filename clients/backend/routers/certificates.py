import logging

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from database import get_pool, record_to_dict, records_to_list
from store import latest_ca, latest_crl, pki_object_response

logger = logging.getLogger("pki_client_backend.certificates")

router = APIRouter(prefix="/certificates", tags=["Certificates"])


@router.get("")
@router.get("/", include_in_schema=False)
async def get_certificates():
    """Retrieve all certificates with certificate owner details (read-only)."""
    query = """
        SELECT c.id, c.user_id, c.serial_number, c.status, c.issued_at, c.revoked_at, c.revocation_reason,
               c.certificate_pem, c.fingerprint, c.valid_from, c.valid_to,
               COALESCE(u.username, '(usunięty)') AS username, u.email
        FROM certificates c
        LEFT JOIN users u ON c.user_id = u.id
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
               COALESCE(u.username, '(usunięty)') AS username, u.email
        FROM certificates c
        LEFT JOIN users u ON c.user_id = u.id
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


# Pobieranie dla człowieka (portal) - domyślnie PEM. Dane czytane z bazy, bez proxy do CA.
@router.get("/ca/download")
@router.get("/ca")
async def download_ca_certificate(request: Request, format: str = Query("pem", pattern="^(pem|der)$")):
    """Download the Root CA certificate stored in the database (PEM by default)."""
    pool = get_pool()
    async with pool.acquire() as conn:
        ca = await latest_ca(conn)
    if ca is None:
        return JSONResponse(status_code=404, content={"error": "Root CA not registered yet"})
    return pki_object_response(request, bytes(ca["certificate_der"]), format, "CERTIFICATE",
                               "ca_certificate", "application/pkix-cert", ca["fingerprint"][:16])


@router.get("/crl/download")
@router.get("/crl")
async def download_crl(request: Request, format: str = Query("pem", pattern="^(pem|der)$")):
    """Download the latest CRL stored in the database (PEM by default)."""
    pool = get_pool()
    async with pool.acquire() as conn:
        crl = await latest_crl(conn)
    if crl is None:
        return JSONResponse(status_code=404, content={"error": "CRL not issued yet"})
    return pki_object_response(request, bytes(crl["crl_der"]), format, "X509 CRL",
                               "crl", "application/pkix-crl", f"crl-{crl['crl_number']}")
