import logging
from fastapi import APIRouter, Query, Response
from fastapi.responses import JSONResponse

from database import get_pool, record_to_dict, records_to_list
from pki.ca import CA_CERT_PATH, initialize_ca, issue_user_certificate
from pki.store import issue_crl, latest_crl
from schemas import CertificateCreate, CertificateRevoke
from utils import der_to_pem

logger = logging.getLogger("pki_backend.certificates")

router = APIRouter(prefix="/certificates", tags=["Certificates"])


@router.get("")
@router.get("/", include_in_schema=False)
async def get_certificates():
    """Retrieve all certificates with certificate owner details."""
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
        logger.exception("Server error while retrieving certificates: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Server error while retrieving certificates"}
        )


@router.post("", status_code=201)
@router.post("/", status_code=201, include_in_schema=False)
async def issue_certificate(payload: CertificateCreate):
    """Issue a new X.509 certificate signed by Root CA."""
    try:
        pool = get_pool()
        async with pool.acquire() as conn:
            check_active = await conn.fetchval(
                """
                SELECT id
                FROM certificates
                WHERE user_id = $1
                AND status = 'ACTIVE'
                """,
                payload.userId
            )

            if check_active is not None:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "User already possesses an active certificate."
                    }
                )

            user = await conn.fetchrow(
                """
                SELECT username, email
                FROM users
                WHERE id = $1
                """,
                payload.userId
            )

            if user is None:
                return JSONResponse(
                    status_code=404,
                    content={"error": "User not found"}
                )

            cert_data = issue_user_certificate(
                username=user["username"],
                email=user["email"]
            )

            row = await conn.fetchrow(
                """
                INSERT INTO certificates (
                    user_id,
                    serial_number,
                    certificate_pem,
                    fingerprint,
                    valid_from,
                    valid_to,
                    status
                )
                VALUES (
                    $1, $2, $3, $4, $5, $6, 'ACTIVE'
                )
                RETURNING *
                """,
                payload.userId,
                cert_data["serial_number"],
                cert_data["certificate_pem"],
                cert_data["fingerprint"],
                cert_data["valid_from"],
                cert_data["valid_to"]
            )

            result = record_to_dict(row)

            result["private_key"] = cert_data["private_key_pem"]

            return result

    except Exception as exc:
        logger.exception("Error generating certificate: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Error generating certificate"}
        )


@router.post("/revoke")
async def revoke_certificate(payload: CertificateRevoke):
    """Revoke a certificate and sign a new CRL (same transaction: status and CRL stay consistent)."""
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
            async with conn.transaction():
                row = await conn.fetchrow(query, reason, payload.certId)
                if row is None:
                    return JSONResponse(
                        status_code=400,
                        content={"error": "Certificate does not exist or has already been revoked."}
                    )
                crl = await issue_crl(conn, "revocation")

            result = record_to_dict(row)
            result["crl_number"] = crl["crl_number"]
            return result
    except Exception as exc:
        logger.exception("Error revoking certificate: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Error revoking certificate"}
        )


@router.get("/ca/download")
@router.get("/ca")
async def download_ca_certificate():
    """Download the Root CA certificate (PEM)."""
    if not CA_CERT_PATH.exists():
        initialize_ca()

    return Response(
        content=CA_CERT_PATH.read_bytes(),
        media_type="application/x-pem-file",
        headers={
            "Content-Disposition": 'attachment; filename="ca_certificate.pem"'
        }
    )


@router.get("/crl/download")
@router.get("/crl")
async def download_crl(format: str = Query("pem", pattern="^(pem|der)$")):
    """Download the latest stored Certificate Revocation List (CRL) - does not sign a new one."""
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await latest_crl(conn, with_der=True)

    if row is None:
        return JSONResponse(
            status_code=404,
            content={"error": "CRL not issued yet"}
        )

    if format == "der":
        return Response(
            content=bytes(row["crl_der"]),
            media_type="application/pkix-crl",
            headers={"Content-Disposition": 'attachment; filename="crl.der"'}
        )
    return Response(
        content=der_to_pem(bytes(row["crl_der"]), "X509 CRL"),
        media_type="application/x-pem-file",
        headers={
            "Content-Disposition": 'attachment; filename="crl.pem"'
        }
    )
