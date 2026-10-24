"""Endpointy dla węzłów brzegowych: najpierw małe metadane (/pki/summary), potem tylko brakujące obiekty.

Obiekty domyślnie w DER (mniej bajtów na wolnym łączu), PEM przez ?format=pem.
ETag = CRLNumber / fingerprint, więc węzeł z aktualną wersją dostaje 304 bez treści.
"""

import logging

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from database import get_pool, record_to_dict, records_to_list
from store import latest_ca, latest_crl, pem_to_der, pki_object_response

logger = logging.getLogger("pki_edge_client_backend.pki")

router = APIRouter(prefix="/pki", tags=["PKI (węzły)"])

FORMAT = Query("der", pattern="^(der|pem)$")


@router.get("/summary")
async def get_summary():
    """Numery wersji i rozmiary obiektów PKI - węzeł porównuje je z lokalnymi przed pobraniem."""
    pool = get_pool()
    async with pool.acquire() as conn:
        ca = await latest_ca(conn)
        crl = await latest_crl(conn)
        certs = await conn.fetchrow(
            """SELECT COUNT(*) FILTER (WHERE status = 'ACTIVE') AS active,
                      COUNT(*) FILTER (WHERE status = 'REVOKED') AS revoked,
                      MAX(GREATEST(issued_at, revoked_at)) AS last_change
               FROM certificates WHERE certificate_pem IS NOT NULL"""
        )
    return {
        "ca": None if ca is None else {
            "fingerprint": ca["fingerprint"],
            "subject": ca["subject"],
            "not_after": ca["not_after"].isoformat(),
            "size": len(ca["certificate_der"]),
        },
        "crl": None if crl is None else {
            "number": crl["crl_number"],
            "this_update": crl["this_update"].isoformat(),
            "next_update": crl["next_update"].isoformat(),
            "revoked_count": crl["revoked_count"],
            "size": len(crl["crl_der"]),
        },
        "certs": record_to_dict(certs),
    }


@router.get("/ca")
async def get_ca(request: Request, format: str = FORMAT):
    """Certyfikat Root CA (DER lub PEM)."""
    pool = get_pool()
    async with pool.acquire() as conn:
        ca = await latest_ca(conn)
    if ca is None:
        return JSONResponse(status_code=404, content={"error": "Root CA not registered yet"})
    return pki_object_response(request, bytes(ca["certificate_der"]), format, "CERTIFICATE",
                               "ca_certificate", "application/pkix-cert", ca["fingerprint"][:16])


@router.get("/crl")
async def get_crl(request: Request, format: str = FORMAT):
    """Ostatnia CRL podpisana przez CA (DER lub PEM), ETag = CRLNumber."""
    pool = get_pool()
    async with pool.acquire() as conn:
        crl = await latest_crl(conn)
    if crl is None:
        return JSONResponse(status_code=404, content={"error": "CRL not issued yet"})
    return pki_object_response(request, bytes(crl["crl_der"]), format, "X509 CRL",
                               "crl", "application/pkix-crl", f"crl-{crl['crl_number']}")


@router.get("/certs")
async def list_certs(status: str | None = Query(None, pattern="^(ACTIVE|REVOKED)$")):
    """Lista wydanych certyfikatów (metadane, bez treści) - węzeł pobiera tylko te, których nie ma."""
    query = """
        SELECT c.serial_number, COALESCE(u.username, '(usunięty)') AS username, c.status, c.fingerprint, c.valid_from, c.valid_to,
               c.revoked_at, length(c.certificate_pem) AS size_pem
        FROM certificates c LEFT JOIN users u ON c.user_id = u.id
        WHERE c.certificate_pem IS NOT NULL AND ($1::text IS NULL OR c.status = $1)
        ORDER BY c.issued_at DESC
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, status)
    return records_to_list(rows)


@router.get("/certs/{serial_number}")
async def get_cert(request: Request, serial_number: str, format: str = FORMAT):
    """Certyfikat o podanym numerze seryjnym (DER lub PEM)."""
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT certificate_pem, fingerprint FROM certificates WHERE serial_number = $1",
            serial_number,
        )
    if row is None or not row["certificate_pem"]:
        return JSONResponse(status_code=404, content={"error": "Certificate not found"})
    return pki_object_response(request, pem_to_der(row["certificate_pem"]), format, "CERTIFICATE",
                               f"cert_{serial_number}", "application/pkix-cert", row["fingerprint"][:16])
