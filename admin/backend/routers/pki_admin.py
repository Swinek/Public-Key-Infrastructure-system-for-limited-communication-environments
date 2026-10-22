import logging

from cryptography import x509
from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from database import get_pool, record_to_dict, records_to_list
from pki.ca import describe_certificate, load_ca_certificate
from pki.store import CRL_META_COLUMNS, CRL_REISSUE_HOURS, issue_crl, latest_crl
from utils import der_to_pem

logger = logging.getLogger("pki_backend.pki")

router = APIRouter(prefix="/pki", tags=["PKI"])


@router.get("/ca")
async def get_ca_info():
    """Root CA metadata: algorithm, SKI, KeyUsage, fingerprint, validity."""
    return describe_certificate(load_ca_certificate())


@router.get("/crl")
async def get_current_crl():
    """Metadata and entries of the latest stored CRL."""
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await latest_crl(conn, with_der=True)
    if row is None:
        return JSONResponse(status_code=404, content={"error": "CRL not issued yet"})

    der = bytes(row["crl_der"])
    crl = x509.load_der_x509_crl(der)
    result = record_to_dict(row)
    del result["crl_der"]
    result["size_pem"] = len(der_to_pem(der, "X509 CRL"))
    result["signature_algorithm"] = crl.signature_algorithm_oid._name
    result["reissue_hours"] = CRL_REISSUE_HOURS
    result["entries"] = [
        {"serial_number": str(entry.serial_number),
         "revocation_date": entry.revocation_date_utc.isoformat()}
        for entry in crl
    ]
    return result


@router.get("/crls")
async def get_crl_history(limit: int = Query(50, ge=1, le=500)):
    """History of issued CRLs (metadata only, newest first)."""
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"SELECT {CRL_META_COLUMNS} FROM crls ORDER BY crl_number DESC LIMIT $1", limit
        )
    return records_to_list(rows)


@router.post("/crl", status_code=201)
async def issue_crl_now():
    """Sign a new CRL immediately (manual trigger from the admin panel)."""
    try:
        pool = get_pool()
        async with pool.acquire() as conn:
            row = await issue_crl(conn, "manual")
        return record_to_dict(row)
    except Exception as exc:
        logger.exception("Error issuing CRL: %s", exc)
        return JSONResponse(status_code=500, content={"error": "Error issuing CRL"})


@router.get("/certificates/{cert_id}")
async def get_certificate_details(cert_id: int):
    """X.509 extensions (AKI/SKI/KeyUsage) and sizes of an issued certificate."""
    pool = get_pool()
    async with pool.acquire() as conn:
        pem = await conn.fetchval("SELECT certificate_pem FROM certificates WHERE id = $1", cert_id)
    if not pem:
        return JSONResponse(status_code=404, content={"error": "Certificate not found or has no PEM"})
    return describe_certificate(x509.load_pem_x509_certificate(pem.encode()))
