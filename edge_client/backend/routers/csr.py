"""Wnioski CSR od węzłów: portal przyjmuje wniosek i podaje jego status, ale niczego nie podpisuje.

Węzeł (edge_client/node/enroll.py) generuje klucz sam i wysyła tylko wniosek PKCS#10. Portal sprawdza podpis
wniosku (dowód posiadania klucza) i zapisuje go w csr_requests – jedyna tabela, do której konto portalu może
dopisywać. Decyzję i podpis certyfikatu wykonuje administrator w CA (admin/backend/routers/csr.py); wydany
certyfikat węzeł pobiera jako dane publiczne (/pki/certs/{serial}).

Węzeł bez internetu wysyła wniosek przez sąsiadów (edge_client/node/relay.py): przewoźnik z internetem składa go
w imieniu węzła z nagłówkiem X-PKI-Route, a portal zapisuje trasę w relayed_via (do porównania przez administratora).
"""

import hashlib
import logging
import re

import asyncpg
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, Path, Request
from fastapi.responses import JSONResponse

import announce
from database import get_pool

logger = logging.getLogger("pki_edge_client_backend.csr")

router = APIRouter(prefix="/pki", tags=["PKI (węzły)"])

MAX_CSR_BYTES = 4096
FINGERPRINT = Path(..., pattern="^[0-9a-f]{64}$")
# Wniosek przyniesiony przez sąsiadów (Etap 3c): trasa węzeł → … → przewoźnik z internetem, np. client_3,client_2,client_1.
ROUTE_HEADER = "x-pki-route"
ROUTE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,50}(,[A-Za-z0-9_.-]{1,50}){1,15}$")


class CsrRejected(ValueError):
    pass


def parse_route(value: str | None, node_id: str) -> str | None:
    """Trasa z nagłówka X-PKI-Route (tylko informacja dla administratora – pośrednik nie jest zaufany)."""
    if not value:
        return None
    if len(value) > 255 or not ROUTE_PATTERN.match(value):
        raise CsrRejected("Niepoprawna trasa wniosku (X-PKI-Route).")
    if value.split(",", 1)[0] != node_id:
        raise CsrRejected("Trasa wniosku musi zaczynać się od węzła z CN.")
    return value


def parse_csr(data: bytes) -> tuple[str, str, bytes]:
    """Sprawdza wniosek. Zwraca (node_id = CN, SHA-256 z SubjectPublicKeyInfo, wniosek w DER)."""
    if not data or len(data) > MAX_CSR_BYTES:
        raise CsrRejected(f"Wniosek pusty albo większy niż {MAX_CSR_BYTES} B.")
    try:
        csr = (x509.load_pem_x509_csr(data) if data.lstrip().startswith(b"-----BEGIN")
               else x509.load_der_x509_csr(data))
    except ValueError as exc:
        raise CsrRejected(f"Niepoprawny wniosek CSR: {exc}") from exc
    if not csr.is_signature_valid:
        raise CsrRejected("Podpis wniosku CSR jest niepoprawny.")
    names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    node_id = str(names[0].value) if names else ""
    if not node_id or len(node_id) > 50:
        raise CsrRejected("Wniosek musi mieć CN = identyfikator węzła (do 50 znaków).")
    spki = csr.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return node_id, hashlib.sha256(spki).hexdigest(), csr.public_bytes(serialization.Encoding.DER)


async def _status(conn: asyncpg.Connection, fingerprint: str):
    return await conn.fetchrow(
        """SELECT r.node_id, r.key_fingerprint, r.status, r.reason, c.serial_number
           FROM csr_requests r LEFT JOIN certificates c ON c.id = r.certificate_id
           WHERE r.key_fingerprint = $1""",
        fingerprint,
    )


def _public(row) -> dict:
    return {"node_id": row["node_id"], "key_fingerprint": row["key_fingerprint"], "status": row["status"],
            "reason": row["reason"], "serial_number": row["serial_number"]}


@router.post("/csr")
async def submit_csr(request: Request):
    """Przyjmuje wniosek CSR (DER lub PEM w treści żądania). Ten sam klucz drugi raz = status istniejącego."""
    announce.remember(request)
    data = await request.body()
    try:
        node_id, fingerprint, csr_der = parse_csr(data)
        route = parse_route(request.headers.get(ROUTE_HEADER), node_id)
    except CsrRejected as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})

    pool = get_pool()
    async with pool.acquire() as conn:
        existing = await _status(conn, fingerprint)
        if existing is not None:
            return _public(existing)
        pending = await conn.fetchval(
            "SELECT key_fingerprint FROM csr_requests WHERE node_id = $1 AND status = 'PENDING'", node_id
        )
        if pending is not None:  # jeden oczekujący wniosek na węzeł – bez zalewania panelu wnioskami
            return JSONResponse(status_code=409, content={
                "error": f"{node_id} ma już oczekujący wniosek (inny klucz) – administrator musi go rozpatrzyć."})
        async with conn.transaction():
            await conn.execute("SET TRANSACTION READ WRITE")  # konto portalu domyślnie tylko do odczytu
            await conn.execute(
                "INSERT INTO csr_requests (node_id, key_fingerprint, csr_der, relayed_via) VALUES ($1, $2, $3, $4)",
                node_id, fingerprint, csr_der, route,
            )
        row = await _status(conn, fingerprint)
    logger.info("Wniosek CSR od %s (klucz %s...)%s", node_id, fingerprint[:16], f" przez {route}" if route else "")
    return _public(row)


@router.get("/csr/{fingerprint}")
async def csr_status(request: Request, fingerprint: str = FINGERPRINT):
    """Status wniosku dla klucza: PENDING / APPROVED (+ numer seryjny certyfikatu) / REJECTED."""
    announce.remember(request)
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await _status(conn, fingerprint)
    if row is None:
        return JSONResponse(status_code=404, content={"error": "Brak wniosku dla tego klucza."})
    return _public(row)
