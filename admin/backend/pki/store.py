"""Zapis certyfikatu CA i podpisanych CRL w bazie (tabele ca_certificates, crls).

CRL jest podpisywana tylko przy odwołaniu, ręcznie z panelu albo okresowo (co CRL_REISSUE_HOURS).
GET /crl zwraca ostatnią zapisaną listę - nie podpisuje nowej, więc ten sam CRLNumber
oznacza zawsze te same bajty (ważne dla porównywania wersji między węzłami).
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

import asyncpg
from cryptography.hazmat.primitives import hashes, serialization

from pki.ca import generate_crl, load_ca_certificate

logger = logging.getLogger("pki_backend.store")

CRL_REISSUE_HOURS = int(os.getenv("CRL_REISSUE_HOURS", "24"))
CRL_CHECK_INTERVAL_SECONDS = int(os.getenv("CRL_CHECK_INTERVAL_SECONDS", "600"))

# Kanał NOTIFY z numerem nowej CRL (ta sama nazwa w edge_client/backend/announce.py).
CRL_NOTIFY_CHANNEL = "crl_issued"

# Klucz blokady doradczej: serializuje nadawanie numerów CRL (dwa wystawienia naraz nie dostaną tego samego).
_CRL_LOCK_KEY = 0x43524C  # "CRL"

CRL_META_COLUMNS = """crl_number, ca_fingerprint, this_update, next_update, revoked_count,
                      length(crl_der) AS size_der, trigger, created_at"""


# Wnioski CSR węzłów (Etap 3b). Portal może je tylko dodawać i czytać; decyzję podejmuje administrator w CA.
# Wykonywane przy każdym starcie (init.sql działa tylko na pustej bazie), więc istniejąca baza też dostaje tabelę.
CSR_SCHEMA = """
CREATE TABLE IF NOT EXISTS csr_requests (
    id SERIAL PRIMARY KEY,
    node_id VARCHAR(50) NOT NULL,
    key_fingerprint VARCHAR(64) UNIQUE NOT NULL,
    csr_der BYTEA NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    reason VARCHAR(255),
    certificate_id INT REFERENCES certificates(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    decided_at TIMESTAMPTZ
);
-- Etap 3c: trasa wniosku przyniesionego przez sąsiadów (np. 'client_3,client_2,client_1'); NULL = wysłany bezpośrednio.
ALTER TABLE csr_requests ADD COLUMN IF NOT EXISTS relayed_via VARCHAR(255);
GRANT SELECT, INSERT ON csr_requests TO pki_portal;
GRANT USAGE ON SEQUENCE csr_requests_id_seq TO pki_portal;
"""

# Kanał NOTIFY: wydano certyfikat na wniosek (payload = node_id) – portal budzi węzły, a te pobierają certyfikat.
CERT_NOTIFY_CHANNEL = "cert_issued"


async def ensure_csr_schema(conn: asyncpg.Connection) -> None:
    await conn.execute(CSR_SCHEMA)


async def register_ca_certificate(conn: asyncpg.Connection) -> str:
    """Zapisuje bieżący certyfikat CA w bazie (jeśli go tam nie ma). Zwraca fingerprint SHA-256."""
    cert = load_ca_certificate()
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    await conn.execute(
        """
        INSERT INTO ca_certificates (fingerprint, subject, certificate_der, not_before, not_after)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (fingerprint) DO NOTHING
        """,
        fingerprint,
        cert.subject.rfc4514_string(),
        cert.public_bytes(serialization.Encoding.DER),
        cert.not_valid_before_utc,
        cert.not_valid_after_utc,
    )
    return fingerprint


async def issue_crl(conn: asyncpg.Connection, trigger: str) -> dict:
    """Podpisuje nową CRL z kolejnym CRLNumber i zapisuje ją w bazie.

    Wywoływać wewnątrz transakcji wywołującego (np. razem ze zmianą statusu certyfikatu)
    albo samodzielnie - wtedy funkcja otwiera własną transakcję.
    """
    if conn.is_in_transaction():
        return await _issue_crl_locked(conn, trigger)
    async with conn.transaction():
        return await _issue_crl_locked(conn, trigger)


async def _issue_crl_locked(conn: asyncpg.Connection, trigger: str) -> dict:
    await conn.execute("SELECT pg_advisory_xact_lock($1)", _CRL_LOCK_KEY)
    crl_number = await conn.fetchval("SELECT COALESCE(MAX(crl_number), 0) + 1 FROM crls")
    revoked_rows = await conn.fetch(
        "SELECT serial_number, revoked_at FROM certificates WHERE status = 'REVOKED' ORDER BY revoked_at"
    )
    crl = generate_crl([dict(r) for r in revoked_rows], crl_number)
    ca_fingerprint = load_ca_certificate().fingerprint(hashes.SHA256()).hex()
    row = await conn.fetchrow(
        f"""
        INSERT INTO crls (crl_number, ca_fingerprint, this_update, next_update, revoked_count, crl_der, trigger)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING {CRL_META_COLUMNS}
        """,
        crl_number,
        ca_fingerprint,
        crl.last_update_utc,
        crl.next_update_utc,
        len(crl),
        crl.public_bytes(serialization.Encoding.DER),
        trigger,
    )
    # Impuls dla węzłów: portal (edge_client/backend/announce.py) nasłuchuje na tym kanale i od razu wyzwala
    # kontakt WAN u węzłów, które mają internet. NOTIFY w transakcji dochodzi dopiero po jej zatwierdzeniu.
    await conn.execute("SELECT pg_notify($1, $2)", CRL_NOTIFY_CHANNEL, str(crl_number))
    logger.info("Wystawiono CRL nr %d (%s, %d wpisów)", crl_number, trigger, len(crl))
    return dict(row)


async def latest_crl(conn: asyncpg.Connection, with_der: bool = False):
    columns = CRL_META_COLUMNS + (", crl_der" if with_der else "")
    return await conn.fetchrow(f"SELECT {columns} FROM crls ORDER BY crl_number DESC LIMIT 1")


async def ensure_fresh_crl(conn: asyncpg.Connection) -> None:
    """Wystawia CRL, jeśli jej nie ma, jest podpisana innym CA albo jest starsza niż CRL_REISSUE_HOURS."""
    ca_fingerprint = await register_ca_certificate(conn)
    latest = await latest_crl(conn)
    now = datetime.now(timezone.utc)
    if latest is None:
        await issue_crl(conn, "startup")
    elif latest["ca_fingerprint"] != ca_fingerprint:
        await issue_crl(conn, "new_ca")
    elif now - latest["this_update"] >= timedelta(hours=CRL_REISSUE_HOURS):
        await issue_crl(conn, "scheduled")


async def crl_scheduler(pool: asyncpg.Pool) -> None:
    """Zadanie w tle: okresowo sprawdza, czy trzeba podpisać nową CRL."""
    while True:
        try:
            async with pool.acquire() as conn:
                await ensure_fresh_crl(conn)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Błąd okresowego wystawiania CRL: %s", exc)
        await asyncio.sleep(CRL_CHECK_INTERVAL_SECONDS)
