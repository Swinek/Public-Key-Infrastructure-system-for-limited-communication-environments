"""Wnioski CSR węzłów: węzeł sam generuje klucz i wniosek, administrator zatwierdza albo odrzuca każdy wniosek.

Wniosek trafia do bazy przez portal (edge_client/backend/routers/pki.py, POST /pki/csr). Zatwierdzenie:
    - podpis certyfikatu na klucz z wniosku (klucz prywatny nie opuszcza węzła, CA go nigdy nie widzi),
    - zarejestrowanie węzła (użytkownik o nazwie = CN), jeśli jeszcze go nie ma,
    - odwołanie poprzedniego aktywnego certyfikatu węzła (węzeł ma jeden certyfikat naraz) i nowa CRL,
    - NOTIFY cert_issued: portal budzi węzły online, a węzeł pobiera certyfikat przy tym kontakcie.

Wniosek węzła bez internetu przynoszą sąsiedzi (Etap 3c, relayed_via = trasa). Pośrednik mógłby złożyć wniosek
z cudzym CN i własnym kluczem, dlatego przed zatwierdzeniem odcisk klucza porównuje się poza systemem z odciskiem
widocznym w panelu węzła.
"""

import logging

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from database import get_pool, record_to_dict, records_to_list
from pki.ca import CsrError, load_csr, public_key_fingerprint, sign_csr
from pki.store import CERT_NOTIFY_CHANNEL, issue_crl
from schemas import CsrDecision

logger = logging.getLogger("pki_backend.csr")

router = APIRouter(prefix="/csr", tags=["CSR (wnioski węzłów)"])

COLUMNS = """r.id, r.node_id, r.key_fingerprint, r.status, r.reason, r.created_at, r.decided_at,
             r.certificate_id, c.serial_number, length(r.csr_der) AS size_der, r.relayed_via"""


@router.get("")
async def list_requests(status: str | None = Query(None, pattern="^(PENDING|APPROVED|REJECTED)$")):
    """Wnioski CSR (najnowsze pierwsze), opcjonalnie tylko o danym statusie."""
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""SELECT {COLUMNS} FROM csr_requests r LEFT JOIN certificates c ON c.id = r.certificate_id
                WHERE $1::text IS NULL OR r.status = $1 ORDER BY r.created_at DESC""",
            status,
        )
    return records_to_list(rows)


async def _pending(conn, request_id: int):
    return await conn.fetchrow(
        "SELECT * FROM csr_requests WHERE id = $1 AND status = 'PENDING' FOR UPDATE", request_id
    )


@router.post("/{request_id}/approve")
async def approve_request(request_id: int):
    """Wystawia certyfikat na klucz z wniosku i zastępuje nim poprzedni certyfikat węzła."""
    pool = get_pool()
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                req = await _pending(conn, request_id)
                if req is None:
                    return JSONResponse(status_code=400, content={"error": "Wniosek nie istnieje albo już rozpatrzony."})
                csr = load_csr(bytes(req["csr_der"]))
                if public_key_fingerprint(csr.public_key()) != req["key_fingerprint"]:
                    return JSONResponse(status_code=400, content={"error": "Odcisk klucza nie zgadza się z wnioskiem."})

                node_id = req["node_id"]
                user = await conn.fetchrow("SELECT id, username, email FROM users WHERE username = $1", node_id)
                if user is None:  # zatwierdzenie wniosku = rejestracja węzła
                    user = await conn.fetchrow(
                        "INSERT INTO users (username, email, role) VALUES ($1, $2, 'node') RETURNING id, username, email",
                        node_id, f"{node_id}@nodes.pki.local",
                    )
                cert = sign_csr(bytes(req["csr_der"]), user["username"], user["email"])

                superseded = await conn.fetch(
                    """UPDATE certificates SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP,
                              revocation_reason = 'superseded'
                       WHERE user_id = $1 AND status = 'ACTIVE' RETURNING serial_number""",
                    user["id"],
                )
                row = await conn.fetchrow(
                    """INSERT INTO certificates (user_id, serial_number, certificate_pem, fingerprint,
                                                 valid_from, valid_to, status)
                       VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE') RETURNING *""",
                    user["id"], cert["serial_number"], cert["certificate_pem"], cert["fingerprint"],
                    cert["valid_from"], cert["valid_to"],
                )
                await conn.execute(
                    """UPDATE csr_requests SET status = 'APPROVED', certificate_id = $2, decided_at = CURRENT_TIMESTAMP
                       WHERE id = $1""",
                    request_id, row["id"],
                )
                crl = await issue_crl(conn, "revocation") if superseded else None
                await conn.execute("SELECT pg_notify($1, $2)", CERT_NOTIFY_CHANNEL, node_id)
    except CsrError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except Exception as exc:
        logger.exception("Error approving CSR %s: %s", request_id, exc)
        return JSONResponse(status_code=500, content={"error": "Error approving CSR"})

    logger.info("CSR %s zatwierdzony: certyfikat %s dla %s (zastąpione: %d)",
                request_id, cert["serial_number"], node_id, len(superseded))
    result = record_to_dict(row)
    result.update({"node_id": node_id, "superseded": [r["serial_number"] for r in superseded],
                   "crl_number": crl["crl_number"] if crl else None})
    return result


@router.post("/{request_id}/reject")
async def reject_request(request_id: int, payload: CsrDecision | None = None):
    """Odrzuca wniosek. Węzeł nie wysyła go ponownie – nowy wniosek tylko na żądanie operatora węzła."""
    reason = (payload.reason if payload else None) or "Odrzucony przez administratora"
    pool = get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            req = await _pending(conn, request_id)
            if req is None:
                return JSONResponse(status_code=400, content={"error": "Wniosek nie istnieje albo już rozpatrzony."})
            row = await conn.fetchrow(
                """UPDATE csr_requests SET status = 'REJECTED', reason = $2, decided_at = CURRENT_TIMESTAMP
                   WHERE id = $1 RETURNING id, node_id, key_fingerprint, status, reason, decided_at""",
                request_id, reason[:255],
            )
            await conn.execute("SELECT pg_notify($1, $2)", CERT_NOTIFY_CHANNEL, req["node_id"])
    return record_to_dict(row)
