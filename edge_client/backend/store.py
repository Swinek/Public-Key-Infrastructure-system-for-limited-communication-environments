"""Odczyt danych PKI z bazy (konto tylko do odczytu). Portal niczego nie podpisuje."""

import zlib
import hashlib
import base64
import textwrap
from typing import Optional

import asyncpg
from fastapi import Request, Response


async def latest_ca(conn: asyncpg.Connection) -> Optional[asyncpg.Record]:
    return await conn.fetchrow(
        """SELECT fingerprint, subject, certificate_der, not_before, not_after
           FROM ca_certificates ORDER BY id DESC LIMIT 1"""
    )


async def latest_crl(conn: asyncpg.Connection) -> Optional[asyncpg.Record]:
    return await conn.fetchrow(
        """SELECT crl_number, this_update, next_update, revoked_count, crl_der
           FROM crls ORDER BY crl_number DESC LIMIT 1"""
    )


def der_to_pem(der: bytes, label: str) -> bytes:
    """Koduje bajty DER jako PEM (RFC 7468): base64 po 64 znaki między nagłówkami."""
    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode(), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n".encode()


def pem_to_der(pem: str) -> bytes:
    """Dekoduje pierwszy blok PEM do DER (bez parsowania ASN.1)."""
    lines = [line.strip() for line in pem.strip().splitlines()]
    body = [line for line in lines if line and not line.startswith("-----")]
    return base64.b64decode("".join(body))


def pki_object_response(request: Request, der: bytes, fmt: str, label: str,
                        filename: str, der_media_type: str, etag: str, compression: str = "none") -> Response:
    """Zwraca obiekt PKI w DER (domyślnie, mniejszy) albo PEM; obsługuje If-None-Match (304)."""
    etag = f'"{etag}-{fmt}{"-zlib" if compression == "zlib" else ""}"'
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    if fmt == "pem":
        content, media_type, filename = der_to_pem(der, label), "application/x-pem-file", f"{filename}.pem"
    else:
        content, media_type, filename = der, der_media_type, f"{filename}.der"
    if compression == "zlib":
        content = zlib.compress(content)
        media_type, filename = "application/zlib", f"{filename}.zlib"
    return Response(
        content=content,
        media_type=media_type,
        headers={"ETag": etag, "Content-Disposition": f'attachment; filename="{filename}"'},
    )


def crl_descriptor(data, kind, number, base=None):
    return {"id": hashlib.sha256(data).hexdigest(), "kind": kind, "number": number,
            "base": base, "size": len(data), "zlib_size": len(zlib.compress(data))}


async def crl_update_objects(conn, full=None):
    full = full if full is not None else await latest_crl(conn)
    if full is None:
        return []
    data = bytes(full["crl_der"])
    result = [(crl_descriptor(data, "full", full["crl_number"]), data)]
    rows = await conn.fetch("SELECT base_number, crl_der FROM crl_deltas WHERE crl_number = $1 ORDER BY base_number DESC",
                            full["crl_number"])
    for row in rows:
        data = bytes(row["crl_der"])
        result.append((crl_descriptor(data, "delta", full["crl_number"], row["base_number"]), data))
    return result
