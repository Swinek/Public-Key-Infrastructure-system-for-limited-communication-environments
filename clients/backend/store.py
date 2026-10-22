"""Odczyt danych PKI z bazy (konto tylko do odczytu). Portal niczego nie podpisuje."""

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
                        filename: str, der_media_type: str, etag: str) -> Response:
    """Zwraca obiekt PKI w DER (domyślnie, mniejszy) albo PEM; obsługuje If-None-Match (304)."""
    etag = f'"{etag}-{fmt}"'
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    if fmt == "pem":
        content, media_type, filename = der_to_pem(der, label), "application/x-pem-file", f"{filename}.pem"
    else:
        content, media_type, filename = der, der_media_type, f"{filename}.der"
    return Response(
        content=content,
        media_type=media_type,
        headers={"ETag": etag, "Content-Disposition": f'attachment; filename="{filename}"'},
    )
