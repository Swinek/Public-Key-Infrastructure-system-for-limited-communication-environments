"""Rzeczywisty PostgreSQL: test w transakcji wycofywanej, w osobnym schemacie.

Uruchomienie w Dockerze z PKI_TEST_DATABASE_URL. Nie zmienia danych systemu.
"""
import asyncio
import importlib
import importlib.util
import os
from pathlib import Path
import secrets
import zlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509


@pytest.mark.skipif(not os.getenv("PKI_TEST_DATABASE_URL"), reason="wymaga testowego połączenia PostgreSQL")
def test_sql_issuance_retention_and_expiry(ca_env, monkeypatch):
    import asyncpg
    store = importlib.import_module("pki.store")
    monkeypatch.setattr(store, "load_ca_certificate", ca_env.ca.load_ca_certificate)
    monkeypatch.setattr(store, "generate_crl", ca_env.ca.generate_crl)
    monkeypatch.setattr(store, "generate_delta_crl", ca_env.ca.generate_delta_crl)
    monkeypatch.setattr(store, "CRL_DELTA_BASES", 2)
    root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("portal_crl_test", root / "edge_client/backend/store.py")
    portal = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(portal)

    async def scenario():
        conn = await asyncpg.connect(os.environ["PKI_TEST_DATABASE_URL"])
        tx = conn.transaction()
        await tx.start()
        try:
            schema = "test_crl_" + secrets.token_hex(6)
            await conn.execute(f'CREATE SCHEMA "{schema}"')
            await conn.execute(f'SET LOCAL search_path TO "{schema}", public')
            sql = (root / "admin/backend/init.sql").read_text()
            await conn.execute(sql[:sql.index("DO $$")])
            await store.ensure_csr_schema(conn)
            now = datetime.now(timezone.utc)
            rows = [(str(secrets.randbits(63) or 1), now-timedelta(hours=1), now+timedelta(days=10)) for _ in range(1000)]
            await conn.executemany("INSERT INTO certificates (serial_number, revoked_at, valid_to, status) VALUES ($1,$2,$3,'REVOKED')", rows)
            await store.issue_crl(conn, "manual")
            await conn.execute("INSERT INTO certificates (serial_number, revoked_at, valid_to, status) VALUES ('1',$1,$2,'REVOKED')", now, now+timedelta(days=10))
            await store.issue_crl(conn, "manual")
            candidates = await portal.crl_update_objects(conn)
            full = next((m, b) for m, b in candidates if m["kind"] == "full")
            delta = next((m, b) for m, b in candidates if m["kind"] == "delta")
            assert len(x509.load_der_x509_crl(full[1])) == 1001
            assert len(x509.load_der_x509_crl(delta[1])) == 1
            assert len(zlib.compress(delta[1])) < len(zlib.compress(full[1]))
            print(f"\n1001 wpisów: pełna DER={len(full[1])}, pełna zlib={len(zlib.compress(full[1]))}, delta DER={len(delta[1])}, delta zlib={len(zlib.compress(delta[1]))}")
            await conn.execute("UPDATE certificates SET valid_to=$1 WHERE serial_number='1'", now-timedelta(hours=ca_env.ca.CRL_EXPIRY_MARGIN_HOURS+1))
            await store.issue_crl(conn, "scheduled")
            retained = await conn.fetchval("SELECT crl_der FROM crls WHERE crl_number=3")
            assert x509.load_der_x509_crl(bytes(retained)).get_revoked_certificate_by_serial_number(1) is not None
            await store.issue_crl(conn, "manual")
            candidates = await portal.crl_update_objects(conn)
            full = next(b for m, b in candidates if m["kind"] == "full")
            assert x509.load_der_x509_crl(full).get_revoked_certificate_by_serial_number(1) is None
            delta = next(b for m, b in candidates if m["kind"] == "delta" and m["base"] == 3)
            removal = x509.load_der_x509_crl(delta).get_revoked_certificate_by_serial_number(1)
            assert removal.extensions.get_extension_for_class(x509.CRLReason).value.reason == x509.ReasonFlags.remove_from_crl
            assert await conn.fetchval("SELECT count(*) FROM crl_deltas") == 2
            assert await conn.fetchval("SELECT min(crl_number) FROM crl_deltas") == 4
        finally:
            await tx.rollback()
            await conn.close()
    asyncio.run(scenario())
