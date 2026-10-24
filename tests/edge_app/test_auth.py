"""Końcowe użycie certyfikatu: uwierzytelnianie Edge app wyzwaniem i podpisem (edge_app/routers/auth.py)."""

from __future__ import annotations

import base64
import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.pki_factory import DAY, NOW, TestCA, key_pem, pem


@pytest.fixture(scope="module")
def ca():
    return TestCA()


@pytest.fixture
def auth(edge_app_env, monkeypatch, ca):
    """Moduł auth aplikacji app_1 z zainstalowanym CA, certyfikatem client_1 i bieżącą CRL."""
    monkeypatch.setenv("NODE_ID", "client_1")
    monkeypatch.setenv("APP_ID", "app_1")
    pki = importlib.import_module("pki")
    cert, key = ca.issue("client_1", not_before=NOW - DAY, not_after=NOW + 3650 * DAY)
    store = pki.get_store()
    store.install(pem(ca.cert), pem(cert), key_pem(key))
    store.update_crl(pem(ca.crl(this_update=NOW - DAY, next_update=NOW + 3650 * DAY)))
    return importlib.import_module("routers.auth")


def _peer_proof(auth, ca, nonce, verifier="app_1", cn="client_2", **issue):
    """Dowód, jaki przedstawiłby inny węzeł: jego certyfikat i podpis wyzwania jego kluczem."""
    cert, key = ca.issue(cn, **issue)
    signature = base64.b64encode(auth.sign(key, auth.signed_message(nonce, verifier))).decode()
    return pem(cert).decode(), signature


def test_valid_proof_is_accepted(auth, ca):
    nonce = auth.issue_challenge()
    cert_pem, sig = _peer_proof(auth, ca, nonce, not_after=NOW + 3650 * DAY)
    result = auth.verify_proof(nonce, cert_pem, sig)
    assert result["authenticated"] is True
    assert result["peer"] == "client_2"
    assert result["verdict"]["status"] == "valid"


def test_nonce_is_single_use(auth, ca):
    nonce = auth.issue_challenge()
    cert_pem, sig = _peer_proof(auth, ca, nonce, not_after=NOW + 3650 * DAY)
    assert auth.verify_proof(nonce, cert_pem, sig)["authenticated"] is True
    replay = auth.verify_proof(nonce, cert_pem, sig)
    assert replay["authenticated"] is False and "nonce" in replay["reason"]


def test_unknown_nonce_is_rejected(auth, ca):
    cert_pem, sig = _peer_proof(auth, ca, "made-up", not_after=NOW + 3650 * DAY)
    assert auth.verify_proof("made-up", cert_pem, sig)["authenticated"] is False


def test_proof_for_another_verifier_is_rejected(auth, ca):
    """Podpis związany z innym weryfikatorem (app_3) nie może być przekazany dalej do app_1."""
    nonce = auth.issue_challenge()
    cert_pem, sig = _peer_proof(auth, ca, nonce, verifier="app_3", not_after=NOW + 3650 * DAY)
    result = auth.verify_proof(nonce, cert_pem, sig)
    assert result["authenticated"] is False and "Podpis" in result["reason"]


def test_signature_with_other_key_is_rejected(auth, ca):
    nonce = auth.issue_challenge()
    cert_pem, _ = _peer_proof(auth, ca, nonce, not_after=NOW + 3650 * DAY)
    _, stolen_sig = _peer_proof(auth, ca, nonce, not_after=NOW + 3650 * DAY)
    assert auth.verify_proof(nonce, cert_pem, stolen_sig)["authenticated"] is False


def test_certificate_from_foreign_ca_is_rejected(auth):
    foreign = TestCA("Foreign CA")
    nonce = auth.issue_challenge()
    cert_pem, sig = _peer_proof(auth, foreign, nonce, not_after=NOW + 3650 * DAY)
    result = auth.verify_proof(nonce, cert_pem, sig)
    assert result["authenticated"] is False
    assert result["verdict"]["status"] == "invalid"


def test_revoked_certificate_is_rejected(auth, ca):
    cert, key = ca.issue("client_2", not_after=NOW + 3650 * DAY)
    pki = importlib.import_module("pki")
    pki.get_store().update_crl(pem(ca.crl(revoked=[cert], number=2, this_update=NOW, next_update=NOW + 3650 * DAY)))
    nonce = auth.issue_challenge()
    sig = base64.b64encode(auth.sign(key, auth.signed_message(nonce, "app_1"))).decode()
    result = auth.verify_proof(nonce, pem(cert).decode(), sig)
    assert result["authenticated"] is False
    assert result["verdict"]["status"] == "revoked"


def test_own_proof_round_trip(auth):
    """make_proof podpisuje własnym kluczem; ten sam węzeł potrafi go zweryfikować (ten sam CA)."""
    nonce = auth.issue_challenge()
    proof = auth.make_proof(nonce, "app_1")
    result = auth.verify_proof(nonce, proof["certificate"], proof["signature"])
    assert result["authenticated"] is True and result["peer"] == "client_1"


def test_api_challenge_and_peer_validation(auth, monkeypatch):
    refreshed = []
    monkeypatch.setattr(auth, "ensure_certificate", lambda: refreshed.append(True))
    app = FastAPI()
    app.include_router(auth.router)
    client = TestClient(app)
    body = client.get("/api/auth/challenge").json()
    assert body["app_id"] == "app_1" and len(body["nonce"]) >= 32
    assert refreshed == [True]  # przed wyzwaniem aplikacja odświeża dane od Edge clienta
    assert client.post("/api/auth/peer", json={"peer": "app_1"}).status_code == 400
    assert client.post("/api/auth/peer", json={"peer": "client_2"}).status_code == 400


def test_prove_without_certificate_is_conflict(edge_app_env, monkeypatch):
    monkeypatch.setenv("APP_ID", "app_1")
    auth = importlib.import_module("routers.auth")
    app = FastAPI()
    app.include_router(auth.router)
    resp = TestClient(app).post("/api/auth/prove", json={"nonce": "x", "verifier": "app_2"})
    assert resp.status_code == 409
