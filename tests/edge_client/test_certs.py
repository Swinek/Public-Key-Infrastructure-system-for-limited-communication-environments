"""Edge client trzyma jeden certyfikat: bez wgrywania certyfikatu, klucza i Root CA; pobranie, sprawdzenie offline,
pakiet tylko dla Edge app, awaryjne wgranie CRL (edge_client/node/certs.py, routers/certs.py)."""

from __future__ import annotations

import importlib

import pytest
from cryptography import x509
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.pki_factory import DAY, NOW, TestCA, der, key_pem, pem


@pytest.fixture
def module(edge_client_node_env, monkeypatch):
    monkeypatch.setenv("NODE_ID", "client_1")
    monkeypatch.setenv("EDGE_APP_URL", "http://app_1:8000")
    module = importlib.import_module("routers.certs")
    monkeypatch.setattr(importlib.import_module("contact"), "announce", lambda *a, **k: [])
    monkeypatch.setattr(importlib.import_module("contact"), "on_wan", lambda wait=False: {"status": "skipped"})
    return module


@pytest.fixture
def client(module):
    app = FastAPI()
    app.include_router(module.router)
    return TestClient(app)


@pytest.fixture
def as_edge_app(module, monkeypatch):
    """Żądania z TestClient udają Edge app tego węzła (sprawdzenie adresu źródłowego)."""
    monkeypatch.setattr(module, "is_edge_app", lambda host: True)


@pytest.fixture(scope="module")
def ca():
    return TestCA()


def _store():
    return importlib.import_module("certs").get_store()


def _install(ca, cert=None, key=None, crl=None):
    """Stan węzła jak po synchronizacji z portalem i zatwierdzonym wniosku (bez wgrywania przez API)."""
    store = _store()
    store.set_ca(pem(ca.cert))
    if cert is not None:
        store.set_certificate(pem(cert), key_pem(key))
    if crl is not None:
        store.update_crl(der(crl))
    return store


def _serial(pem_text) -> int:
    data = pem_text if isinstance(pem_text, bytes) else pem_text.encode()
    return x509.load_pem_x509_certificate(data).serial_number


def test_there_is_no_upload_of_certificate_key_or_ca(client, ca):
    cert, key = ca.issue("client_1")
    files = {"ca": ("ca", pem(ca.cert)), "cert": ("cert", pem(cert)), "key": ("key", key_pem(key))}
    assert client.post("/api/certs", files=files).status_code == 405
    assert _store().ca() is None and _store().certificate() is None


def test_status_shows_certificate_without_key(client, ca):
    cert, key = ca.issue("client_1")
    _install(ca, cert, key)
    body = client.get("/api/certs").json()
    assert body["certificate"]["serial_number"] == str(cert.serial_number)
    assert body["request"] is None and "PRIVATE KEY" not in str(body)


def test_certificate_can_be_downloaded_without_key(client, ca):
    assert client.get("/api/certs/certificate").status_code == 404
    cert, key = ca.issue("client_1")
    _install(ca, cert, key)
    resp = client.get("/api/certs/certificate")
    assert _serial(resp.content) == cert.serial_number
    assert "client_1_cert.pem" in resp.headers["content-disposition"]
    assert b"PRIVATE KEY" not in resp.content


def test_bundle_is_only_for_the_edge_app(client):
    assert client.get("/api/certs/bundle").status_code == 403


def test_bundle_has_certificate_key_ca_and_crl(client, ca, as_edge_app):
    assert client.get("/api/certs/bundle").json()["certificate"] is None
    cert, key = ca.issue("client_1")
    _install(ca, cert, key, ca.crl(number=4))
    bundle = client.get("/api/certs/bundle").json()
    assert _serial(bundle["certificate"]) == cert.serial_number
    assert "PRIVATE KEY" in bundle["private_key"]
    crl = x509.load_pem_x509_crl(bundle["crl_pem"].encode())
    assert crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 4


def test_crl_upload_only_signed_and_newer(client, ca):
    assert client.post("/api/certs/crl", files={"crl": ("c", der(ca.crl(number=5)))}).status_code == 400  # brak CA
    _install(ca)
    assert client.post("/api/certs/crl", files={"crl": ("c", der(ca.crl(number=5)))}).json()["stored"] == ["crl"]
    body = client.post("/api/certs/crl", files={"crl": ("c", der(ca.crl(number=4)))}).json()
    assert body["stored"] == [] and body["warnings"] and body["status"]["crl"]["number"] == 5
    forged = TestCA(cn="Test Root CA").crl(number=9)  # ta sama nazwa, inny klucz
    assert client.post("/api/certs/crl", files={"crl": ("c", der(forged))}).status_code == 400


def test_new_request_generates_key_on_the_node(client, ca):
    _install(ca)
    body = client.post("/api/certs/csr").json()
    request = body["status"]["request"]
    assert request["status"] == "NEW" and len(request["key_fingerprint"]) == 64
    assert "csr_der" not in request and "PRIVATE KEY" not in str(body)
    pending = _store().pending()
    csr = x509.load_der_x509_csr(pending["csr_der"])
    assert csr.is_signature_valid
    assert csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "client_1"


def test_certificate_has_offline_verdict(client, ca):
    cert, key = ca.issue("client_1", not_after=NOW + 3650 * DAY)
    _install(ca, cert, key)
    assert client.get("/api/certs").json()["certificate"]["verdict"]["status"] == "unknown"  # bez CRL
    _store().update_crl(der(ca.crl(number=1, this_update=NOW, next_update=NOW + 3650 * DAY)))
    assert client.get("/api/certs").json()["certificate"]["verdict"]["status"] == "valid"
    _store().update_crl(der(ca.crl(revoked=[cert], number=2, this_update=NOW, next_update=NOW + 3650 * DAY)))
    assert client.get("/api/certs").json()["certificate"]["verdict"]["status"] == "revoked"


def test_verify_endpoint(client, ca):
    assert client.post("/api/certs/verify").status_code == 400  # jeszcze bez certyfikatu
    cert, key = ca.issue("client_1", not_after=NOW + 3650 * DAY)
    _install(ca, cert, key, ca.crl(number=1, this_update=NOW - DAY, next_update=NOW + DAY))
    at = NOW.isoformat()

    body = client.post("/api/certs/verify", data={"at": at}).json()  # domyślnie zapisany certyfikat
    assert body["stored"] is True and body["status"] == "valid" and body["checked_at"] == at
    assert client.post("/api/certs/verify", data={"at": (NOW + 3 * DAY).isoformat()}).json()["status"] == "unknown"

    other, _ = TestCA("Foreign CA").issue("x")
    resp = client.post("/api/certs/verify", files={"cert": ("c.pem", pem(other))}, data={"at": at}).json()
    assert resp["stored"] is False and resp["status"] == "invalid"
    assert client.post("/api/certs/verify", files={"cert": ("c.pem", b"garbage")}).json()["status"] == "invalid"
    assert client.post("/api/certs/verify", data={"at": "yesterday"}).status_code == 400


def test_old_version_layout_is_migrated(module, tmp_path, ca):
    """Dawny układ (versions/<n>/, active) – zostaje tylko aktywna wersja jako jedyny certyfikat."""
    certs = importlib.import_module("certs")
    root = tmp_path / "old"
    first, first_key = ca.issue("client_1")
    second, second_key = ca.issue("client_1")
    for n, (cert, key) in ((1, (first, first_key)), (2, (second, second_key))):
        (root / "versions" / str(n)).mkdir(parents=True)
        (root / "versions" / str(n) / "cert.pem").write_bytes(pem(cert))
        (root / "versions" / str(n) / "key.pem").write_bytes(key_pem(key))
    (root / "active").write_text("2")

    store = certs.CertStore(root)
    assert store.certificate().serial_number == second.serial_number
    assert not (root / "versions").exists() and not (root / "active").exists()
