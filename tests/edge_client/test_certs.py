"""Edge client trzyma jeden certyfikat: wgranie (zastępuje poprzedni), pobranie, sprawdzenie, pakiet tylko dla Edge app
(edge_client/node/certs.py, routers/certs.py)."""

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
    return importlib.import_module("routers.certs")


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


def _upload(client, **files):
    return client.post("/api/certs", files={k: (k, v) for k, v in files.items()})


def _serial(pem_text) -> int:
    data = pem_text if isinstance(pem_text, bytes) else pem_text.encode()
    return x509.load_pem_x509_certificate(data).serial_number


def test_new_upload_replaces_the_certificate(client, ca):
    first, first_key = ca.issue("client_1")
    second, second_key = ca.issue("client_1")

    resp = _upload(client, ca=pem(ca.cert), cert=pem(first), key=key_pem(first_key), crl=der(ca.crl(number=1)))
    assert resp.status_code == 200, resp.text
    assert resp.json()["stored"] == ["ca", "cert", "crl"] and resp.json()["replaced"] is False

    resp = _upload(client, cert=der(second), key=key_pem(second_key))
    assert resp.json()["replaced"] is True

    body = client.get("/api/certs").json()
    assert body["certificate"]["serial_number"] == str(second.serial_number)
    assert "PRIVATE KEY" not in str(body)


def test_certificate_can_be_downloaded_without_key(client, ca):
    assert client.get("/api/certs/certificate").status_code == 404
    cert, key = ca.issue("client_1")
    _upload(client, ca=pem(ca.cert), cert=pem(cert), key=key_pem(key))

    resp = client.get("/api/certs/certificate")
    assert resp.status_code == 200
    assert _serial(resp.content) == cert.serial_number
    assert "client_1_cert.pem" in resp.headers["content-disposition"]
    assert b"PRIVATE KEY" not in resp.content


def test_bundle_is_only_for_the_edge_app(client):
    resp = client.get("/api/certs/bundle")
    assert resp.status_code == 403


def test_bundle_has_certificate_key_ca_and_crl(client, ca, as_edge_app):
    assert client.get("/api/certs/bundle").json()["certificate"] is None
    first, first_key = ca.issue("client_1")
    second, second_key = ca.issue("client_1")
    _upload(client, ca=pem(ca.cert), cert=pem(first), key=key_pem(first_key), crl=der(ca.crl(number=4)))
    _upload(client, cert=pem(second), key=key_pem(second_key))

    bundle = client.get("/api/certs/bundle").json()
    assert _serial(bundle["certificate"]) == second.serial_number
    assert "PRIVATE KEY" in bundle["private_key"]
    assert x509.load_pem_x509_crl(bundle["crl_pem"].encode()).extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 4


def test_upload_checks(client, ca):
    cert, key = ca.issue("client_1")
    _, other_key = ca.issue("client_1")
    assert _upload(client, cert=pem(cert), key=key_pem(key)).status_code == 400  # brak CA
    assert _upload(client, ca=pem(ca.cert)).status_code == 200
    assert _upload(client, cert=pem(cert)).status_code == 400  # bez klucza
    resp = _upload(client, cert=pem(cert), key=key_pem(other_key))
    assert resp.status_code == 400 and "nie pasuje" in resp.json()["detail"]["error"]
    foreign, foreign_key = TestCA("Foreign CA").issue("client_1")
    assert _upload(client, cert=pem(foreign), key=key_pem(foreign_key)).status_code == 400
    assert _upload(client, ca=pem(TestCA("Rogue CA").cert)).status_code == 400
    assert client.get("/api/certs").json()["certificate"] is None


def test_rejected_upload_keeps_the_previous_certificate(client, ca):
    cert, key = ca.issue("client_1")
    _upload(client, ca=pem(ca.cert), cert=pem(cert), key=key_pem(key))
    _, other_key = ca.issue("client_1")
    newer, _ = ca.issue("client_1")
    assert _upload(client, cert=pem(newer), key=key_pem(other_key)).status_code == 400
    assert client.get("/api/certs").json()["certificate"]["serial_number"] == str(cert.serial_number)


def test_older_crl_is_skipped(client, ca):
    _upload(client, ca=pem(ca.cert), crl=der(ca.crl(number=5)))
    body = _upload(client, crl=der(ca.crl(number=4))).json()
    assert body["stored"] == [] and body["warnings"]
    assert body["status"]["crl"]["number"] == 5


def test_certificate_has_offline_verdict(client, ca):
    cert, key = ca.issue("client_1", not_after=NOW + 3650 * DAY)
    _upload(client, ca=pem(ca.cert), cert=pem(cert), key=key_pem(key))
    assert client.get("/api/certs").json()["certificate"]["verdict"]["status"] == "unknown"  # bez CRL

    _upload(client, crl=der(ca.crl(number=1, this_update=NOW, next_update=NOW + 3650 * DAY)))
    assert client.get("/api/certs").json()["certificate"]["verdict"]["status"] == "valid"

    _upload(client, crl=der(ca.crl(revoked=[cert], number=2, this_update=NOW, next_update=NOW + 3650 * DAY)))
    assert client.get("/api/certs").json()["certificate"]["verdict"]["status"] == "revoked"


def test_verify_endpoint(client, ca):
    assert client.post("/api/certs/verify").status_code == 400  # jeszcze bez certyfikatu
    cert, key = ca.issue("client_1", not_after=NOW + 3650 * DAY)
    _upload(client, ca=pem(ca.cert), cert=pem(cert), key=key_pem(key),
            crl=der(ca.crl(number=1, this_update=NOW - DAY, next_update=NOW + DAY)))
    at = NOW.isoformat()

    body = client.post("/api/certs/verify", data={"at": at}).json()  # domyślnie zapisany certyfikat
    assert body["stored"] is True and body["status"] == "valid" and body["checked_at"] == at
    assert client.post("/api/certs/verify", data={"at": (NOW + 3 * DAY).isoformat()}).json()["status"] == "unknown"

    other, _ = TestCA("Foreign CA").issue("x")
    resp = client.post("/api/certs/verify", files={"cert": ("c.pem", pem(other))}, data={"at": at}).json()
    assert resp["stored"] is False and resp["status"] == "invalid"
    assert client.post("/api/certs/verify", files={"cert": ("c.pem", b"garbage")}).json()["status"] == "invalid"
    assert client.post("/api/certs/verify", data={"at": "yesterday"}).status_code == 400


def test_files_are_recognised_by_content(client, ca):
    """Jedno pole 'files': certyfikat, klucz, Root CA i CRL w dowolnej kolejności i formacie (PEM/DER)."""
    cert, key = ca.issue("client_1")
    files = [("files", ("a.bin", der(ca.crl(number=3)))), ("files", ("b.bin", key_pem(key))),
             ("files", ("c.bin", der(cert))), ("files", ("d.bin", pem(ca.cert)))]
    body = client.post("/api/certs", files=files).json()
    assert sorted(body["stored"]) == ["ca", "cert", "crl"]
    assert body["status"]["certificate"]["serial_number"] == str(cert.serial_number)
    assert body["status"]["crl"]["number"] == 3


def test_unrecognised_or_duplicate_files(client, ca):
    assert client.post("/api/certs", files=[("files", ("x.txt", b"hello"))]).status_code == 400
    first, _ = ca.issue("client_1")
    second, _ = ca.issue("client_1")
    resp = client.post("/api/certs", files=[("files", ("1.pem", pem(first))), ("files", ("2.pem", pem(second)))])
    assert resp.status_code == 400 and "cert" in resp.json()["detail"]


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
