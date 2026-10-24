"""Edge app: instalacja danych PKI pobranych od Edge clienta, /api/pki/fetch, /status (edge_app/routers/pki.py)."""

from __future__ import annotations

import importlib

import pytest
import requests
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from tests.pki_factory import DAY, NOW, TestCA, der, key_pem, pem


class _Response:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body
        self.text = str(body)

    def json(self):
        return self._body


@pytest.fixture
def module(edge_app_env, monkeypatch):
    monkeypatch.setenv("NODE_ID", "client_1")
    monkeypatch.setenv("EDGE_CLIENT_URL", "http://client_1:8000")
    return importlib.import_module("routers.pki")


@pytest.fixture
def client(module):
    app = FastAPI()
    app.include_router(module.router)
    return TestClient(app)


@pytest.fixture(scope="module")
def ca():
    return TestCA()


@pytest.fixture(scope="module")
def node(ca):
    return ca.issue("client_1")


def _install(module, ca=None, cert=None, key=None, crl=None):
    """install_objects jak przy pobraniu od Edge clienta; zwraca (kod, treść) jak endpoint."""
    try:
        installed, warnings = module.install_objects(ca, cert, key, crl)
    except HTTPException as exc:
        return exc.status_code, exc.detail
    return 200, {"installed": installed, "warnings": warnings}


def _bundle(ca, cert, key, crl):
    return {
        "ca": pem(ca.cert).decode(),
        "certificate": None if cert is None else pem(cert).decode(),
        "private_key": None if key is None else key_pem(key).decode(),
        "crl_pem": None if crl is None else pem(crl).decode(),
    }


def _edge_client_returns(module, monkeypatch, status_code, body, calls=None):
    def fake_get(url, timeout=None):
        if calls is not None:
            calls.append(url)
        return _Response(status_code, body)
    monkeypatch.setattr(module.requests, "get", fake_get)


def test_status_of_empty_store(client):
    body = client.get("/api/pki/status").json()
    assert body["node_id"] == "client_1"
    assert body["ca"] is None and body["node"] is None and body["crl"] is None
    assert body["own_certificate"] is None and body["source"] is None


def test_fetch_installs_certificate_from_edge_client(client, module, monkeypatch, ca, node):
    cert, key = node
    calls = []
    # CRL ważna długo: status liczony jest względem bieżącego zegara, nie stałej NOW z pki_factory.
    crl = ca.crl(number=3, this_update=NOW - DAY, next_update=NOW + 3650 * DAY)
    _edge_client_returns(module, monkeypatch, 200, _bundle(ca, cert, key, crl), calls)

    resp = client.post("/api/pki/fetch")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert calls == ["http://client_1:8000/api/certs/bundle"]
    assert body["installed"] == ["ca", "cert", "crl"] and body["warnings"] == []
    assert body["status"]["source"]["serial_number"] == str(cert.serial_number)
    assert body["status"]["crl"]["number"] == 3
    assert body["status"]["own_certificate"]["status"] == "valid"
    assert "PRIVATE KEY" not in resp.text


def test_fetching_again_replaces_the_used_certificate(client, module, monkeypatch, ca, node):
    first, first_key = node
    second, second_key = ca.issue("client_1")
    _edge_client_returns(module, monkeypatch, 200, _bundle(ca, second, second_key, None))
    assert client.post("/api/pki/fetch").status_code == 200
    _edge_client_returns(module, monkeypatch, 200, _bundle(ca, first, first_key, None))
    body = client.post("/api/pki/fetch").json()
    assert body["status"]["node"]["serial_number"] == str(first.serial_number)
    assert body["status"]["source"]["serial_number"] == str(first.serial_number)


def test_fetch_without_certificate_on_edge_client(client, module, monkeypatch, ca):
    _edge_client_returns(module, monkeypatch, 200, _bundle(ca, None, None, None))
    assert client.post("/api/pki/fetch").status_code == 404


def test_fetch_refused_or_unreachable_edge_client(client, module, monkeypatch):
    _edge_client_returns(module, monkeypatch, 403, {"detail": "tylko Edge app"})
    resp = client.post("/api/pki/fetch")
    assert resp.status_code == 403 and "tylko Edge app" in resp.json()["detail"]

    def down(*args, **kwargs):
        raise requests.ConnectionError("no route")

    monkeypatch.setattr(module.requests, "get", down)
    assert client.post("/api/pki/fetch").status_code == 502


def test_fetch_rejects_certificate_of_foreign_ca(client, module, monkeypatch, ca):
    foreign_cert, foreign_key = TestCA("Foreign CA").issue("client_1")
    _edge_client_returns(module, monkeypatch, 200, _bundle(ca, foreign_cert, foreign_key, None))
    resp = client.post("/api/pki/fetch")
    assert resp.status_code == 400
    assert resp.json()["detail"]["installed"] == ["ca"]
    assert client.get("/api/pki/status").json()["node"] is None


def test_install_warns_when_cn_differs_from_node_id(module, ca):
    cert, key = ca.issue("client_9")
    code, body = _install(module, ca=der(ca.cert), cert=der(cert), key=key_pem(key))
    assert code == 200 and any("NODE_ID" in w for w in body["warnings"])


def test_install_requires_cert_and_key_together(module, ca, node):
    cert, _ = node
    assert _install(module, ca=der(ca.cert), cert=der(cert))[0] == 400


def test_install_rejects_other_ca_after_pinning(module, ca):
    assert _install(module, ca=der(ca.cert))[0] == 200
    code, detail = _install(module, ca=der(TestCA("Rogue CA").cert))
    assert code == 400 and "przypiętym" in detail["error"]


def test_older_crl_is_skipped_with_warning(module, ca):
    _install(module, ca=der(ca.cert), crl=der(ca.crl(number=5)))
    code, body = _install(module, crl=der(ca.crl(number=4)))
    assert code == 200 and body["installed"] == [] and body["warnings"]


def test_install_rejects_oversized_object(module):
    assert _install(module, crl=b"x" * (300 * 1024))[0] == 413


def test_ensure_certificate_takes_fresh_data(module, monkeypatch, ca, node):
    cert, key = node
    _edge_client_returns(module, monkeypatch, 200, _bundle(ca, cert, key, ca.crl(number=7)))
    assert module.ensure_certificate() is None
    assert module.current_source()["serial_number"] == str(cert.serial_number)


def test_ensure_certificate_offline_uses_last_copy(module, monkeypatch, ca, node):
    def down(*args, **kwargs):
        raise requests.ConnectionError("no route")

    monkeypatch.setattr(module.requests, "get", down)
    with pytest.raises(HTTPException) as exc:  # nic jeszcze nie pobrano
        module.ensure_certificate()
    assert exc.value.status_code == 502

    cert, key = node
    _install(module, ca=der(ca.cert), cert=der(cert), key=key_pem(key))
    warning = module.ensure_certificate()
    assert warning and "ostatnio pobranego" in warning
