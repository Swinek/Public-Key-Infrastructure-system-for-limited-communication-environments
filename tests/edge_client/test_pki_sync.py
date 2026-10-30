"""Synchronizacja CRL / Root CA przy kontakcie (edge_client/node/pki_sync.py) i endpointy /pki/* Edge clienta.

Peer (portal albo sąsiad) jest podstawiony: wire.get zwraca przygotowane odpowiedzi, więc testy sprawdzają
decyzje węzła – co pobiera, co odrzuca i co zapisuje – bez sieci.
"""

from __future__ import annotations

import importlib
import json
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.pki_factory import TestCA, der, pem

NEIGHBOUR = {"kind": "neighbour", "id": "client_2", "url": "http://192.168.12.20:8000"}
PORTAL = {"kind": "wan", "id": "portal", "url": "http://portal:5001"}


@pytest.fixture(scope="module")
def ca():
    return TestCA()


@pytest.fixture
def node(edge_client_node_env, monkeypatch):
    monkeypatch.setenv("NODE_ID", "client_1")
    monkeypatch.delenv("CA_FINGERPRINT", raising=False)
    return _load(monkeypatch)


def _load(monkeypatch):
    sync = importlib.import_module("pki_sync")
    contact = importlib.import_module("contact")
    announced = []
    monkeypatch.setattr(contact, "announce", lambda reason, exclude=None, wait=False: announced.append((reason, exclude)))
    sync.announced = announced
    return sync


class FakePeer:
    """Odpowiedzi peera: ścieżka -> bajty. Zapisuje, co pobrano."""

    def __init__(self, wire, objects):
        self.wire, self.objects, self.requests = wire, objects, []

    def get(self, url, limit):
        path = url.split(":8000", 1)[-1].split(":5001", 1)[-1]
        self.requests.append(path)
        body = self.objects[path]
        if len(body) > limit:
            raise self.wire.WireError(f"Odpowiedź przekracza limit {limit} B – pobieranie przerwane.")
        return self.wire.Fetched(200, body, len(body) + 300)


def _peer(node, monkeypatch, ca, crl=None, declared_crl_size=None, ca_cert=None):
    wire = importlib.import_module("wire")
    ca_cert = ca_cert or ca.cert
    summary = {"ca": {"fingerprint": ca_cert.fingerprint(hashes.SHA256()).hex(), "size": len(der(ca_cert))},
               "crl": None}
    objects = {"/pki/ca": der(ca_cert)}
    if crl is not None:
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        summary["crl"] = {"number": number, "size": declared_crl_size or len(der(crl))}
        objects["/pki/crl"] = der(crl)
    objects["/pki/summary"] = json.dumps(summary).encode()
    fake = FakePeer(wire, objects)
    monkeypatch.setattr(wire, "get", fake.get)
    return fake


def _store(node):
    return importlib.import_module("certs").get_store()


def _transfers():
    return importlib.import_module("transfers").entries()


def test_newer_crl_from_neighbour_is_stored_and_announced(node, monkeypatch, ca):
    _store(node).set_ca(pem(ca.cert))
    _store(node).update_crl(der(ca.crl(number=3)))
    peer = _peer(node, monkeypatch, ca, ca.crl(number=5))

    assert node.exchange(NEIGHBOUR) == {"ca": "same", "crl": "stored"}
    assert importlib.import_module("certs").crl_number(_store(node).crl()) == 5
    assert peer.requests == ["/pki/summary", "/pki/crl"]  # CA ten sam – nie pobrany
    assert node.announced == [("crl-5", "client_2")]  # dalej, ale nie do źródła
    kinds = {(e["kind"], e["status"]) for e in _transfers()}
    assert {("summary", "ok"), ("crl_full", "ok"), ("ca_cert", "skipped")} <= kinds


def test_same_crl_is_not_downloaded_and_counted_as_saved(node, monkeypatch, ca):
    _store(node).set_ca(pem(ca.cert))
    crl = ca.crl(number=4)
    _store(node).update_crl(der(crl))
    peer = _peer(node, monkeypatch, ca, crl)

    assert node.exchange(NEIGHBOUR)["crl"] == "same"
    assert peer.requests == ["/pki/summary"]
    saved = [e for e in _transfers() if e["kind"] == "crl_full"]
    assert saved[0]["status"] == "skipped" and saved[0]["saved_bytes"] == len(der(crl))
    assert node.announced == []


def test_older_crl_from_neighbour_is_ignored(node, monkeypatch, ca):
    _store(node).set_ca(pem(ca.cert))
    _store(node).update_crl(der(ca.crl(number=7)))
    peer = _peer(node, monkeypatch, ca, ca.crl(number=6))
    assert node.exchange(NEIGHBOUR)["crl"] == "same"
    assert peer.requests == ["/pki/summary"]


def test_forged_crl_is_rejected_and_previous_kept(node, monkeypatch, ca):
    """Złośliwy pośrednik: CRL o wyższym numerze, ale podpisana innym kluczem."""
    _store(node).set_ca(pem(ca.cert))
    _store(node).update_crl(der(ca.crl(number=2)))
    rogue = TestCA(cn="Test Root CA")  # ta sama nazwa, inny klucz
    _peer(node, monkeypatch, ca, rogue.crl(number=9))

    with pytest.raises(node.PkiSyncError, match="odrzucona"):
        node.exchange(NEIGHBOUR)
    assert importlib.import_module("certs").crl_number(_store(node).crl()) == 2
    assert any(e["kind"] == "crl_full" and e["status"] == "rejected" for e in _transfers())
    assert node.announced == []


def test_crl_larger_than_declared_is_aborted(node, monkeypatch, ca):
    _store(node).set_ca(pem(ca.cert))
    crl = ca.crl(number=8)
    _peer(node, monkeypatch, ca, crl, declared_crl_size=50)

    with pytest.raises(node.PkiSyncError, match="limit"):
        node.exchange(NEIGHBOUR)
    assert _store(node).crl() is None
    assert any(e["kind"] == "crl_full" and e["status"] == "aborted" for e in _transfers())


def test_declared_size_above_hard_limit_is_not_downloaded(node, monkeypatch, ca):
    _store(node).set_ca(pem(ca.cert))
    peer = _peer(node, monkeypatch, ca, ca.crl(number=8), declared_crl_size=10 ** 9)
    with pytest.raises(node.PkiSyncError):
        node.exchange(NEIGHBOUR)
    assert "/pki/crl" not in peer.requests


def test_no_ca_without_pin_even_from_portal(node, monkeypatch, ca):
    """Bez CA_FINGERPRINT żadne CA nie jest przyjmowane (koniec zaufania przy pierwszym użyciu)."""
    peer = _peer(node, monkeypatch, ca, ca.crl(number=1))
    assert node.exchange(PORTAL) == {"ca": None, "crl": None}
    assert _store(node).ca() is None and "/pki/ca" not in peer.requests


def test_ca_from_neighbour_without_pin_is_not_taken(node, monkeypatch, ca):
    peer = _peer(node, monkeypatch, ca, ca.crl(number=1))
    assert node.exchange(NEIGHBOUR) == {"ca": None, "crl": None}  # bez CA nie da się sprawdzić CRL
    assert _store(node).ca() is None and peer.requests == ["/pki/summary"]


def test_ca_from_neighbour_with_matching_pin(edge_client_node_env, monkeypatch, ca):
    monkeypatch.setenv("CA_FINGERPRINT", ca.cert.fingerprint(hashes.SHA256()).hex().upper())
    node = _load(monkeypatch)
    _peer(node, monkeypatch, ca, ca.crl(number=1))
    assert node.exchange(NEIGHBOUR) == {"ca": "stored", "crl": "stored"}


def test_pinned_ca_rejects_other_ca(edge_client_node_env, monkeypatch, ca):
    monkeypatch.setenv("CA_FINGERPRINT", ca.cert.fingerprint(hashes.SHA256()).hex())
    node = _load(monkeypatch)
    rogue = TestCA("Rogue CA")
    peer = _peer(node, monkeypatch, ca, ca_cert=rogue.cert)
    node.exchange(PORTAL)
    assert _store(node).ca() is None and "/pki/ca" not in peer.requests  # odcisk z summary nie pasuje
    with pytest.raises(importlib.import_module("certs").CertStoreError, match="CA_FINGERPRINT"):
        _store(node).set_ca(pem(rogue.cert))  # ręczne wgranie też


# ---- endpointy /pki/* (ten sam format co portal) ------------------------------------------------------------


@pytest.fixture
def pki_client(node, monkeypatch):
    monkeypatch.setattr(importlib.import_module("neighbours"), "is_radio", lambda ip: True)  # TestClient = sąsiad
    app = FastAPI()
    app.include_router(importlib.import_module("routers.pki").router)
    return TestClient(app)


def test_pki_endpoints_serve_the_stored_originals(pki_client, node, ca):
    assert pki_client.get("/pki/summary").json() == {"ca": None, "crl": None, "certs": None}
    assert pki_client.get("/pki/crl").status_code == 404
    crl = ca.crl(number=6)
    _store(node).set_ca(pem(ca.cert))
    _store(node).update_crl(der(crl))

    summary = pki_client.get("/pki/summary").json()
    assert summary["crl"]["number"] == 6 and summary["crl"]["size"] == len(der(crl))
    assert summary["ca"]["size"] == len(der(ca.cert))

    resp = pki_client.get("/pki/crl")
    assert resp.content == der(crl)  # oryginał podpisany przez CA, bajt w bajt
    assert pki_client.get("/pki/crl", headers={"If-None-Match": resp.headers["etag"]}).status_code == 304
    assert pki_client.get("/pki/ca?format=pem").content == pem(ca.cert)
    served = [e for e in _transfers() if e["direction"] == "out"]
    assert {e["kind"] for e in served} == {"summary", "crl_full", "ca_cert"}
    assert any(e["status"] == "skipped" and e["saved_bytes"] == len(der(crl)) for e in served)

# Kompresja jest opcjonalna: starsze węzły nadal otrzymują oryginalny DER.
def test_compressed_endpoint_preserves_signed_der(pki_client, node, ca):
    import zlib
    crl = ca.crl(number=10, revoked=[SimpleNamespace(serial_number=i) for i in range(1, 100)])
    _store(node).set_ca(pem(ca.cert))
    _store(node).update_crl(der(crl))
    response = pki_client.get("/pki/crl?compression=zlib")
    assert zlib.decompress(response.content) == der(crl)
    assert response.headers["content-type"] == "application/zlib"
    assert response.headers["etag"] != pki_client.get("/pki/crl").headers["etag"]
    assert pki_client.get("/pki/crl?compression=zlib", headers={"If-None-Match": response.headers["etag"]}).status_code == 304


@pytest.mark.parametrize("invalid", [False, True, "oversized", "trailing", "forged"])
def test_compressed_sync_is_bounded_and_verified(node, monkeypatch, ca, invalid):
    import zlib
    _store(node).set_ca(pem(ca.cert))
    _store(node).update_crl(der(ca.crl(number=1)))
    crl = (TestCA() if invalid == "forged" else ca).crl(number=10, revoked=[SimpleNamespace(serial_number=i) for i in range(1, 100)])
    body = zlib.compress(der(crl))
    if invalid is True:
        body = body[:-3]
    elif invalid == "trailing":
        body += b"junk"
    wire = importlib.import_module("wire")
    info = {"number": 10, "size": len(der(crl)), "zlib_size": len(body)}
    if invalid == "oversized":
        body = zlib.compress(b"x" * 100000)
        info["zlib_size"] = len(body)
    peer = FakePeer(wire, {"/pki/crl?compression=zlib": body})
    monkeypatch.setattr(wire, "get", peer.get)
    if invalid:
        with pytest.raises(node.PkiSyncError):
            node.sync_crl(NEIGHBOUR, info)
        assert importlib.import_module("certs").crl_number(_store(node).crl()) == 1
    else:
        assert node.sync_crl(NEIGHBOUR, info) == "stored"
        assert _store(node).crl_der() == der(crl)
        record = _transfers()[-1]
        assert record["payload_bytes"] == len(body) and record["encoding"] == "DER+zlib"
