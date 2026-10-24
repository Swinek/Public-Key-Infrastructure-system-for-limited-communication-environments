"""Etap 3c: wniosek CSR i certyfikat przez sąsiadów (edge_client/node/enroll.py, relay.py, saf.py).

Trzy węzły w jednym procesie: każdy ma własny katalog danych, a „łącza radiowe” i portal są podstawione (wire).
Kontakt radiowy uruchamia po obu stronach te same wymiany co contact.py: store-and-forward, potem enroll."""

from __future__ import annotations

import hashlib
import importlib
import json
from contextlib import contextmanager

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tests.pki_factory import TestCA, der, key_pem, pem

PORTAL_URL = "http://portal:5001"


class FakePortal:
    """Portal + administrator CA: przyjmuje wnioski (jeden oczekujący na węzeł), test zatwierdza albo odrzuca."""

    def __init__(self, wire, certs, ca):
        self.wire, self.certs, self.ca = wire, certs, ca
        self.requests, self.issued, self.posts = {}, {}, []

    def post(self, sender, body, headers):
        csr = x509.load_der_x509_csr(body)
        node = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        fp = self.certs.key_fingerprint(csr.public_key())
        route = (headers or {}).get("X-PKI-Route")
        self.posts.append({"sender": sender, "fp": fp, "route": route})
        if fp not in self.requests:
            if any(r["node"] == node and r["status"] == "PENDING" for r in self.requests.values()):
                raise self.wire.WireError(f"{PORTAL_URL}/pki/csr: HTTP 409 b'pending'")
            self.requests[fp] = {"node": node, "csr": csr, "status": "PENDING", "reason": None,
                                 "serial_number": None, "relayed_via": route}
        return self._json({"status": self.requests[fp]["status"], "key_fingerprint": fp})

    def get(self, url):
        if "/pki/csr/" in url:
            fp = url.rsplit("/", 1)[1]
            if fp not in self.requests:
                raise self.wire.WireError(f"{url}: HTTP 404")
            r = self.requests[fp]
            return self._json({k: r[k] for k in ("status", "reason", "serial_number")})
        serial = url.rsplit("/", 1)[1]
        return self.wire.Fetched(200, der(self.issued[serial]), 600)

    def approve(self):
        r = next(r for r in self.requests.values() if r["status"] == "PENDING")
        cert = self.ca.issue_for(r["csr"].public_key(), r["node"])
        self.issued[str(cert.serial_number)] = cert
        r.update(status="APPROVED", serial_number=str(cert.serial_number))
        return cert

    def reject(self, reason="nieoczekiwany"):
        next(r for r in self.requests.values() if r["status"] == "PENDING").update(status="REJECTED", reason=reason)

    def _json(self, obj):
        body = json.dumps(obj).encode()
        return self.wire.Fetched(200, body, len(body) + 200)


class Net:
    """client_1 .. client_3 z osobnymi katalogami danych; `online` = węzły z łączem WAN."""

    def __init__(self, tmp_path, monkeypatch, ca):
        self.tmp = tmp_path
        self.config = importlib.import_module("config")
        self.certs = importlib.import_module("certs")
        self.wire = importlib.import_module("wire")
        contact = importlib.import_module("contact")
        monkeypatch.setattr(contact, "announce", lambda *a, **k: [])  # pobrania wywołuje sam test (radio)
        self.saf = importlib.import_module("saf")
        self.enroll = importlib.import_module("enroll")
        self.relay = importlib.import_module("relay")
        monkeypatch.setattr(self.config, "PORTAL_URL", PORTAL_URL)
        self.portal = FakePortal(self.wire, self.certs, ca)
        self.online = set()
        monkeypatch.setattr(self.wire, "get", self._get)
        monkeypatch.setattr(self.wire, "post_json", self._post_json)
        monkeypatch.setattr(self.wire, "post_bytes", self._post_bytes)
        for node in ("client_1", "client_2", "client_3"):
            with self.at(node):
                self.store().set_ca(pem(ca.cert))
                if node != "client_3":  # przewoźnicy mają już certyfikaty; client_3 jest nowy
                    cert, key = ca.issue(node)
                    self.store().set_certificate(pem(cert), key_pem(key))

    @contextmanager
    def at(self, node):
        c = self.config
        saved = (c.NODE_ID, c.DATA_DIR, c.CERTS_DIR, self.certs._store)
        c.NODE_ID, c.DATA_DIR, c.CERTS_DIR = node, self.tmp / node, self.tmp / node / "certs"
        self.certs._store = None
        try:
            yield
        finally:
            c.NODE_ID, c.DATA_DIR, c.CERTS_DIR, self.certs._store = saved

    def store(self):
        return self.certs.get_store()

    @staticmethod
    def peer(node):
        return {"kind": "neighbour", "id": node, "url": f"http://{node}:8000"}

    def _check_wan(self, url):
        if url.startswith(PORTAL_URL) and self.config.NODE_ID not in self.online:
            raise self.wire.WireError(f"{url}: ConnectionError (no internet)")

    def _get(self, url, limit):
        self._check_wan(url)
        if url.startswith(PORTAL_URL):
            return self.portal.get(url)
        node, msg_id = url.split("//")[1].split(":")[0], url.rsplit("/", 2)[-2]
        with self.at(node):
            data = self.saf.content(msg_id)
        if data is None or len(data) > limit:
            raise self.wire.WireError(f"{url}: HTTP 404")
        return self.wire.Fetched(200, data, len(data) + 200)

    def _post_json(self, url, payload, limit):
        node = url.split("//")[1].split(":")[0]
        with self.at(node):
            items, _ = self.saf.offer(payload["known"], payload["node_id"])
        body = json.dumps({"items": items}).encode()
        return self.wire.Fetched(200, body, len(body) + 200)

    def _post_bytes(self, url, body, content_type, limit, headers=None):
        self._check_wan(url)
        return self.portal.post(self.config.NODE_ID, body, headers)

    def radio(self, a, b, rounds=2):
        """Kontakt radiowy a <-> b (hello / announce): każda strona pobiera od drugiej, potem enroll."""
        for _ in range(rounds):
            for me, other in ((a, b), (b, a)):
                with self.at(me):
                    self.saf.exchange(self.peer(other))
                    self.enroll.exchange(self.peer(other))

    def wan(self, node):
        self.online.add(node)
        with self.at(node):
            return self.enroll.exchange({"kind": "wan", "id": "portal", "url": PORTAL_URL}), \
                self.relay.exchange({"kind": "wan", "id": "portal", "url": PORTAL_URL})

    def transfers(self, node, kind):
        with self.at(node):
            return [e for e in importlib.import_module("transfers").entries() if e["kind"] == kind]


@pytest.fixture(scope="module")
def ca():
    return TestCA()


@pytest.fixture
def net(edge_client_node_env, monkeypatch, ca):
    return Net(edge_client_node_env, monkeypatch, ca)


def _chain_request(net):
    """client_3 (bez internetu) -> client_2 -> client_1 (internet): wniosek trafia do portalu."""
    net.online.add("client_1")
    net.radio("client_3", "client_2")
    net.radio("client_2", "client_1")
    with net.at("client_3"):
        return net.store().pending()


def _queue_at(net, node, item, content=None):
    with net.at(node):
        net.saf.accept(item, content)


def test_csr_travels_3_2_1_to_portal_and_certificate_comes_back(net):
    pending = _chain_request(net)
    assert pending["status"] == "RELAYED"
    [request] = net.portal.requests.values()
    assert request["node"] == "client_3" and request["relayed_via"] == "client_3,client_2,client_1"
    with net.at("client_1"):
        assert net.saf.queue() == [] and [e["node_id"] for e in net.relay.relayed()] == ["client_3"]

    cert = net.portal.approve()
    assert net.wan("client_1")[1]["certificates"] == 1  # impuls cert_issued -> kontakt WAN przewoźnika
    with net.at("client_1"):
        assert net.relay.relayed() == []
    net.radio("client_1", "client_2")
    net.radio("client_2", "client_3")
    with net.at("client_3"):
        assert net.store().certificate().serial_number == cert.serial_number
        assert net.store().pending() is None
    # Rejestr transferów: każdy skok widzi bajty wniosku i certyfikatu.
    assert any(e["direction"] == "in" and e["status"] == "ok" for e in net.transfers("client_2", "csr"))
    assert any(e["direction"] == "out" and "carried for client_3" in e["note"] for e in net.transfers("client_1", "csr"))
    assert any(e["direction"] == "in" and e["status"] == "ok" for e in net.transfers("client_2", "cert"))
    assert any(e["status"] == "ok" and "installed" in e["note"] for e in net.transfers("client_3", "cert"))


def test_carrier_rejects_garbage_csr(net):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client_1")]))  # CN różny od nadawcy
           .sign(key, hashes.SHA256()))
    body = csr.public_bytes(serialization.Encoding.DER)
    with net.at("client_3"):
        item = net.saf.new_item("csr", "portal", content=body, msg_id=net.certs.key_fingerprint(key.public_key()))
    _queue_at(net, "client_3", item, body)
    net.radio("client_3", "client_2", rounds=1)
    with net.at("client_2"):
        assert item["msg_id"] not in {i["msg_id"] for i in net.saf.queue()}
    assert [e["status"] for e in net.transfers("client_2", "csr") if e["number"] == item["msg_id"]] == ["rejected"]


def test_carrier_rejects_certificate_of_foreign_ca(net):
    stranger, _ = TestCA(cn="Test Root CA").issue("client_3")  # ta sama nazwa CA, inny klucz
    body = der(stranger)
    with net.at("client_2"):
        item = net.saf.new_item("cert", "client_3", content=body, msg_id=hashlib.sha256(body).hexdigest())
    _queue_at(net, "client_2", item, body)
    net.radio("client_2", "client_1", rounds=1)
    with net.at("client_1"):
        assert net.saf.queue() == []
    assert [e["status"] for e in net.transfers("client_1", "cert")] == ["rejected"]


def test_certificate_for_another_key_is_not_installed(net, ca):
    _chain_request(net)
    forged, _ = ca.issue("client_3")  # podpis właściwego CA, ale klucz pośrednika
    body = der(forged)
    with net.at("client_2"):
        item = net.saf.new_item("cert", "client_3", content=body, msg_id=hashlib.sha256(body).hexdigest())
    _queue_at(net, "client_2", item, body)
    net.radio("client_2", "client_3", rounds=1)
    with net.at("client_3"):
        assert net.store().certificate() is None and net.store().pending()["status"] == "RELAYED"
    assert any(e["status"] == "rejected" and "not_ours" in e["note"] for e in net.transfers("client_3", "cert"))


def test_two_carriers_make_one_request_and_one_certificate(net):
    net.online.update({"client_1", "client_2"})
    net.radio("client_3", "client_2")
    net.radio("client_3", "client_1")
    assert len(net.portal.requests) == 1
    assert {p["sender"] for p in net.portal.posts} == {"client_1", "client_2"}  # oba przekazały ten sam klucz

    cert = net.portal.approve()
    net.wan("client_1")
    net.wan("client_2")
    net.radio("client_1", "client_3")
    net.radio("client_2", "client_3")
    with net.at("client_3"):
        assert net.store().certificate().serial_number == cert.serial_number
    statuses = [e["status"] for e in net.transfers("client_3", "cert")]
    assert statuses.count("ok") == 1  # druga kopia ma ten sam msg_id - już znana, nie pobierana


def test_rejection_from_a_carrier_is_only_a_hint(net):
    pending = _chain_request(net)
    with net.at("client_2"):
        hint = net.saf.new_item("csr_result", "client_3", result={
            "key_fingerprint": pending["key_fingerprint"], "status": "REJECTED", "reason": "fałszywe"},
            msg_id=hashlib.sha256(b"forged").hexdigest())
    _queue_at(net, "client_2", hint)
    net.radio("client_2", "client_3", rounds=1)
    with net.at("client_3"):
        assert net.store().pending()["status"] == "RELAYED"  # nadal otwarty
        assert "pośrednika client_2" in net.store().pending()["reason"]

    cert = net.portal.approve()
    assert net.wan("client_3")[0] == "installed"  # własny kontakt WAN rozstrzyga
    with net.at("client_3"):
        assert net.store().certificate().serial_number == cert.serial_number


def test_rejection_by_the_ca_comes_back_as_hint(net):
    _chain_request(net)
    net.portal.reject()
    assert net.wan("client_1")[1]["rejections"] == 1
    net.radio("client_1", "client_2")
    net.radio("client_2", "client_3")
    with net.at("client_3"):
        assert "nieoczekiwany" in net.store().pending()["reason"]
    assert net.wan("client_3")[0] == "rejected"


def test_node_with_internet_does_not_relay(net):
    assert net.wan("client_3")[0] == "submitted"
    net.radio("client_3", "client_2")
    with net.at("client_2"):
        assert net.saf.queue() == []
    assert net.portal.posts[0]["route"] is None
