"""Automatyczny certyfikat węzła (edge_client/node/enroll.py): klucz powstaje w węźle, wniosek CSR idzie przy
kontakcie WAN, certyfikat jest instalowany dopiero po zatwierdzeniu w CA. Portal jest podstawiony (wire)."""

from __future__ import annotations

import importlib
import json

import pytest
from cryptography import x509

from tests.pki_factory import NOW, TestCA, der, key_pem, pem

PORTAL = {"kind": "wan", "id": "portal", "url": "http://portal:5001"}
NEIGHBOUR = {"kind": "neighbour", "id": "client_2", "url": "http://192.168.12.20:8000"}


@pytest.fixture(scope="module")
def ca():
    return TestCA()


@pytest.fixture
def node(edge_client_node_env, monkeypatch, ca):
    monkeypatch.setenv("NODE_ID", "client_1")
    enroll = importlib.import_module("enroll")
    importlib.import_module("certs").get_store().set_ca(pem(ca.cert))
    return enroll


class FakePortal:
    """CA za portalem: przyjmuje wnioski, a test decyduje o nich jak administrator."""

    def __init__(self, wire, ca):
        self.wire, self.ca, self.requests, self.issued = wire, ca, {}, {}

    def post_bytes(self, url, body, content_type, limit):
        csr = x509.load_der_x509_csr(body)
        fp = importlib.import_module("certs").key_fingerprint(csr.public_key())
        self.requests.setdefault(fp, {"status": "PENDING", "csr": csr, "reason": None, "serial_number": None})
        return self._json({"status": self.requests[fp]["status"], "key_fingerprint": fp})

    def get(self, url, limit):
        if "/pki/csr/" in url:
            fp = url.rsplit("/", 1)[1]
            if fp not in self.requests:
                raise self.wire.WireError(f"{url}: HTTP 404")
            r = self.requests[fp]
            return self._json({k: r[k] for k in ("status", "reason", "serial_number")})
        serial = url.rsplit("/", 1)[1]
        return self.wire.Fetched(200, der(self.issued[serial]), 500)

    def approve(self, public_key=None):
        fp, r = next((fp, r) for fp, r in self.requests.items() if r["status"] == "PENDING")
        cert = self.ca.issue_for(public_key or r["csr"].public_key(), "client_1")
        self.issued[str(cert.serial_number)] = cert
        r.update(status="APPROVED", serial_number=str(cert.serial_number))
        return cert

    def reject(self):
        r = next(r for r in self.requests.values() if r["status"] == "PENDING")
        r.update(status="REJECTED", reason="nieoczekiwany")

    def _json(self, obj):
        body = json.dumps(obj).encode()
        return self.wire.Fetched(200, body, len(body) + 200)


@pytest.fixture
def portal(node, monkeypatch, ca):
    wire = importlib.import_module("wire")
    fake = FakePortal(wire, ca)
    monkeypatch.setattr(wire, "post_bytes", fake.post_bytes)
    monkeypatch.setattr(wire, "get", fake.get)
    return fake


def _store():
    return importlib.import_module("certs").get_store()


def test_node_without_certificate_files_a_request_and_installs_after_approval(node, portal):
    assert node.exchange(PORTAL) == "submitted"
    assert len(portal.requests) == 1 and _store().certificate() is None
    assert node.exchange(PORTAL) == "pending"  # administrator jeszcze nie zdecydował

    cert = portal.approve()
    assert node.exchange(PORTAL) == "installed"
    assert _store().certificate().serial_number == cert.serial_number
    assert _store().pending() is None
    assert node.exchange(PORTAL) is None  # ważny certyfikat – nic do zrobienia


def test_private_key_never_leaves_the_node(node, portal):
    node.exchange(PORTAL)
    sent = [r["csr"] for r in portal.requests.values()]
    assert all(isinstance(c, x509.CertificateSigningRequest) for c in sent)
    portal.approve()
    node.exchange(PORTAL)
    key = (_store().root / "key.pem").read_bytes()
    assert key not in json.dumps({k: str(v) for k, v in portal.requests.items()}).encode()


def test_rejected_request_is_not_sent_again(node, portal):
    node.exchange(PORTAL)
    portal.reject()
    assert node.exchange(PORTAL) == "rejected"
    assert node.exchange(PORTAL) == "rejected" and len(portal.requests) == 1
    assert _store().pending()["status"] == "REJECTED"


def test_certificate_for_another_key_is_not_installed(node, portal, ca):
    node.exchange(PORTAL)
    _, stranger_key = ca.issue("client_1")
    portal.approve(public_key=stranger_key.public_key())
    assert node.exchange(PORTAL) == "not ours"
    assert _store().certificate() is None and _store().pending() is not None


def test_revoked_certificate_leads_to_a_new_request_not_a_new_certificate(node, portal, ca):
    cert, key = ca.issue("client_1")
    _store().set_certificate(pem(cert), key_pem(key))
    _store().update_crl(der(ca.crl(revoked=[cert], number=3)))
    assert node.needs_certificate(_store(), NOW) == "certificate revoked"
    assert node.exchange(PORTAL) == "submitted"
    assert _store().certificate().serial_number == cert.serial_number  # stary zostaje do zatwierdzenia nowego


def test_radio_contact_relays_the_request_instead_of_contacting_the_portal(node, portal):
    saf = importlib.import_module("saf")
    assert node.exchange(NEIGHBOUR) == "relayed" and portal.requests == {}
    pending = _store().pending()
    assert pending["status"] == "RELAYED"
    [item] = saf.queue()
    assert item["type"] == "csr" and item["destination_id"] == "portal"
    assert item["msg_id"] == pending["key_fingerprint"]  # deterministyczny id: kopie u przewoźników to jeden element
    assert node.exchange(NEIGHBOUR) is None and len(saf.queue()) == 1  # drugi kontakt nie dubluje wniosku
    # Węzeł dostał internet: ten sam klucz idzie bezpośrednio (portal nie zna jeszcze wniosku).
    assert node.exchange(PORTAL) == "submitted" and list(portal.requests) == [pending["key_fingerprint"]]
