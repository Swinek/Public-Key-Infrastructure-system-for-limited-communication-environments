"""Testy integracyjne etapu 1 – wymagają `docker compose up --build -d`.

Uruchamianie: docker compose --profile test run --rm tests pytest -m docker
(w kontenerze testów adresy usług biorą się z ADMIN_URL / PORTAL_URL).
"""

import os
import uuid

import httpx
import pytest
from cryptography import x509

pytestmark = pytest.mark.docker

ADMIN_URL = os.getenv("ADMIN_URL", "http://localhost:5000")
PORTAL_URL = os.getenv("PORTAL_URL", "http://localhost:5001")


def _summary():
    return httpx.get(f"{PORTAL_URL}/pki/summary", timeout=5.0).json()


def test_summary_matches_served_objects():
    summary = _summary()
    ca_der = httpx.get(f"{PORTAL_URL}/pki/ca", timeout=5.0).content
    crl_der = httpx.get(f"{PORTAL_URL}/pki/crl", timeout=5.0).content
    assert len(ca_der) == summary["ca"]["size"]
    assert len(crl_der) == summary["crl"]["size"]

    ca = x509.load_der_x509_certificate(ca_der)
    crl = x509.load_der_x509_crl(crl_der)
    assert crl.is_signature_valid(ca.public_key())
    assert crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == summary["crl"]["number"]


def test_crl_get_does_not_resign():
    first = httpx.get(f"{PORTAL_URL}/pki/crl", timeout=5.0)
    second = httpx.get(f"{PORTAL_URL}/pki/crl", timeout=5.0)
    assert first.content == second.content
    cached = httpx.get(f"{PORTAL_URL}/pki/crl", headers={"If-None-Match": first.headers["etag"]}, timeout=5.0)
    assert cached.status_code == 304 and cached.content == b""


def test_revocation_increments_crl_number_and_lists_serial():
    name = f"it_{uuid.uuid4().hex[:8]}"
    user = httpx.post(f"{ADMIN_URL}/api/users", json={"username": name, "email": f"{name}@test.local"},
                      timeout=10.0).json()
    cert = httpx.post(f"{ADMIN_URL}/api/certificates", json={"userId": user["id"]}, timeout=10.0).json()
    before = _summary()["crl"]["number"]

    revoked = httpx.post(f"{ADMIN_URL}/api/certificates/revoke", json={"certId": cert["id"]}, timeout=10.0).json()
    assert revoked["crl_number"] > before

    crl = x509.load_der_x509_crl(httpx.get(f"{PORTAL_URL}/pki/crl", timeout=5.0).content)
    assert crl.get_revoked_certificate_by_serial_number(int(cert["serial_number"])) is not None
    httpx.delete(f"{ADMIN_URL}/api/users/{user['id']}", timeout=5.0)


def test_deleting_user_revokes_and_keeps_serial_in_crl():
    """Usunięcie użytkownika nie może wyrzucić odwołanego numeru seryjnego z kolejnych CRL."""
    name = f"it_{uuid.uuid4().hex[:8]}"
    user = httpx.post(f"{ADMIN_URL}/api/users", json={"username": name, "email": f"{name}@test.local"},
                      timeout=10.0).json()
    cert = httpx.post(f"{ADMIN_URL}/api/certificates", json={"userId": user["id"]}, timeout=10.0).json()
    before = _summary()["crl"]["number"]

    httpx.delete(f"{ADMIN_URL}/api/users/{user['id']}", timeout=10.0).raise_for_status()
    assert _summary()["crl"]["number"] > before  # aktywny certyfikat odwołany -> nowa CRL

    httpx.post(f"{ADMIN_URL}/api/pki/crl", timeout=10.0).raise_for_status()  # kolejna lista
    crl = x509.load_der_x509_crl(httpx.get(f"{PORTAL_URL}/pki/crl", timeout=5.0).content)
    assert crl.get_revoked_certificate_by_serial_number(int(cert["serial_number"])) is not None
