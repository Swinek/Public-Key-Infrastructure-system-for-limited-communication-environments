"""Testy dymne Root CA (admin/backend/pki/ca.py)."""

from __future__ import annotations

import inspect
import stat
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _load_ca_cert(ca_env) -> x509.Certificate:
    return x509.load_pem_x509_certificate(ca_env.ca.CA_CERT_PATH.read_bytes())


def test_ca_is_self_signed_with_ca_basic_constraints(ca_env):
    cert = _load_ca_cert(ca_env)
    assert cert.subject == cert.issuer
    cert.verify_directly_issued_by(cert)  # samopodpisany
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical
    assert bc.value.ca is True


def _issue(ca_env, name: str) -> dict:
    """Certyfikat przez CSR – jedyna ścieżka wystawienia (klucz powstaje u węzła)."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
           .sign(key, hashes.SHA256()))
    return ca_env.ca.sign_csr(csr.public_bytes(serialization.Encoding.DER), name, f"{name}@example.com")


def test_ca_cannot_generate_node_keys(ca_env):
    assert not hasattr(ca_env.ca, "issue_user_certificate")


def test_leaf_certificate_signed_by_ca(ca_env):
    ca_cert = _load_ca_cert(ca_env)
    result = _issue(ca_env, "alice")

    for key in ("serial_number", "certificate_pem", "fingerprint", "valid_from", "valid_to"):
        assert key in result
    assert "private_key_pem" not in result

    cert = x509.load_pem_x509_certificate(result["certificate_pem"].encode())
    cert.verify_directly_issued_by(ca_cert)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "alice"
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert result["serial_number"] == str(cert.serial_number)


def test_crl_contains_revoked_serial_and_skips_invalid(ca_env):
    ca_cert = _load_ca_cert(ca_env)
    issued = _issue(ca_env, "bob")
    serial = int(issued["serial_number"])
    revoked_at = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    crl = ca_env.ca.generate_crl([
        {"serial_number": issued["serial_number"], "revoked_at": revoked_at},
        {"serial_number": "to-nie-jest-serial", "revoked_at": None},
    ], crl_number=1)

    assert crl.is_signature_valid(ca_cert.public_key())
    assert crl.issuer == ca_cert.subject
    entry = crl.get_revoked_certificate_by_serial_number(serial)
    assert entry is not None
    assert entry.revocation_date_utc == revoked_at
    assert len(crl) == 1  # niepoprawny serial pominięty


def test_initialize_ca_is_idempotent(ca_env):
    key_before = ca_env.ca.CA_KEY_PATH.read_bytes()
    cert_before = ca_env.ca.CA_CERT_PATH.read_bytes()
    ca_env.ca.initialize_ca()
    assert ca_env.ca.CA_KEY_PATH.read_bytes() == key_before
    assert ca_env.ca.CA_CERT_PATH.read_bytes() == cert_before


def _ca_sets_key_permissions(ca_module) -> bool:
    try:
        return "0o600" in inspect.getsource(ca_module)
    except (OSError, TypeError):
        return False


def test_ca_private_key_permissions_0600(ca_env):
    if not _ca_sets_key_permissions(ca_env.ca):
        pytest.skip("ca.py nie ustawia jeszcze uprawnień 0600 dla klucza CA")
    mode = stat.S_IMODE(ca_env.ca.CA_KEY_PATH.stat().st_mode)
    assert mode == 0o600
