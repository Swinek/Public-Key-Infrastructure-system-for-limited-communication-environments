"""Etap 1: rozszerzenia X.509 (SKI/AKI/KeyUsage), CRLNumber i zgodność z `openssl verify`."""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _ca_cert(ca_env) -> x509.Certificate:
    return x509.load_pem_x509_certificate(ca_env.ca.CA_CERT_PATH.read_bytes())


def _ext(cert_or_crl, cls):
    return cert_or_crl.extensions.get_extension_for_class(cls)


def test_ca_uses_ecdsa_p256_with_ski_and_key_usage(ca_env):
    ca = _ca_cert(ca_env)
    assert isinstance(ca.public_key(), ec.EllipticCurvePublicKey)
    assert ca.public_key().curve.name == "secp256r1"

    ski = _ext(ca, x509.SubjectKeyIdentifier)
    assert ski.value == x509.SubjectKeyIdentifier.from_public_key(ca.public_key())

    ku = _ext(ca, x509.KeyUsage)
    assert ku.critical
    assert ku.value.key_cert_sign and ku.value.crl_sign
    assert not ku.value.digital_signature


def test_leaf_certificate_has_aki_matching_ca_ski(ca_env):
    ca = _ca_cert(ca_env)
    leaf = x509.load_pem_x509_certificate(
        ca_env.ca.issue_user_certificate("carol", "carol@example.com")["certificate_pem"].encode()
    )
    ca_ski = _ext(ca, x509.SubjectKeyIdentifier).value.digest
    assert _ext(leaf, x509.AuthorityKeyIdentifier).value.key_identifier == ca_ski
    assert _ext(leaf, x509.SubjectKeyIdentifier).value == \
        x509.SubjectKeyIdentifier.from_public_key(leaf.public_key())

    ku = _ext(leaf, x509.KeyUsage)
    assert ku.critical
    assert ku.value.digital_signature
    assert not ku.value.key_cert_sign and not ku.value.crl_sign


def test_serial_number_fits_in_8_bytes(ca_env):
    for _ in range(20):
        serial = ca_env.ca.random_serial_number()
        assert 0 < serial < 2 ** 63


def test_crl_has_number_and_aki(ca_env):
    ca = _ca_cert(ca_env)
    crl = ca_env.ca.generate_crl([], crl_number=42)
    assert _ext(crl, x509.CRLNumber).value.crl_number == 42
    assert _ext(crl, x509.AuthorityKeyIdentifier).value.key_identifier == \
        _ext(ca, x509.SubjectKeyIdentifier).value.digest
    hours = (crl.next_update_utc - crl.last_update_utc).total_seconds() / 3600
    assert hours == ca_env.ca.CRL_VALIDITY_HOURS


def test_describe_certificate_reports_extensions(ca_env):
    info = ca_env.ca.describe_certificate(_ca_cert(ca_env))
    assert info["is_ca"] is True
    assert info["key_algorithm"] == "ECDSA secp256r1"
    assert info["key_usage"] == ["key_cert_sign", "crl_sign"]
    assert info["subject_key_identifier"]
    assert info["size_der"] < info["size_pem"]


# --- porównanie z OpenSSL (tak samo zweryfikuje węzeł offline) -------------------------------

requires_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="brak openssl")


def _openssl_verify(tmp_path, ca_env, leaf_pem: str, crl: x509.CertificateRevocationList) -> bool:
    ca_file = tmp_path / "ca.pem"
    crl_file = tmp_path / "crl.pem"
    leaf_file = tmp_path / "leaf.pem"
    ca_file.write_bytes(ca_env.ca.CA_CERT_PATH.read_bytes())
    crl_file.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    leaf_file.write_text(leaf_pem)
    result = subprocess.run(
        ["openssl", "verify", "-x509_strict", "-crl_check", "-use_deltas",
         "-CAfile", str(ca_file), "-CRLfile", str(crl_file), str(leaf_file)],
        capture_output=True, text=True,
    )
    return result.returncode == 0


@requires_openssl
def test_openssl_accepts_valid_and_rejects_revoked(tmp_path, ca_env):
    valid = ca_env.ca.issue_user_certificate("dave", "dave@example.com")
    revoked = ca_env.ca.issue_user_certificate("eve", "eve@example.com")
    crl = ca_env.ca.generate_crl(
        [{"serial_number": revoked["serial_number"], "revoked_at": datetime.now(timezone.utc)}],
        crl_number=7,
    )
    assert _openssl_verify(tmp_path, ca_env, valid["certificate_pem"], crl)
    assert not _openssl_verify(tmp_path, ca_env, revoked["certificate_pem"], crl)
