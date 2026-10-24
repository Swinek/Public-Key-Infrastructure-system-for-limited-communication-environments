"""Etap 3b: CA podpisuje wniosek CSR węzła – certyfikat na klucz z wniosku, klucz prywatny nie trafia do CA."""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def _csr(key, cn="client_1") -> bytes:
    return (x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER))


def test_certificate_is_issued_for_the_key_in_the_request(ca_env):
    key = ec.generate_private_key(ec.SECP256R1())
    result = ca_env.ca.sign_csr(_csr(key), "client_1", "client_1@nodes.pki.local")
    cert = x509.load_pem_x509_certificate(result["certificate_pem"].encode())
    assert cert.public_key() == key.public_key()
    assert "private_key_pem" not in result
    ca_cert = x509.load_pem_x509_certificate(ca_env.ca.CA_CERT_PATH.read_bytes())
    cert.verify_directly_issued_by(ca_cert)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "client_1"
    assert ca_env.ca.public_key_fingerprint(key.public_key()) == ca_env.ca.public_key_fingerprint(cert.public_key())


def test_request_for_another_node_is_refused(ca_env):
    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ca_env.ca.CsrError, match="CN"):
        ca_env.ca.sign_csr(_csr(key, cn="client_2"), "client_1", "x@y")


def test_request_with_other_key_type_or_broken_signature_is_refused(ca_env):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(ca_env.ca.CsrError, match="EC"):
        ca_env.ca.sign_csr(_csr(rsa_key), "client_1", "x@y")
    broken = bytearray(_csr(ec.generate_private_key(ec.SECP256R1())))
    broken[-3] ^= 0xFF  # uszkodzony podpis
    with pytest.raises(ca_env.ca.CsrError):
        ca_env.ca.sign_csr(bytes(broken), "client_1", "x@y")
