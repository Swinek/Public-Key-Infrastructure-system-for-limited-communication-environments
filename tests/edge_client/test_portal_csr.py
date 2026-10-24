"""Portal przyjmuje wniosek CSR i niczego nie podpisuje (edge_client/backend/routers/csr.py: parse_csr)."""

from __future__ import annotations

import hashlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@pytest.fixture
def csr_module(component_importer):
    component_importer("edge_client")
    import routers.csr as module
    return module


def _csr(key, cn="client_1"):
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)] if cn else []))
    return builder.sign(key, hashes.SHA256())


def test_valid_request_gives_node_id_and_key_fingerprint(csr_module):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = _csr(key)
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    for data in (csr.public_bytes(serialization.Encoding.DER), csr.public_bytes(serialization.Encoding.PEM)):
        node_id, fp, der = csr_module.parse_csr(data)
        assert node_id == "client_1" and fp == hashlib.sha256(spki).hexdigest()
        assert der == csr.public_bytes(serialization.Encoding.DER)


@pytest.mark.parametrize("data", [b"", b"garbage", b"x" * 5000])
def test_garbage_is_refused(csr_module, data):
    with pytest.raises(csr_module.CsrRejected):
        csr_module.parse_csr(data)


def test_request_without_cn_is_refused(csr_module):
    der = _csr(ec.generate_private_key(ec.SECP256R1()), cn=None).public_bytes(serialization.Encoding.DER)
    with pytest.raises(csr_module.CsrRejected, match="CN"):
        csr_module.parse_csr(der)
