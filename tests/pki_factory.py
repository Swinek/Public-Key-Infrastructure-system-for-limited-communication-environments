"""Testowe CA (EC P-256, jak admin/backend/pki/ca.py) do budowania certyfikatów i CRL w testach.

Niezależne od admin/backend – testy węzła nie dotykają prawdziwego klucza Root CA.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
DAY = timedelta(days=1)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def pem(obj) -> bytes:
    return obj.public_bytes(serialization.Encoding.PEM)


def der(obj) -> bytes:
    return obj.public_bytes(serialization.Encoding.DER)


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


class TestCA:
    __test__ = False  # nie jest klasą testów pytest

    def __init__(self, cn: str = "Test Root CA", not_before: datetime = NOW - 365 * DAY,
                 not_after: datetime = NOW + 3650 * DAY, ca_flag: bool = True, crl_sign: bool = True):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.ski = x509.SubjectKeyIdentifier.from_public_key(self.key.public_key())
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(_name(cn))
            .issuer_name(_name(cn))
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=ca_flag, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=crl_sign,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(self.ski, critical=False)
            .sign(self.key, hashes.SHA256())
        )

    def _aki(self) -> x509.AuthorityKeyIdentifier:
        return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(self.ski)

    def issue(self, cn: str = "client_1", not_before: datetime = NOW - DAY,
              not_after: datetime = NOW + 365 * DAY, serial: Optional[int] = None):
        """Zwraca (certyfikat, klucz prywatny) węzła."""
        key = ec.generate_private_key(ec.SECP256R1())
        return self.issue_for(key.public_key(), cn, not_before, not_after, serial), key

    def issue_for(self, public_key, cn: str = "client_1", not_before: datetime = NOW - DAY,
                  not_after: datetime = NOW + 365 * DAY, serial: Optional[int] = None) -> x509.Certificate:
        """Certyfikat na podany klucz publiczny (jak CA po zatwierdzeniu wniosku CSR)."""
        return (
            x509.CertificateBuilder()
            .subject_name(_name(cn))
            .issuer_name(self.cert.subject)
            .public_key(public_key)
            .serial_number(serial or x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=True, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(self._aki(), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .sign(self.key, hashes.SHA256())
        )

    def crl(self, revoked: Iterable[x509.Certificate] = (), number: Optional[int] = 1,
            this_update: datetime = NOW - DAY, next_update: datetime = NOW + DAY,
            delta_base: Optional[int] = None) -> x509.CertificateRevocationList:
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.cert.subject)
            .last_update(this_update)
            .next_update(next_update)
            .add_extension(self._aki(), critical=False)
        )
        if number is not None:
            builder = builder.add_extension(x509.CRLNumber(number), critical=False)
        if delta_base is not None:
            builder = builder.add_extension(x509.DeltaCRLIndicator(delta_base), critical=True)
        for cert in revoked:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(cert.serial_number)
                .revocation_date(this_update)
                .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False)
                .build()
            )
        return builder.sign(self.key, hashes.SHA256())
