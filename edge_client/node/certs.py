"""Certificate store of the edge client: exactly one certificate (with its key) per node.

Uploading a new certificate + key replaces the stored one. The Root CA and the latest CRL are kept next to it,
because the edge app needs both to check certificates offline.

Layout of DATA_DIR/certs/ (PEM for certificates and keys, DER for the CRL):
    ca.pem      Root CA certificate (the first one uploaded; another CA is rejected)
    crl.der     newest CRL signed by that CA (higher CRLNumber replaces it)
    cert.pem    certificate of this node
    key.pem     its private key (mode 0600)
    meta.json   upload time of the certificate

The edge client never signs anything. On upload it checks that the key matches the certificate and that the
certificate and the CRL come from the stored CA; at any time the certificate (or any other one) can be checked
offline - chain to the Root CA, validity period, status in the stored CRL - with the same verifier as the edge
app (pki/verifier.py). The edge app verifies everything again before using it.
"""
from __future__ import annotations

import json
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization

import config
from pki.verifier import Verdict, verify
from utils import atomic_write_bytes

CA_FILE = "ca.pem"
CRL_FILE = "crl.der"
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"
META_FILE = "meta.json"


class CertStoreError(ValueError):
    """Rejected upload (message for the user, in Polish)."""


def load_certificate(data: bytes) -> x509.Certificate:
    try:
        if data.lstrip().startswith(b"-----BEGIN"):
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise CertStoreError(f"Niepoprawny certyfikat X.509: {exc}") from exc


def _load_crl(data: bytes) -> x509.CertificateRevocationList:
    try:
        if data.lstrip().startswith(b"-----BEGIN"):
            return x509.load_pem_x509_crl(data)
        return x509.load_der_x509_crl(data)
    except ValueError as exc:
        raise CertStoreError(f"Niepoprawna lista CRL: {exc}") from exc


def classify(data: bytes) -> str:
    """Recognises an uploaded file by its content: 'key', 'crl', 'ca' (CA certificate) or 'cert'."""
    if b"PRIVATE KEY-----" in data:
        return "key"
    try:
        _load_crl(data)
        return "crl"
    except CertStoreError:
        pass
    cert = load_certificate(data)  # raises CertStoreError for anything else
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    return "ca" if is_ca else "cert"


def _crl_number(crl: x509.CertificateRevocationList) -> Optional[int]:
    try:
        return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        return None


def _fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


class CertStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self._lock = threading.Lock()
        self._migrate_versions()

    def _migrate_versions(self) -> None:
        """Earlier layout kept numbered versions (versions/<n>/, active): keep only the active one."""
        versions_dir = self.root / "versions"
        if not versions_dir.is_dir():
            return
        active = self._read("active")
        source = versions_dir / (active.decode().strip() if active else "")
        if active and (source / "cert.pem").exists() and not (self.root / CERT_FILE).exists():
            for name in (KEY_FILE, META_FILE, CERT_FILE):  # key first: a certificate on disk always has its key
                if (source / name).exists():
                    atomic_write_bytes(self.root / name, (source / name).read_bytes(),
                                       mode=0o600 if name == KEY_FILE else 0o644)
        shutil.rmtree(versions_dir)
        (self.root / "active").unlink(missing_ok=True)

    # ---- reading ---------------------------------------------------------------------------

    def _read(self, relative: str) -> Optional[bytes]:
        try:
            return (self.root / relative).read_bytes()
        except FileNotFoundError:
            return None

    def ca(self) -> Optional[x509.Certificate]:
        data = self._read(CA_FILE)
        return None if data is None else x509.load_pem_x509_certificate(data)

    def crl(self) -> Optional[x509.CertificateRevocationList]:
        data = self._read(CRL_FILE)
        return None if data is None else x509.load_der_x509_crl(data)

    def certificate(self) -> Optional[x509.Certificate]:
        data = self._read(CERT_FILE)
        return None if data is None else x509.load_pem_x509_certificate(data)

    def certificate_pem(self) -> Optional[bytes]:
        return self._read(CERT_FILE)

    def check(self, cert: x509.Certificate, now: Optional[datetime] = None) -> Verdict:
        """Offline check against the stored Root CA and CRL (no network)."""
        return verify(cert, self.ca(), self.crl(), now or datetime.now(timezone.utc))

    def status(self) -> Dict[str, Any]:
        """Certificate metadata with its current verdict, Root CA and CRL - never the private key."""
        ca, crl, cert = self.ca(), self.crl(), self.certificate()
        now = datetime.now(timezone.utc)
        meta = json.loads(self._read(META_FILE) or b"{}")
        return {
            "checked_at": now.isoformat(),
            "certificate": None if cert is None else {
                "subject": cert.subject.rfc4514_string(),
                "serial_number": str(cert.serial_number),
                "fingerprint": _fingerprint(cert),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "uploaded_at": meta.get("uploaded_at"),
                "verdict": self.check(cert, now).to_dict(),
            },
            "ca": None if ca is None else {
                "subject": ca.subject.rfc4514_string(),
                "fingerprint": _fingerprint(ca),
                "not_after": ca.not_valid_after_utc.isoformat(),
            },
            "crl": None if crl is None else {
                "number": _crl_number(crl),
                "this_update": crl.last_update_utc.isoformat(),
                "next_update": crl.next_update_utc.isoformat() if crl.next_update_utc else None,
                "revoked_count": len(crl),
            },
        }

    def bundle(self) -> Dict[str, Any]:
        """Everything the edge app needs to use the certificate.

        Contains the private key - served only to this node's edge app (see routers/certs.py).
        """
        ca, crl = self._read(CA_FILE), self._read(CRL_FILE)
        cert, key = self._read(CERT_FILE), self._read(KEY_FILE)
        return {
            "ca": None if ca is None else ca.decode(),
            "certificate": None if cert is None else cert.decode(),
            "private_key": None if key is None else key.decode(),
            "crl_pem": None if crl is None else x509.load_der_x509_crl(crl).public_bytes(serialization.Encoding.PEM).decode(),
        }

    # ---- writing ---------------------------------------------------------------------------

    def set_ca(self, data: bytes) -> bool:
        """Stores the Root CA. Returns False when the same CA is already stored; another CA is rejected."""
        ca = load_certificate(data)
        try:
            if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise CertStoreError("Certyfikat nie jest certyfikatem CA (BasicConstraints: CA=false).")
        except x509.ExtensionNotFound:
            raise CertStoreError("Certyfikat CA nie ma rozszerzenia BasicConstraints.") from None
        with self._lock:
            current = self.ca()
            if current is not None:
                if _fingerprint(current) == _fingerprint(ca):
                    return False
                raise CertStoreError("Edge client ma już inny certyfikat Root CA – nie można go podmienić.")
            atomic_write_bytes(self.root / CA_FILE, _pem(ca))
        return True

    def set_certificate(self, cert_data: bytes, key_data: bytes) -> bool:
        """Stores the certificate + key, replacing the previous pair. Returns True if one was replaced."""
        ca = self.ca()
        if ca is None:
            raise CertStoreError("Najpierw trzeba wgrać certyfikat Root CA.")
        cert = load_certificate(cert_data)
        try:
            cert.verify_directly_issued_by(ca)
        except (ValueError, TypeError, InvalidSignature):
            raise CertStoreError("Certyfikat nie został wystawiony przez zapisany Root CA.") from None
        try:
            key = serialization.load_pem_private_key(key_data, password=None)
        except (ValueError, TypeError) as exc:
            raise CertStoreError("Niepoprawny klucz prywatny (oczekiwany PEM bez hasła).") from exc
        if key.public_key() != cert.public_key():
            raise CertStoreError("Klucz prywatny nie pasuje do certyfikatu.")
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        meta = {"uploaded_at": datetime.now(timezone.utc).isoformat()}
        with self._lock:
            replaced = (self.root / CERT_FILE).exists()
            # The certificate is removed before its key is replaced, so a certificate on disk always has its key.
            (self.root / CERT_FILE).unlink(missing_ok=True)
            atomic_write_bytes(self.root / KEY_FILE, key_pem, mode=0o600)
            atomic_write_bytes(self.root / META_FILE, json.dumps(meta).encode())
            atomic_write_bytes(self.root / CERT_FILE, _pem(cert))
        return replaced

    def update_crl(self, data: bytes) -> bool:
        """Stores a CRL signed by the stored CA if its CRLNumber is higher. False = same or older (skipped)."""
        ca = self.ca()
        if ca is None:
            raise CertStoreError("Brak certyfikatu Root CA – nie można sprawdzić CRL.")
        crl = _load_crl(data)
        if crl.issuer != ca.subject or not crl.is_signature_valid(ca.public_key()):
            raise CertStoreError("CRL nie jest podpisana przez zapisany Root CA.")
        number = _crl_number(crl)
        if number is None:
            raise CertStoreError("CRL nie ma numeru (CRLNumber).")
        with self._lock:
            current = self.crl()
            if current is not None and number <= (_crl_number(current) or -1):
                return False
            atomic_write_bytes(self.root / CRL_FILE, crl.public_bytes(serialization.Encoding.DER))
        return True


_store: Optional[CertStore] = None


def get_store() -> CertStore:
    global _store
    if _store is None:
        _store = CertStore(config.CERTS_DIR)
    return _store
