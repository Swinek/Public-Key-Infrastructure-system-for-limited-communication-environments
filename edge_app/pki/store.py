"""Local PKI store of an edge node: Root CA certificate (pinned), own certificate and key, last CRL.

Files in the store directory (DER - fewer bytes, same format as the portal sends):
    ca.der        Root CA certificate
    ca.pin        SHA-256 fingerprint of the CA pinned at the first install (when CA_FINGERPRINT is not set)
    node.der      certificate of this node
    node_key.pem  private key of this node (mode 0600)
    crl.der       last accepted CRL

Nothing is written before it is verified against the pinned CA, and every file is written atomically,
so data received from intermediaries (portal, neighbours) never replaces a good copy with a broken one.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization

from utils import atomic_write_bytes

CA_FILE = "ca.der"
PIN_FILE = "ca.pin"
CERT_FILE = "node.der"
KEY_FILE = "node_key.pem"
CRL_FILE = "crl.der"


class PkiError(ValueError):
    """Rejected PKI object (message for the user, in Polish)."""


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def normalize_fingerprint(value: str) -> str:
    return value.replace(":", "").strip().lower()


def load_certificate(data: bytes) -> x509.Certificate:
    """Certificate in PEM or DER."""
    try:
        if data.lstrip().startswith(b"-----BEGIN"):
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise PkiError(f"Niepoprawny certyfikat X.509: {exc}") from exc


def load_crl(data: bytes) -> x509.CertificateRevocationList:
    """CRL in PEM or DER."""
    try:
        if data.lstrip().startswith(b"-----BEGIN"):
            return x509.load_pem_x509_crl(data)
        return x509.load_der_x509_crl(data)
    except ValueError as exc:
        raise PkiError(f"Niepoprawna lista CRL: {exc}") from exc


def crl_number(crl: x509.CertificateRevocationList) -> Optional[int]:
    try:
        return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        return None


def is_delta_crl(crl: x509.CertificateRevocationList) -> bool:
    try:
        crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
        return True
    except x509.ExtensionNotFound:
        return False


def _key_identifier(cert: x509.Certificate) -> Optional[bytes]:
    try:
        return cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except x509.ExtensionNotFound:
        return None


def _authority_key_identifier(obj) -> Optional[bytes]:
    try:
        return obj.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
    except x509.ExtensionNotFound:
        return None


def check_ca_certificate(ca: x509.Certificate) -> None:
    """Self-signed CA certificate allowed to sign certificates and CRLs (RFC 5280 §4.2.1.3, §4.2.1.9)."""
    try:
        if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise PkiError("Certyfikat nie jest certyfikatem CA (BasicConstraints: CA=false).")
    except x509.ExtensionNotFound:
        raise PkiError("Certyfikat CA nie ma rozszerzenia BasicConstraints.") from None
    try:
        ku = ca.extensions.get_extension_for_class(x509.KeyUsage).value
        if not (ku.key_cert_sign and ku.crl_sign):
            raise PkiError("Certyfikat CA nie ma KeyUsage keyCertSign i cRLSign.")
    except x509.ExtensionNotFound:
        raise PkiError("Certyfikat CA nie ma rozszerzenia KeyUsage.") from None
    try:
        ca.verify_directly_issued_by(ca)
    except (ValueError, TypeError, InvalidSignature):
        raise PkiError("Certyfikat CA nie jest poprawnie samopodpisany.") from None


def check_issued_by(cert: x509.Certificate, ca: x509.Certificate) -> None:
    """Signature, issuer name and AKI/SKI of a certificate issued directly by the CA."""
    try:
        cert.verify_directly_issued_by(ca)
    except (ValueError, TypeError, InvalidSignature):
        raise PkiError("Certyfikat nie został wystawiony przez zaufane Root CA (wystawca lub podpis).") from None
    aki, ski = _authority_key_identifier(cert), _key_identifier(ca)
    if aki is not None and ski is not None and aki != ski:
        raise PkiError("Identyfikator klucza wystawcy (AKI) certyfikatu nie pasuje do Root CA.")


def check_crl_signed_by(crl: x509.CertificateRevocationList, ca: x509.Certificate) -> None:
    """Issuer, AKI and CA signature of a CRL."""
    if crl.issuer != ca.subject:
        raise PkiError("Wystawca CRL nie jest zaufanym Root CA.")
    aki, ski = _authority_key_identifier(crl), _key_identifier(ca)
    if aki is not None and ski is not None and aki != ski:
        raise PkiError("Identyfikator klucza wystawcy (AKI) CRL nie pasuje do Root CA.")
    if not crl.is_signature_valid(ca.public_key()):
        raise PkiError("Podpis CRL nieprawidłowy.")


class PkiStore:
    def __init__(self, root: Path, pinned_fingerprint: str = ""):
        self.root = Path(root)
        self._env_pin = normalize_fingerprint(pinned_fingerprint)
        self._lock = threading.Lock()

    # ---- reading ---------------------------------------------------------------------------

    def _read(self, name: str) -> Optional[bytes]:
        try:
            return (self.root / name).read_bytes()
        except FileNotFoundError:
            return None

    def ca(self) -> Optional[x509.Certificate]:
        data = self._read(CA_FILE)
        return None if data is None else x509.load_der_x509_certificate(data)

    def node_certificate(self) -> Optional[x509.Certificate]:
        data = self._read(CERT_FILE)
        return None if data is None else x509.load_der_x509_certificate(data)

    def private_key(self):
        data = self._read(KEY_FILE)
        return None if data is None else serialization.load_pem_private_key(data, password=None)

    def crl(self) -> Optional[x509.CertificateRevocationList]:
        data = self._read(CRL_FILE)
        return None if data is None else x509.load_der_x509_crl(data)

    def pinned_fingerprint(self) -> str:
        """Fingerprint from the configuration, otherwise the one pinned at the first install."""
        if self._env_pin:
            return self._env_pin
        data = self._read(PIN_FILE)
        return "" if data is None else normalize_fingerprint(data.decode("ascii"))

    # ---- writing (verify first, then atomic write) -----------------------------------------

    def install_ca(self, data: bytes) -> x509.Certificate:
        """Installs the Root CA. It must match the pinned fingerprint; without a pin the first CA gets pinned."""
        ca = load_certificate(data)
        check_ca_certificate(ca)
        fp = fingerprint(ca)
        with self._lock:
            pin = self.pinned_fingerprint()
            if pin and fp != pin:
                raise PkiError(f"Fingerprint certyfikatu CA ({fp}) nie zgadza się z przypiętym ({pin}).")
            if not pin:
                atomic_write_bytes(self.root / PIN_FILE, fp.encode("ascii") + b"\n")
            atomic_write_bytes(self.root / CA_FILE, ca.public_bytes(serialization.Encoding.DER))
        return ca

    def install_node(self, cert_data: bytes, key_data: bytes) -> x509.Certificate:
        """Installs the node certificate and its private key (the CA must be installed first)."""
        ca = self.ca()
        if ca is None:
            raise PkiError("Najpierw trzeba zainstalować certyfikat Root CA.")
        cert = load_certificate(cert_data)
        check_issued_by(cert, ca)
        try:
            key = serialization.load_pem_private_key(key_data, password=None)
        except (ValueError, TypeError) as exc:
            raise PkiError("Niepoprawny klucz prywatny (oczekiwany PEM bez hasła).") from exc
        if key.public_key() != cert.public_key():
            raise PkiError("Klucz prywatny nie pasuje do certyfikatu.")
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        with self._lock:
            # Key first: a certificate on disk always has its key.
            atomic_write_bytes(self.root / KEY_FILE, key_pem, mode=0o600)
            atomic_write_bytes(self.root / CERT_FILE, cert.public_bytes(serialization.Encoding.DER))
        return cert

    def install(self, ca_data: bytes, cert_data: bytes, key_data: bytes) -> None:
        self.install_ca(ca_data)
        self.install_node(cert_data, key_data)

    def update_crl(self, data: bytes) -> bool:
        """Stores a CRL if it is signed by the CA and newer (higher CRLNumber) than the stored one.

        Returns False when the stored CRL is the same or newer (nothing to do), raises PkiError when
        the CRL is not trustworthy. Delta-CRLs are Stage 3 and are rejected here.
        """
        ca = self.ca()
        if ca is None:
            raise PkiError("Brak certyfikatu Root CA – nie można sprawdzić CRL.")
        crl = load_crl(data)
        check_crl_signed_by(crl, ca)
        if is_delta_crl(crl):
            raise PkiError("Delta-CRL nie jest jeszcze obsługiwana – potrzebna pełna lista.")
        number = crl_number(crl)
        if number is None:
            raise PkiError("CRL nie ma numeru (CRLNumber) – nie można ocenić, czy jest nowsza.")
        if crl.next_update_utc is None:
            raise PkiError("CRL nie ma pola nextUpdate.")
        with self._lock:
            current = self.crl()
            if current is not None and number <= (crl_number(current) or -1):
                return False
            atomic_write_bytes(self.root / CRL_FILE, crl.public_bytes(serialization.Encoding.DER))
        return True

    # ---- summary ---------------------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        """State of the store for the node panel/API (no private key material)."""
        ca, cert, crl = self.ca(), self.node_certificate(), self.crl()
        return {
            "ca": None if ca is None else {
                "subject": ca.subject.rfc4514_string(),
                "fingerprint": fingerprint(ca),
                "pinned": self.pinned_fingerprint(),
                "not_after": ca.not_valid_after_utc.isoformat(),
            },
            "node": None if cert is None else {
                "subject": cert.subject.rfc4514_string(),
                "serial_number": str(cert.serial_number),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "has_private_key": (self.root / KEY_FILE).exists(),
            },
            "crl": None if crl is None else {
                "number": crl_number(crl),
                "this_update": crl.last_update_utc.isoformat(),
                "next_update": crl.next_update_utc.isoformat() if crl.next_update_utc else None,
                "revoked_count": len(crl),
                "size": len(crl.public_bytes(serialization.Encoding.DER)),
            },
        }
