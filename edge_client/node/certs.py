"""Certificate store of the edge client: exactly one certificate (with its key) per node.

The key is generated here and never leaves the node (except to this node's edge app): enroll.py sends only a CSR,
the CA returns a certificate, and installing it replaces the previous one. The Root CA and the latest CRL are kept
next to it, because the edge app needs both to check certificates offline.

Layout of DATA_DIR/certs/ (PEM for certificates and keys, DER for the CRL):
    ca.pem      Root CA certificate (the first one uploaded; another CA is rejected)
    crl.der     newest CRL signed by that CA (higher CRLNumber replaces it)
    cert.pem    certificate of this node
    key.pem     its private key (mode 0600)
    meta.json   installation time of the certificate
    pending_key.pem, pending.csr, pending.json   new key + request waiting for the CA (enroll.py)
    peers/<CN>.pem   certificates of other nodes (public, from radio neighbours - pki_sync.py), so that this
                     node's edge app can encrypt for a node that is out of range

The edge client never signs anything. On upload it checks that the key matches the certificate and that the
certificate and the CRL come from the stored CA; at any time the certificate (or any other one) can be checked
offline - chain to the Root CA, validity period, status in the stored CRL - with the same verifier as the edge
app (pki/verifier.py). The edge app verifies everything again before using it.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import config
from pki.verifier import Verdict, verify
from utils import atomic_write_bytes

CA_FILE = "ca.pem"
CRL_FILE = "crl.der"
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"
META_FILE = "meta.json"
PENDING_KEY_FILE = "pending_key.pem"
PENDING_CSR_FILE = "pending.csr"
PENDING_META_FILE = "pending.json"
PEERS_DIR = "peers"
NODE_CN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")  # CN of a node certificate, used as a file name


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


def _crl_number(crl: x509.CertificateRevocationList) -> Optional[int]:
    try:
        return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
    except x509.ExtensionNotFound:
        return None


def _fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def crl_number(crl: x509.CertificateRevocationList) -> Optional[int]:
    return _crl_number(crl)


def fingerprint(cert: x509.Certificate) -> str:
    return _fingerprint(cert)


def key_fingerprint(public_key) -> str:
    """SHA-256 of SubjectPublicKeyInfo (DER) - the same id of a key in the CSR, at the portal and in the CA."""
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def common_name(cert: x509.Certificate) -> str:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def signature_name(obj) -> str:
    """Signature algorithm of a certificate / CRL for the transfer register, e.g. 'ecdsa-with-SHA256'."""
    return getattr(obj.signature_algorithm_oid, "_name", obj.signature_algorithm_oid.dotted_string)


class CertStore:
    def __init__(self, root: Path, pin: str = ""):
        self.root = Path(root)
        self.pin = pin.replace(":", "").strip().lower()
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
                "installed_at": meta.get("installed_at") or meta.get("uploaded_at"),
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

    def ca_der(self) -> Optional[bytes]:
        ca = self.ca()
        return None if ca is None else ca.public_bytes(serialization.Encoding.DER)

    def crl_der(self) -> Optional[bytes]:
        return self._read(CRL_FILE)

    def summary(self) -> Dict[str, Any]:
        """The same metadata as the portal's /pki/summary: a peer compares numbers before downloading anything."""
        ca, crl = self.ca(), self.crl()
        return {
            "ca": None if ca is None else {
                "fingerprint": _fingerprint(ca),
                "subject": ca.subject.rfc4514_string(),
                "not_after": ca.not_valid_after_utc.isoformat(),
                "size": len(self.ca_der()),
            },
            "crl": None if crl is None else {
                "number": _crl_number(crl),
                "this_update": crl.last_update_utc.isoformat(),
                "next_update": crl.next_update_utc.isoformat() if crl.next_update_utc else None,
                "revoked_count": len(crl),
                "size": len(self.crl_der()),
            },
            "certs": None,  # the portal lists issued certificates; an edge client holds only its own
            "node_certs": self.node_certificates(),
        }

    # ---- certificates of other nodes (public data from neighbours) ----------------------------

    def peer_certificate(self, cn: str) -> Optional[x509.Certificate]:
        if not NODE_CN.match(cn):
            return None
        data = self._read(f"{PEERS_DIR}/{cn}.pem")
        return None if data is None else x509.load_pem_x509_certificate(data)

    def node_certificates(self) -> Dict[str, str]:
        """CN -> serial number of every node certificate held here (own one included), for /pki/summary."""
        known: Dict[str, str] = {}
        for path in sorted((self.root / PEERS_DIR).glob("*.pem")):
            cert = self.peer_certificate(path.stem)
            if cert is not None:
                known[path.stem] = str(cert.serial_number)
        own = self.certificate()
        if own is not None:
            known[common_name(own)] = str(own.serial_number)
        return known

    def node_certificate_der(self, cn: str) -> Optional[bytes]:
        own = self.certificate()
        cert = own if own is not None and common_name(own) == cn else self.peer_certificate(cn)
        return None if cert is None else cert.public_bytes(serialization.Encoding.DER)

    def add_peer_certificate(self, data: bytes, own_cn: str) -> bool:
        """Stores another node's certificate if it is valid now (Root CA, validity, stored CRL).

        False = the same or an older certificate of that node is already here. A neighbour is not trusted: only
        the signature of the Root CA and the stored CRL decide."""
        cert = load_certificate(data)
        cn = common_name(cert)
        if not NODE_CN.match(cn) or cn == own_cn:
            raise CertStoreError(f"Niepoprawny CN certyfikatu węzła: '{cn}'.")
        verdict = self.check(cert)
        if not verdict.ok:
            raise CertStoreError(f"Certyfikat {cn} odrzucony ({verdict.status.value}): {verdict.reason}")
        with self._lock:
            current = self.peer_certificate(cn)
            if current is not None and (current.serial_number == cert.serial_number
                                        or current.not_valid_before_utc >= cert.not_valid_before_utc):
                return False
            atomic_write_bytes(self.root / PEERS_DIR / f"{cn}.pem", _pem(cert))
        return True

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
        """Stores the Root CA (pki_sync.py). False when the same CA is already stored; another CA is rejected."""
        ca = load_certificate(data)
        try:
            if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise CertStoreError("Certyfikat nie jest certyfikatem CA (BasicConstraints: CA=false).")
        except x509.ExtensionNotFound:
            raise CertStoreError("Certyfikat CA nie ma rozszerzenia BasicConstraints.") from None
        if self.pin and _fingerprint(ca) != self.pin:
            raise CertStoreError("Certyfikat CA nie zgadza się z przypiętym odciskiem (CA_FINGERPRINT).")
        with self._lock:
            current = self.ca()
            if current is not None:
                if _fingerprint(current) == _fingerprint(ca):
                    return False
                raise CertStoreError("Edge client ma już inny certyfikat Root CA – nie można go podmienić.")
            atomic_write_bytes(self.root / CA_FILE, _pem(ca))
        return True

    def set_certificate(self, cert_data: bytes, key_data: bytes) -> bool:
        """Stores the certificate + key, replacing the previous pair (via install_issued). True if one was replaced."""
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
        meta = {"installed_at": datetime.now(timezone.utc).isoformat()}
        with self._lock:
            replaced = (self.root / CERT_FILE).exists()
            # The certificate is removed before its key is replaced, so a certificate on disk always has its key.
            (self.root / CERT_FILE).unlink(missing_ok=True)
            atomic_write_bytes(self.root / KEY_FILE, key_pem, mode=0o600)
            atomic_write_bytes(self.root / META_FILE, json.dumps(meta).encode())
            atomic_write_bytes(self.root / CERT_FILE, _pem(cert))
        return replaced

    # ---- own key and certificate request (enroll.py) ----------------------------------------

    def pending(self) -> Optional[Dict[str, Any]]:
        """The certificate request waiting for the CA: key fingerprint, status, CSR (DER). None if there is none."""
        meta = self._read(PENDING_META_FILE)
        csr = self._read(PENDING_CSR_FILE)
        if meta is None or csr is None or self._read(PENDING_KEY_FILE) is None:
            return None
        return {**json.loads(meta), "csr_der": csr}

    def new_request(self, node_id: str) -> Dict[str, Any]:
        """Generates a new key (EC P-256, never leaves this node) and a CSR with CN = node_id.

        The current certificate and its key stay in use until the CA issues a certificate for the new key."""
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)]))
               .sign(key, hashes.SHA256()))
        meta = {"node_id": node_id, "key_fingerprint": key_fingerprint(key.public_key()), "status": "NEW",
                "reason": None, "created_at": datetime.now(timezone.utc).isoformat()}
        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        with self._lock:
            atomic_write_bytes(self.root / PENDING_KEY_FILE, key_pem, mode=0o600)
            atomic_write_bytes(self.root / PENDING_CSR_FILE, csr.public_bytes(serialization.Encoding.DER))
            atomic_write_bytes(self.root / PENDING_META_FILE, json.dumps(meta).encode())
        return {**meta, "csr_der": csr.public_bytes(serialization.Encoding.DER)}

    def set_pending_status(self, status: str, reason: Optional[str] = None) -> None:
        with self._lock:
            meta = json.loads(self._read(PENDING_META_FILE) or b"{}")
            if not meta:
                return
            meta.update({"status": status, "reason": reason, "updated_at": datetime.now(timezone.utc).isoformat()})
            atomic_write_bytes(self.root / PENDING_META_FILE, json.dumps(meta).encode())

    def install_issued(self, cert_data: bytes) -> bool:
        """Installs the certificate issued for the pending key (replaces the current one). False if it is not ours.

        Accepted only if the stored Root CA signed it and it carries the public key of the pending request -
        a certificate for someone else's key is useless, whoever delivered it."""
        key = self._read(PENDING_KEY_FILE)
        if key is None:
            return False
        cert = load_certificate(cert_data)
        if key_fingerprint(cert.public_key()) != key_fingerprint(serialization.load_pem_private_key(key, None).public_key()):
            return False
        self.set_certificate(cert_data, key)  # checks the CA signature and the key again
        with self._lock:
            for name in (PENDING_META_FILE, PENDING_CSR_FILE, PENDING_KEY_FILE):
                (self.root / name).unlink(missing_ok=True)
        return True

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
        _store = CertStore(config.CERTS_DIR, config.CA_FINGERPRINT)
    return _store
