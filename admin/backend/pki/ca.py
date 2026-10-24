import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


logger = logging.getLogger("pki_backend")

# Katalog danych PKI; w kontenerze montowany jako bind mount (zob. docker-compose.yml),
# dzięki czemu Root CA przetrwa przebudowę obrazu i nie trafia do warstw obrazu.
PKI_DIR = Path(os.getenv("PKI_DIR", Path(__file__).resolve().parent.parent / "pki_data"))
CA_KEY_PATH = PKI_DIR / "ca_private_key.pem"
CA_CERT_PATH = PKI_DIR / "ca_certificate.pem"

# Okres ważności CRL (nextUpdate - thisUpdate). Dłuższy niż okres ponownego podpisywania
# (CRL_REISSUE_HOURS w pki/store.py), żeby węzeł odcięty na kilka dni miał nadal ważną listę.
CRL_VALIDITY_HOURS = int(os.getenv("CRL_VALIDITY_HOURS", "168"))

# ECDSA P-256 + SHA-256 dla CA i certyfikatów (decyzja 2026-10-22: podpis ~72 B zamiast 512 B przy RSA-4096).
CURVE = ec.SECP256R1()
HASH = hashes.SHA256()

CA_KEY_USAGE = x509.KeyUsage(
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
    encipher_only=False, decipher_only=False,
)
LEAF_KEY_USAGE = x509.KeyUsage(
    digital_signature=True, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
    encipher_only=False, decipher_only=False,
)


def _ensure_pki_dir():
    """Tworzy katalog danych PKI (tylko dla właściciela)."""
    PKI_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(PKI_DIR, 0o700)
    except PermissionError:
        logger.warning("Nie można ustawić uprawnień 0700 dla %s", PKI_DIR)


def _write_private_key(path: Path, data: bytes):
    """Zapisuje klucz prywatny w pliku tworzonym od razu z uprawnieniami 0600."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(path, 0o600)


def random_serial_number() -> int:
    """64-bitowy losowy numer seryjny (63 bity, żeby w DER był dodatni i miał ≤ 8 bajtów)."""
    return secrets.randbits(63) or 1


def initialize_ca():
    """
    Creates the root Certification Authority if it does not exist yet.
    """

    _ensure_pki_dir()

    if CA_KEY_PATH.exists() and CA_CERT_PATH.exists():
        try:
            os.chmod(CA_KEY_PATH, 0o600)
        except PermissionError:
            logger.warning("Nie można ustawić uprawnień 0600 dla %s", CA_KEY_PATH)
        cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
        try:
            cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            cert.extensions.get_extension_for_class(x509.KeyUsage)
        except x509.ExtensionNotFound:
            logger.warning(
                "Root CA w %s nie ma rozszerzeń SKI/KeyUsage (stara infrastruktura) - "
                "przenieś pki_data do kopii i uruchom ponownie, aby wygenerować nowe CA.", PKI_DIR
            )
        logger.info("Używam istniejącego Root CA z %s", PKI_DIR)
        return

    private_key = ec.generate_private_key(CURVE)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Offline PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Offline PKI Root CA"),
    ])

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        .add_extension(CA_KEY_USAGE, critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        .sign(private_key, HASH)
    )

    _write_private_key(
        CA_KEY_PATH,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

    CA_CERT_PATH.write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )

    fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
    logger.warning(
        "UWAGA: wygenerowano NOWY Root CA w %s (SHA-256: %s). "
        "Wcześniej wydane certyfikaty, CRL i zapisane w węzłach fingerprinty "
        "starego CA przestają pasować - węzły trzeba ponownie zainicjalizować.",
        PKI_DIR, fingerprint
    )


def load_ca():
    """Zwraca (klucz prywatny CA, certyfikat CA), inicjalizując CA w razie potrzeby."""
    if not CA_KEY_PATH.exists() or not CA_CERT_PATH.exists():
        initialize_ca()
    ca_private_key = serialization.load_pem_private_key(CA_KEY_PATH.read_bytes(), password=None)
    ca_certificate = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
    return ca_private_key, ca_certificate


def load_ca_certificate() -> x509.Certificate:
    if not CA_CERT_PATH.exists():
        initialize_ca()
    return x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())


def _authority_key_identifier(ca_certificate: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    ski = ca_certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)


def _key_algorithm(public_key) -> str:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"ECDSA {public_key.curve.name}"
    return f"{type(public_key).__name__} {getattr(public_key, 'key_size', '')}".strip()


def _key_usage_names(ku: x509.KeyUsage) -> list[str]:
    attrs = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
             "key_agreement", "key_cert_sign", "crl_sign")
    return [attr for attr in attrs if getattr(ku, attr)]


def describe_certificate(cert: x509.Certificate) -> dict:
    """Metadane certyfikatu do wyświetlenia w panelu (bez tajnych danych)."""
    def ext(cls):
        try:
            return cert.extensions.get_extension_for_class(cls).value
        except x509.ExtensionNotFound:
            return None

    ski = ext(x509.SubjectKeyIdentifier)
    aki = ext(x509.AuthorityKeyIdentifier)
    ku = ext(x509.KeyUsage)
    bc = ext(x509.BasicConstraints)
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": str(cert.serial_number),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "key_algorithm": _key_algorithm(cert.public_key()),
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "subject_key_identifier": ski.digest.hex() if ski else None,
        "authority_key_identifier": aki.key_identifier.hex() if aki and aki.key_identifier else None,
        "key_usage": _key_usage_names(ku) if ku else [],
        "is_ca": bool(bc and bc.ca),
        "size_der": len(cert.public_bytes(serialization.Encoding.DER)),
        "size_pem": len(cert.public_bytes(serialization.Encoding.PEM)),
    }


def issue_user_certificate(username: str, email: str):
    """
    Generates a private key and an X.509 certificate
    signed by the root CA.
    """

    user_private_key = ec.generate_private_key(CURVE)
    result = _sign_leaf(user_private_key.public_key(), username, email)
    result["private_key_pem"] = user_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    return result


class CsrError(ValueError):
    """Wniosek CSR odrzucony przy sprawdzaniu (komunikat dla administratora)."""


def load_csr(data: bytes) -> x509.CertificateSigningRequest:
    """Wczytuje CSR (PEM lub DER) i sprawdza jego podpis (dowód posiadania klucza prywatnego)."""
    try:
        if data.lstrip().startswith(b"-----BEGIN"):
            csr = x509.load_pem_x509_csr(data)
        else:
            csr = x509.load_der_x509_csr(data)
    except ValueError as exc:
        raise CsrError(f"Niepoprawny wniosek CSR: {exc}") from exc
    if not csr.is_signature_valid:
        raise CsrError("Podpis wniosku CSR jest niepoprawny.")
    return csr


def csr_common_name(csr: x509.CertificateSigningRequest) -> str:
    names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not names:
        raise CsrError("Wniosek CSR nie ma CN.")
    return str(names[0].value)


def public_key_fingerprint(public_key) -> str:
    """SHA-256 z SubjectPublicKeyInfo (DER) – identyfikuje klucz węzła we wniosku i w certyfikacie."""
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def sign_csr(csr_data: bytes, username: str, email: str) -> dict:
    """Wystawia certyfikat na klucz z wniosku CSR. Klucz prywatny węzła nigdy nie trafia do CA.

    Z wniosku brany jest tylko klucz publiczny: podmiot, okres ważności i rozszerzenia ustala CA."""
    csr = load_csr(csr_data)
    if csr_common_name(csr) != username:
        raise CsrError(f"CN wniosku ({csr_common_name(csr)}) nie zgadza się z nazwą węzła ({username}).")
    public_key = csr.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or public_key.curve.name != CURVE.name:
        raise CsrError(f"Wniosek musi zawierać klucz EC {CURVE.name}.")
    return _sign_leaf(public_key, username, email)


def _sign_leaf(public_key, username: str, email: str) -> dict:
    """Certyfikat węzła podpisany przez Root CA dla podanego klucza publicznego."""
    ca_private_key, ca_certificate = load_ca()

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Offline PKI Client"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(public_key)
        .serial_number(random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(LEAF_KEY_USAGE, critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        )
        .add_extension(_authority_key_identifier(ca_certificate), critical=False)
        .sign(ca_private_key, HASH)
    )

    certificate_pem = certificate.public_bytes(
        serialization.Encoding.PEM
    )

    fingerprint = certificate.fingerprint(
        hashes.SHA256()
    ).hex()

    return {
        "serial_number": str(certificate.serial_number),
        "certificate_pem": certificate_pem.decode(),
        "fingerprint": fingerprint,
        "valid_from": certificate.not_valid_before_utc,
        "valid_to": certificate.not_valid_after_utc,
    }


def generate_crl(revoked_records: list[dict], crl_number: int,
                 now: datetime | None = None) -> x509.CertificateRevocationList:
    """
    Signs a Certificate Revocation List (CRL) with the Root CA.
    revoked_records: list of dicts with keys 'serial_number' (decimal str) and 'revoked_at' (datetime)
    crl_number: monotonic CRLNumber (RFC 5280 §5.2.3), assigned by the caller (pki/store.py)
    """
    ca_private_key, ca_certificate = load_ca()

    now = now or datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_certificate.subject)
        .last_update(now)
        .next_update(now + timedelta(hours=CRL_VALIDITY_HOURS))
        .add_extension(x509.CRLNumber(crl_number), critical=False)
        .add_extension(_authority_key_identifier(ca_certificate), critical=False)
    )

    for item in revoked_records:
        try:
            serial_int = int(str(item.get("serial_number", "")).strip())
        except ValueError:
            logger.warning("Pomijam niepoprawny numer seryjny w CRL: %r", item.get("serial_number"))
            continue

        revoked_at = item.get("revoked_at")
        if not revoked_at:
            revoked_at = now
        elif revoked_at.tzinfo is None:
            revoked_at = revoked_at.replace(tzinfo=timezone.utc)

        revoked_cert_builder = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial_int)
            .revocation_date(revoked_at)
        )
        builder = builder.add_revoked_certificate(revoked_cert_builder.build())

    return builder.sign(ca_private_key, HASH)
