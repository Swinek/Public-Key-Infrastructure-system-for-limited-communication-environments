from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


PKI_DIR = Path(__file__).resolve().parent.parent / "pki_data"
CA_KEY_PATH = PKI_DIR / "ca_private_key.pem"
CA_CERT_PATH = PKI_DIR / "ca_certificate.pem"
CRL_PEM_PATH = PKI_DIR / "crl.pem"
CRL_DER_PATH = PKI_DIR / "crl.der"


def initialize_ca():
    """
    Creates the root Certification Authority if it does not exist yet.
    """

    PKI_DIR.mkdir(exist_ok=True)

    if CA_KEY_PATH.exists() and CA_CERT_PATH.exists():
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

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
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        .sign(private_key, hashes.SHA256())
    )

    CA_KEY_PATH.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

    CA_CERT_PATH.write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )

def issue_user_certificate(username: str, email: str):
    """
    Generates a private key and an X.509 certificate
    signed by the root CA.
    """

    if not CA_KEY_PATH.exists() or not CA_CERT_PATH.exists():
        initialize_ca()

    ca_private_key = serialization.load_pem_private_key(
        CA_KEY_PATH.read_bytes(),
        password=None
    )

    ca_certificate = x509.load_pem_x509_certificate(
        CA_CERT_PATH.read_bytes()
    )

    # User private key
    user_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

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
        .public_key(user_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .sign(ca_private_key, hashes.SHA256())
    )

    certificate_pem = certificate.public_bytes(
        serialization.Encoding.PEM
    )

    private_key_pem = user_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    fingerprint = certificate.fingerprint(
        hashes.SHA256()
    ).hex()

    return {
        "serial_number": str(certificate.serial_number),
        "certificate_pem": certificate_pem.decode(),
        "private_key_pem": private_key_pem.decode(),
        "fingerprint": fingerprint,
        "valid_from": certificate.not_valid_before_utc,
        "valid_to": certificate.not_valid_after_utc,
    }


def generate_crl(revoked_records: list[dict]) -> bytes:
    """
    Generates and saves a Certificate Revocation List (CRL) signed by the Root CA.
    revoked_records: list of dicts with keys 'serial_number' (str) and 'revoked_at' (datetime)
    """
    if not CA_KEY_PATH.exists() or not CA_CERT_PATH.exists():
        initialize_ca()

    ca_private_key = serialization.load_pem_private_key(
        CA_KEY_PATH.read_bytes(),
        password=None
    )
    ca_certificate = x509.load_pem_x509_certificate(
        CA_CERT_PATH.read_bytes()
    )

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_certificate.subject)
        .last_update(now)
        .next_update(now + timedelta(days=7))
    )

    for item in revoked_records:
        serial_raw = str(item.get("serial_number", "")).strip()
        if not serial_raw:
            continue
        try:
            serial_int = int(serial_raw)
        except ValueError:
            if serial_raw.startswith("SN-"):
                try:
                    serial_int = int(serial_raw.replace("SN-", ""))
                except ValueError:
                    continue
            else:
                try:
                    serial_int = int(serial_raw, 16)
                except ValueError:
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

    crl = builder.sign(ca_private_key, hashes.SHA256())
    crl_pem = crl.public_bytes(serialization.Encoding.PEM)
    crl_der = crl.public_bytes(serialization.Encoding.DER)

    PKI_DIR.mkdir(exist_ok=True)
    CRL_PEM_PATH.write_bytes(crl_pem)
    CRL_DER_PATH.write_bytes(crl_der)

    return crl_pem