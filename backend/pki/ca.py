from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


PKI_DIR = Path("pki_data")
CA_KEY_PATH = PKI_DIR / "ca_private_key.pem"
CA_CERT_PATH = PKI_DIR / "ca_certificate.pem"


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