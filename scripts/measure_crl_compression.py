"""Porównanie rozmiarów CRL ECDSA P-256: DER i zlib (bez ruchu sieciowego).

Uruchomienie z katalogu projektu: python scripts/measure_crl_compression.py
Wynik CSV na stdout; klucze są tymczasowe, wyłącznie w pamięci.
"""
import csv
import secrets
import sys
import zlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def main():
    key = ec.generate_private_key(ec.SECP256R1())
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pomiar CRL")])
    now = datetime.now(timezone.utc)
    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(["revoked_count", "der_bytes", "zlib_bytes", "selected_bytes", "saved_bytes", "saved_percent"])
    serials = set()
    while len(serials) < 1000:
        serials.add(secrets.randbits(63) or 1)
    serials = sorted(serials)
    for count in (0, 1, 10, 100, 1000):
        builder = (x509.CertificateRevocationListBuilder().issuer_name(issuer)
                   .last_update(now).next_update(now + timedelta(days=7))
                   .add_extension(x509.CRLNumber(1), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False))
        for serial in serials[:count]:
            entry = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).build()
            builder = builder.add_revoked_certificate(entry)
        der = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
        packed = zlib.compress(der)
        selected = min(len(der), len(packed))
        saved = len(der) - selected
        writer.writerow([count, len(der), len(packed), selected, saved, round(100 * saved / len(der), 2)])


if __name__ == "__main__":
    main()
