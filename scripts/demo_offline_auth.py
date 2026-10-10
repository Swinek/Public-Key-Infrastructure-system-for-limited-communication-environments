#!/usr/bin/env python3
"""
Demonstracja uwierzytelniania wzajemnego węzłów brzegowych w środowisku offline
(np. fale radiowe, łącze szeregowe, odizolowana maszyna wirtualna bez dostępu do Internetu).

Scenariusz:
1. Węzeł A (np. Operator Radiowy Alfa) chce nawiązać bezpieczną rozmowę z Węzłem B (Stacja Polowa Bravo).
2. Węzły NIE mają dostępu do serwera PKI ani Internetu.
3. Każdy węzeł posiada lokalnie wgrany certyfikat Root CA (zaufana kotwica) oraz listę unieważnień CRL.
4. Węzeł A przesyła swój certyfikat publiczny.
5. Węzeł B weryfikuje certyfikat A przeciwko lokalnemu Root CA i sprawdza CRL.
6. Węzeł B wysyła losowe wyzwanie (kryptograficzny nonce / challenge).
7. Węzeł A podpisuje wyzwanie swoim kluczem prywatnym.
8. Węzeł B weryfikuje podpis kluczem publicznym z certyfikatu A.
9. Po pomyślnej weryfikacji tożsamość jest potwierdzona i transmisja radiowa zostaje otwarta.

Użycie:
    python demo_offline_auth.py
    python demo_offline_auth.py --cert node_cert.pem --key node_private.key --ca ca_certificate.pem [--crl crl.pem]
"""

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:
    print("Błąd: Wymagana biblioteka 'cryptography'. Zainstaluj ją przez: pip install cryptography")
    sys.exit(1)


def verify_certificate_against_ca(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """Weryfikuje podpis matematyczny certyfikatu węzła kluczem publicznym Root CA."""
    ca_public_key = ca_cert.public_key()
    try:
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False


def is_cert_revoked(cert: x509.Certificate, crl: x509.CertificateRevocationList) -> tuple[bool, str]:
    """Sprawdza, czy numer seryjny certyfikatu znajduje się na liście unieważnień CRL."""
    revoked_entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if revoked_entry is not None:
        reason = "Unspecified"
        try:
            for ext in revoked_entry.extensions:
                if isinstance(ext.value, x509.CRLReason):
                    reason = ext.value.reason.name
        except Exception:
            pass
        return True, reason
    return False, ""


def simulate_handshake(cert_pem_bytes: bytes, key_pem_bytes: bytes, ca_pem_bytes: bytes, crl_pem_bytes: bytes = None):
    print("=" * 70)
    print(" SYMULACJA UWIERZYTELNIANIA WĘZŁA BRZEGOWEGO W ŚRODOWISKU OFFLINE (RADIO/VM)")
    print(" Medium transmisyjne: Fale radiowe / Sieć ad-hoc (Brak dostępu do Internetu)")
    print("=" * 70)

    # 1. Ładowanie komponentów kryptograficznych
    ca_cert = x509.load_pem_x509_certificate(ca_pem_bytes)
    node_cert = x509.load_pem_x509_certificate(cert_pem_bytes)
    node_key = serialization.load_pem_private_key(key_pem_bytes, password=None)

    node_cn = node_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    ca_cn = ca_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value

    print(f"\n[1] Nadawca (Węzeł A) zgłasza się na kanale radiowym.")
    print(f"    Tożsamość podmiotu (CN): {node_cn}")
    print(f"    Numer seryjny certyfikatu: {node_cert.serial_number}")
    print(f"    Wystawca (Issuer): {node_cert.issuer.rfc4514_string()}")

    # 2. Weryfikacja ważności czasowej
    now = datetime.now(timezone.utc)
    print(f"\n[2] Węzeł B sprawdza ważność czasową certyfikatu A...")
    if node_cert.not_valid_before_utc <= now <= node_cert.not_valid_after_utc:
        print(f"    [OK] Certyfikat jest w okresie ważności.")
        print(f"         Ważny od: {node_cert.not_valid_before_utc}")
        print(f"         Ważny do: {node_cert.not_valid_after_utc}")
    else:
        print("    [BŁĄD] Certyfikat wygasł lub nie wszedł jeszcze w okres ważności!")
        return False

    # 3. Weryfikacja podpisu CA (offline bez kontaktu z serwerem)
    print(f"\n[3] Węzeł B weryfikuje podpis certyfikatu A lokalnym kluczem Root CA ({ca_cn})...")
    if verify_certificate_against_ca(node_cert, ca_cert):
        print(f"    [OK] Podpis kryptograficzny X.509 prawidłowy. Certyfikat pochodzi z zaufanego CA.")
    else:
        print("    [BŁĄD] Nieprawidłowy podpis certyfikatu! Odrzucenie tożsamości.")
        return False

    # 4. Sprawdzenie listy unieważnień CRL (jeśli dostępna)
    if crl_pem_bytes:
        print(f"\n[4] Węzeł B weryfikuje status w lokalnej liście unieważnień (CRL)...")
        crl = x509.load_pem_x509_crl(crl_pem_bytes)
        revoked, reason = is_cert_revoked(node_cert, crl)
        if revoked:
            print(f"    [ALARM] Certyfikat węzła {node_cn} został UNIEWAŻNIONY!")
            print(f"            Powód odwołania: {reason}")
            print("    [ODMOWA] Połączenie radiowe przerwane. Klucz skompromitowany.")
            return False
        else:
            print(f"    [OK] Certyfikat węzła nie figuruje na liście unieważnień CRL.")
    else:
        print(f"\n[4] Brak lokalnego pliku CRL – pomijanie sprawdzania listy odwołań.")

    # 5. Wyzwanie kryptograficzne (Challenge-Response)
    print(f"\n[5] Węzeł B generuje losowe wyzwanie (Nonce 32 bajty) i przesyła radiowo do Węzła A...")
    challenge = os.urandom(32)
    print(f"    Wyzwanie (HEX): {challenge.hex()[:32]}...")

    # 6. Podpisanie wyzwania kluczem prywatnym przez Węzeł A
    print(f"\n[6] Węzeł A podpisuje wyzwanie swoim kluczem prywatnym (RSA SHA-256)...")
    signature = node_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    print(f"    Podpis wygenerowany ({len(signature)} bajtów). Przesyłanie odpowiedzi...")

    # 7. Weryfikacja podpisu przez Węzeł B kluczem publicznym z certyfikatu
    print(f"\n[7] Węzeł B weryfikuje podpis wyzwania kluczem publicznym z certyfikatu Węzła A...")
    node_public_key = node_cert.public_key()
    try:
        node_public_key.verify(
            signature,
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print("    [OK] Podpis wyzwania zweryfikowany pomyślnie!")
    except Exception as exc:
        print(f"    [BŁĄD] Weryfikacja podpisu nie powiodła się: {exc}")
        return False

    print("\n" + "=" * 70)
    print(" SUKCES: WĘZEŁ A ZOSTAŁ KRYPTOGRAFICZNIE UWIERZYTELNIONY W TRYBIE OFFLINE!")
    print(f" Rozmowa radiowa pomiędzy Węzłem B a '{node_cn}' została autoryzowana.")
    print("=" * 70)
    return True


def run_self_test():
    """Generuje przykładową parę węzłów i testuje cały proces."""
    print("[*] Brak podanych plików – uruchamianie testu demonstracyjnego na danych z backend/pki_data...")
    
    repo_root = Path(__file__).resolve().parent.parent
    ca_cert_path = repo_root / "backend" / "pki_data" / "ca_certificate.pem"
    ca_key_path = repo_root / "backend" / "pki_data" / "ca_private_key.pem"
    crl_path = repo_root / "backend" / "pki_data" / "crl.pem"

    if not ca_cert_path.exists() or not ca_key_path.exists():
        print(f"Błąd: Nie znaleziono {ca_cert_path}. Uruchom backend lub podaj pliki ręcznie.")
        return

    ca_cert_bytes = ca_cert_path.read_bytes()
    ca_key_bytes = ca_key_path.read_bytes()
    crl_bytes = crl_path.read_bytes() if crl_path.exists() else None

    # Generujemy tymczasowy węzeł testowy podpisany przez CA
    ca_key = serialization.load_pem_private_key(ca_key_bytes, password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_bytes)

    node_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    from datetime import timedelta
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "radio_node_alfa_1")]))
        .issuer_name(ca_cert.subject)
        .public_key(node_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )

    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    key_bytes = node_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    simulate_handshake(cert_bytes, key_bytes, ca_cert_bytes, crl_bytes)


def main():
    parser = argparse.ArgumentParser(description="Demonstracja uwierzytelniania węzła offline PKI")
    parser.add_argument("--cert", help="Ścieżka do certyfikatu węzła (PEM)")
    parser.add_argument("--key", help="Ścieżka do klucza prywatnego węzła (KEY/PEM)")
    parser.add_argument("--ca", help="Ścieżka do certyfikatu Root CA (ca_certificate.pem)")
    parser.add_argument("--crl", help="Ścieżka do listy odwołań CRL (crl.pem)")

    args = parser.parse_args()

    if args.cert and args.key and args.ca:
        cert_bytes = Path(args.cert).read_bytes()
        key_bytes = Path(args.key).read_bytes()
        ca_bytes = Path(args.ca).read_bytes()
        crl_bytes = Path(args.crl).read_bytes() if args.crl else None
        simulate_handshake(cert_bytes, key_bytes, ca_bytes, crl_bytes)
    else:
        run_self_test()


if __name__ == "__main__":
    main()
