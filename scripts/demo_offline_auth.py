#!/usr/bin/env python3
"""
Demonstracja uwierzytelniania węzłów brzegowych w środowisku offline
(np. fale radiowe, łącze szeregowe, odizolowana maszyna wirtualna bez dostępu do Internetu).

Skrypt wyłącznie WERYFIKUJE. Nie czyta klucza prywatnego Root CA i niczego nim nie
podpisuje – certyfikaty wystawia CA (admin/backend) przez API.

Przebieg (bez argumentów):
  FAZA ONLINE  – wydanie certyfikatu węzła „alfa” oraz odwołanego „mallory” przez API CA,
                 pobranie certyfikatu Root CA i CRL z portalu klienta (jak węzeł polowy).
  FAZA OFFLINE – od tej chwili bez sieci. Węzeł B (Stacja Polowa Bravo):
                 1. weryfikuje podpis CA na CRL i jej świeżość (nextUpdate),
                 2. weryfikuje certyfikat A: okres ważności, podpis Root CA, status w CRL,
                 3. odrzuca węzeł z odwołanym certyfikatem („mallory”) – oczekiwany wynik,
                 4. wysyła losowe wyzwanie (nonce), A podpisuje je kluczem prywatnym,
                    B weryfikuje podpis kluczem publicznym z certyfikatu A.

Użycie:
    python3 demo_offline_auth.py [--no-revoked] [--admin-url URL] [--portal-url URL]
    python3 demo_offline_auth.py --cert node_cert.pem --key node_private.key --ca ca_certificate.pem --crl crl.pem

Zmienne środowiskowe ADMIN_URL / PORTAL_URL ustawiają domyślne adresy
(http://localhost:5000 i http://localhost:5001).

Wymaga: cryptography >= 43 (Certificate.verify_directly_issued_by, *_utc).
"""

import argparse
import json
import os
import secrets
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
except ImportError:
    print("Błąd: Wymagana biblioteka 'cryptography' (>= 43). Zainstaluj ją przez: pip install cryptography")
    sys.exit(1)


class DemoError(Exception):
    """Błąd przerywający demonstrację (komunikat dla użytkownika)."""


# ==============================================================================
# HTTP (biblioteka standardowa)
# ==============================================================================

def http_request(url: str, payload: dict | None = None, timeout: float = 15.0) -> bytes:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise DemoError(f"{url} zwrócił HTTP {exc.code}: {body}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise DemoError(f"Brak połączenia z {url}: {exc}") from exc


def api_post(url: str, payload: dict) -> dict:
    return json.loads(http_request(url, payload))


def issue_node(admin_url: str, name: str, workdir: Path) -> tuple[dict, Path, Path]:
    """Rejestruje węzeł w CA i wystawia mu certyfikat.

    Klucz prywatny węzła generuje serwer CA – w demo to akceptujemy; docelowo węzeł
    generuje klucz sam i wysyła CSR (Etap 3 planu wdrożenia).
    """
    suffix = f"{int(time.time())}_{secrets.randbelow(10000)}"
    user = api_post(f"{admin_url}/api/users", {
        "username": f"radio_node_{name}_{suffix}",
        "email": f"{name}_{suffix}@radio.local",
        "role": "user",
    })
    cert = api_post(f"{admin_url}/api/certificates", {"userId": user["id"]})

    cert_path = workdir / f"{name}_cert.pem"
    key_path = workdir / f"{name}_private.key"
    cert_path.write_text(cert["certificate_pem"])
    key_path.write_text(cert["private_key"])
    key_path.chmod(0o600)
    print(f"    Wydano certyfikat węzła CN=radio_node_{name}_{suffix} (seryjny: {cert['serial_number']})")
    return cert, cert_path, key_path


# ==============================================================================
# Weryfikacja offline
# ==============================================================================

def verify_crl(crl: x509.CertificateRevocationList, ca_cert: x509.Certificate) -> None:
    """Sprawdza podpis CA na CRL, wystawcę i świeżość (nextUpdate). Rzuca DemoError."""
    if crl.issuer != ca_cert.subject:
        raise DemoError("Wystawca CRL nie zgadza się z Root CA – lista odrzucona.")
    if not crl.is_signature_valid(ca_cert.public_key()):
        raise DemoError("Podpis CRL nieprawidłowy – lista odrzucona.")
    now = datetime.now(timezone.utc)
    if crl.next_update_utc is None:
        raise DemoError("CRL nie zawiera pola nextUpdate – nie można ocenić jej świeżości.")
    if now > crl.next_update_utc:
        raise DemoError(
            f"CRL przeterminowana (nextUpdate {crl.next_update_utc} < teraz {now}). "
            "Węzeł musi pozyskać nowszą CRL (portal lub sąsiad P2P)."
        )
    if crl.last_update_utc > now:
        raise DemoError(f"CRL z przyszłości (thisUpdate {crl.last_update_utc}) – możliwa rozbieżność zegarów.")


def crl_number(crl: x509.CertificateRevocationList) -> str:
    try:
        return str(crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number)
    except x509.ExtensionNotFound:
        return "brak"


def is_cert_revoked(cert: x509.Certificate, crl: x509.CertificateRevocationList) -> tuple[bool, str]:
    """Sprawdza, czy numer seryjny certyfikatu znajduje się na liście unieważnień CRL."""
    revoked_entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if revoked_entry is None:
        return False, ""
    try:
        reason = revoked_entry.extensions.get_extension_for_class(x509.CRLReason).value.reason.name
    except x509.ExtensionNotFound:
        reason = "unspecified"
    return True, reason


def check_node_certificate(node_cert: x509.Certificate, ca_cert: x509.Certificate,
                           crl: x509.CertificateRevocationList, label: str) -> bool:
    """Weryfikuje certyfikat węzła offline: ważność, podpis Root CA, status w CRL."""
    ca_cn = ca_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    node_cn = node_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value

    now = datetime.now(timezone.utc)
    print(f"\n[{label}a] Sprawdzanie ważności czasowej certyfikatu {node_cn}...")
    if node_cert.not_valid_before_utc <= now <= node_cert.not_valid_after_utc:
        print("    [OK] Certyfikat jest w okresie ważności.")
        print(f"         Ważny od: {node_cert.not_valid_before_utc}")
        print(f"         Ważny do: {node_cert.not_valid_after_utc}")
    else:
        print("    [BŁĄD] Certyfikat wygasł lub nie wszedł jeszcze w okres ważności!")
        return False

    print(f"\n[{label}b] Weryfikacja podpisu certyfikatu lokalnym certyfikatem Root CA ({ca_cn})...")
    try:
        node_cert.verify_directly_issued_by(ca_cert)
        print("    [OK] Podpis X.509 prawidłowy. Certyfikat pochodzi z zaufanego CA.")
    except (ValueError, TypeError, InvalidSignature) as exc:
        print(f"    [BŁĄD] Certyfikat nie został wystawiony przez Root CA: {exc or 'nieprawidłowy podpis'}")
        return False

    print(f"\n[{label}c] Sprawdzanie statusu w lokalnej liście unieważnień (CRL)...")
    revoked, reason = is_cert_revoked(node_cert, crl)
    if revoked:
        print(f"    [ALARM] Certyfikat węzła {node_cn} został UNIEWAŻNIONY! Powód: {reason}")
        print("    [ODMOWA] Połączenie radiowe odrzucone.")
        return False
    print("    [OK] Certyfikat węzła nie figuruje na liście unieważnień CRL.")
    return True


def sign_challenge(key, challenge: bytes) -> bytes:
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(challenge, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                               salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(challenge, ec.ECDSA(hashes.SHA256()))
    raise DemoError(f"Nieobsługiwany typ klucza: {type(key).__name__}")


def verify_challenge(public_key, signature: bytes, challenge: bytes) -> None:
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, challenge, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                            salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
    else:
        raise DemoError(f"Nieobsługiwany typ klucza: {type(public_key).__name__}")


def simulate_handshake(cert_pem_bytes: bytes, key_pem_bytes: bytes, ca_pem_bytes: bytes,
                       crl_pem_bytes: bytes, revoked_cert_pem_bytes: bytes | None = None) -> bool:
    print("\n" + "=" * 70)
    print(" FAZA OFFLINE – od tej chwili bez sieci")
    print(" Medium transmisyjne: Fale radiowe / Sieć ad-hoc (Brak dostępu do Internetu)")
    print(" Weryfikacja wyłącznie na podstawie lokalnego Root CA i ostatniej CRL.")
    print("=" * 70)

    ca_cert = x509.load_pem_x509_certificate(ca_pem_bytes)
    node_cert = x509.load_pem_x509_certificate(cert_pem_bytes)
    node_key = serialization.load_pem_private_key(key_pem_bytes, password=None)
    crl = x509.load_pem_x509_crl(crl_pem_bytes)
    node_cn = node_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value

    # 0. Lokalna CRL – podpis CA i świeżość
    print("\n[0] Węzeł B weryfikuje lokalną listę odwołań (CRL)...")
    print(f"    thisUpdate: {crl.last_update_utc}   nextUpdate: {crl.next_update_utc}   numer: {crl_number(crl)}")
    try:
        verify_crl(crl, ca_cert)
    except DemoError as exc:
        print(f"    [BŁĄD] {exc}")
        return False
    print("    [OK] Podpis CRL zweryfikowany kluczem publicznym Root CA, lista jest aktualna.")

    # 1. Tożsamość nadawcy
    print("\n[1] Nadawca (Węzeł A) zgłasza się na kanale radiowym.")
    print(f"    Tożsamość podmiotu (CN): {node_cn}")
    print(f"    Numer seryjny certyfikatu: {node_cert.serial_number:x}")
    print(f"    Wystawca (Issuer): {node_cert.issuer.rfc4514_string()}")

    # 2. Weryfikacja certyfikatu A
    if not check_node_certificate(node_cert, ca_cert, crl, "2"):
        print("    [ODMOWA] Węzeł A nie został uwierzytelniony.")
        return False

    # 3. Próba węzła z odwołanym certyfikatem – oczekiwane odrzucenie
    if revoked_cert_pem_bytes:
        mallory_cert = x509.load_pem_x509_certificate(revoked_cert_pem_bytes)
        mallory_cn = mallory_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        print(f"\n[3] Na kanale zgłasza się węzeł z ODWOŁANYM certyfikatem: {mallory_cn}")
        if check_node_certificate(mallory_cert, ca_cert, crl, "3"):
            print("    [BŁĄD DEMO] Odwołany certyfikat został zaakceptowany!")
            return False
        if not is_cert_revoked(mallory_cert, crl)[0]:
            print("    [BŁĄD DEMO] Certyfikat odrzucony z innego powodu niż odwołanie.")
            return False
        print("    [OK – OCZEKIWANE ODRZUCENIE] Poprawny wynik demonstracji.")

    # 4–6. Wyzwanie kryptograficzne (Challenge-Response)
    print("\n[4] Węzeł B generuje losowe wyzwanie (Nonce 32 bajty) i przesyła radiowo do Węzła A...")
    challenge = os.urandom(32)
    print(f"    Wyzwanie (HEX): {challenge.hex()[:32]}...")

    print("\n[5] Węzeł A podpisuje wyzwanie swoim kluczem prywatnym (SHA-256)...")
    signature = sign_challenge(node_key, challenge)
    print(f"    Podpis wygenerowany ({len(signature)} bajtów). Przesyłanie odpowiedzi...")

    print("\n[6] Węzeł B weryfikuje podpis wyzwania kluczem publicznym z certyfikatu Węzła A...")
    try:
        verify_challenge(node_cert.public_key(), signature, challenge)
        print("    [OK] Podpis wyzwania zweryfikowany pomyślnie!")
    except InvalidSignature:
        print("    [BŁĄD] Weryfikacja podpisu nie powiodła się! Odmowa uwierzytelnienia.")
        return False

    print("\n" + "=" * 70)
    print(" SUKCES: WĘZEŁ A ZOSTAŁ KRYPTOGRAFICZNIE UWIERZYTELNIONY W TRYBIE OFFLINE!")
    print(f" Rozmowa radiowa pomiędzy Węzłem B a '{node_cn}' została autoryzowana.")
    if revoked_cert_pem_bytes:
        print(" Węzeł z odwołanym certyfikatem został poprawnie odrzucony na podstawie lokalnej CRL.")
    print("=" * 70)
    return True


# ==============================================================================
# FAZA ONLINE
# ==============================================================================

def run_online_phase(admin_url: str, portal_url: str, with_revoked: bool, workdir: Path) -> dict:
    """Wydaje certyfikaty przez API CA i pobiera CA + CRL z portalu. Zwraca bajty PEM."""
    print("=" * 70)
    print(" SYMULACJA UWIERZYTELNIANIA WĘZŁA BRZEGOWEGO W ŚRODOWISKU OFFLINE (RADIO/VM)")
    print("=" * 70)
    print("\n" + "-" * 70)
    print(" FAZA ONLINE – łącze do centrum PKI dostępne")
    print(f"   CA (admin):      {admin_url}")
    print(f"   Portal klienta:  {portal_url}")
    print("-" * 70)

    print("[*] Sprawdzanie dostępności CA...")
    try:
        http_request(f"{admin_url}/api/health", timeout=5)
    except DemoError as exc:
        raise DemoError(f"CA niedostępne ({exc}). Uruchom: docker compose up --build -d") from exc
    print("    [OK] CA odpowiada.")

    print("[*] Wydawanie certyfikatu węzła „alfa”...")
    _, alfa_cert, alfa_key = issue_node(admin_url, "alfa", workdir)

    mallory_cert = None
    if with_revoked:
        print("[*] Wydawanie certyfikatu węzła „mallory” i jego odwołanie (keyCompromise)...")
        mallory, mallory_cert, _ = issue_node(admin_url, "mallory", workdir)
        api_post(f"{admin_url}/api/certificates/revoke", {"certId": mallory["id"], "reason": "keyCompromise"})
        print("    Certyfikat „mallory” odwołany w CA.")

    print("[*] Pobieranie certyfikatu Root CA i aktualnej CRL z portalu klienta (po odwołaniach)...")
    ca_bytes = http_request(f"{portal_url}/api/certificates/ca")
    crl_bytes = http_request(f"{portal_url}/api/certificates/crl")
    (workdir / "ca_certificate.pem").write_bytes(ca_bytes)
    (workdir / "crl.pem").write_bytes(crl_bytes)
    ca_cert = x509.load_pem_x509_certificate(ca_bytes)
    print(f"    Root CA: {ca_cert.subject.rfc4514_string()}")
    print(f"    Odcisk SHA-256: {ca_cert.fingerprint(hashes.SHA256()).hex(':').upper()}")

    return {
        "cert": alfa_cert.read_bytes(),
        "key": alfa_key.read_bytes(),
        "ca": ca_bytes,
        "crl": crl_bytes,
        "revoked": mallory_cert.read_bytes() if mallory_cert else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Demonstracja uwierzytelniania węzła offline PKI")
    parser.add_argument("--cert", help="Ścieżka do certyfikatu węzła (PEM)")
    parser.add_argument("--key", help="Ścieżka do klucza prywatnego węzła (KEY/PEM)")
    parser.add_argument("--ca", help="Ścieżka do certyfikatu Root CA (ca_certificate.pem)")
    parser.add_argument("--crl", help="Ścieżka do listy odwołań CRL (crl.pem)")
    parser.add_argument("--admin-url", default=os.getenv("ADMIN_URL", "http://localhost:5000"),
                        help="Adres API CA (domyślnie $ADMIN_URL lub http://localhost:5000)")
    parser.add_argument("--portal-url", default=os.getenv("PORTAL_URL", "http://localhost:5001"),
                        help="Adres portalu klienta (domyślnie $PORTAL_URL lub http://localhost:5001)")
    parser.add_argument("--no-revoked", action="store_true",
                        help="Pomiń wydanie i odwołanie certyfikatu „mallory”")
    args = parser.parse_args()

    try:
        if args.cert or args.key:
            if not (args.cert and args.key):
                parser.error("--cert i --key muszą być podane razem")
            cert_bytes = Path(args.cert).read_bytes()
            key_bytes = Path(args.key).read_bytes()
            ca_bytes = Path(args.ca).read_bytes() if args.ca else http_request(f"{args.portal_url}/api/certificates/ca")
            crl_bytes = Path(args.crl).read_bytes() if args.crl else http_request(f"{args.portal_url}/api/certificates/crl")
            ok = simulate_handshake(cert_bytes, key_bytes, ca_bytes, crl_bytes)
        else:
            with tempfile.TemporaryDirectory(prefix="demo_offline_") as tmp:
                data = run_online_phase(args.admin_url, args.portal_url, not args.no_revoked, Path(tmp))
                ok = simulate_handshake(data["cert"], data["key"], data["ca"], data["crl"], data["revoked"])
    except DemoError as exc:
        print(f"\nBŁĄD: {exc}")
        return 1
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
