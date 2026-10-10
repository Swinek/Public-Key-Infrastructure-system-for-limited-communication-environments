#!/usr/bin/env bash
# ==============================================================================
# DEMONSTRACJA UWIERZYTELNIANIA WĘZŁÓW BRZEGOWYCH W ŚRODOWISKU OFFLINE (RADIO/VM)
# Wykorzystuje standardowe polecenia OpenSSL (dostępne domyślnie na każdym Linuksie).
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
PKI_DATA="$REPO_ROOT/backend/pki_data"

CERT="${1:-}"
KEY="${2:-}"
CA="${3:-$PKI_DATA/ca_certificate.pem}"
CRL="${4:-$PKI_DATA/crl.pem}"

echo "================================================================================"
echo " SYMULACJA UWIERZYTELNIANIA WĘZŁA BRZEGOWEGO W ŚRODOWISKU OFFLINE (RADIO/VM)"
echo " Medium: Fale radiowe / Odizolowana maszyna wirtualna (Brak dostępu do sieci)"
echo " Narzędzie kryptograficzne: OpenSSL"
echo "================================================================================"

# Jeśli nie podano plików, tworzymy tymczasowy węzeł do natychmiastowego testu
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

if [ -z "$CERT" ] || [ -z "$KEY" ]; then
    echo "[*] Brak podanych plików certyfikatu węzła. Generowanie testowego węzła..."
    if [ ! -f "$CA" ]; then
        echo "BŁĄD: Nie znaleziono Root CA w $CA. Uruchom najpierw backend lub podaj ścieżkę do Root CA."
        exit 1
    fi

    # Generujemy parę kluczy i certyfikat testowego węzła podpisany przez lokalny Root CA
    openssl genrsa -out "$TEMP_DIR/node_private.key" 2048 2>/dev/null
    openssl req -new -key "$TEMP_DIR/node_private.key" \
        -subj "/C=PL/O=Offline PKI Client/CN=radio_node_alfa_1/emailAddress=alfa@radio.local" \
        -out "$TEMP_DIR/node.csr" 2>/dev/null
    
    openssl x509 -req -in "$TEMP_DIR/node.csr" \
        -CA "$CA" -CAkey "$PKI_DATA/ca_private_key.pem" \
        -CAserial "$TEMP_DIR/ca.srl" -CAcreateserial \
        -out "$TEMP_DIR/node_cert.pem" -days 365 -sha256 2>/dev/null

    CERT="$TEMP_DIR/node_cert.pem"
    KEY="$TEMP_DIR/node_private.key"
    echo "    Utworzono tożsamość węzła: CN=radio_node_alfa_1"
fi

echo ""
echo "[KROK 1] Odczyt tożsamości węzła z certyfikatu publicznego X.509..."
SUBJECT=$(openssl x509 -in "$CERT" -noout -subject)
ISSUER=$(openssl x509 -in "$CERT" -noout -issuer)
SERIAL=$(openssl x509 -in "$CERT" -noout -serial)
echo "    Podmiot (Subject): $SUBJECT"
echo "    Wystawca (Issuer): $ISSUER"
echo "    Numer seryjny:     $SERIAL"

echo ""
echo "[KROK 2] Weryfikacja łańcucha zaufania certyfikatu lokalnym kluczem Root CA..."
if [ -f "$CRL" ]; then
    cat "$CA" "$CRL" > "$TEMP_DIR/trust_chain_with_crl.pem"
    if openssl verify -CAfile "$TEMP_DIR/trust_chain_with_crl.pem" -crl_check "$CERT" > "$TEMP_DIR/verify.log" 2>&1; then
        echo "    [OK] Certyfikat jest ważny i podpisany przez Root CA. Brak na liście CRL!"
    else
        echo "    [BŁĄD] Weryfikacja nie powiodła się lub certyfikat został UNIEWAŻNIONY w CRL!"
        cat "$TEMP_DIR/verify.log"
        exit 1
    fi
else
    if openssl verify -verbose -CAfile "$CA" "$CERT" > "$TEMP_DIR/verify.log" 2>&1; then
        echo "    [OK] Certyfikat jest poprawnie podpisany przez Root CA."
    else
        echo "    [BŁĄD] Nieprawidłowy certyfikat!"
        cat "$TEMP_DIR/verify.log"
        exit 1
    fi
fi

echo ""
echo "[KROK 3] Procedura Challenge-Response (Wyzwanie - Odpowiedź)..."
echo "    Stacja Bravo generuje losowe wyzwanie (32 bajty nonce)..."
openssl rand -out "$TEMP_DIR/challenge.bin" 32
echo "    Wyzwanie przesłane radiowo do Węzła Alfa: $(xxd -p -c 32 "$TEMP_DIR/challenge.bin" 2>/dev/null || od -An -tx1 "$TEMP_DIR/challenge.bin" | tr -d ' \n')"

echo ""
echo "[KROK 4] Węzeł Alfa podpisuje wyzwanie swoim kluczem prywatnym..."
openssl dgst -sha256 -sign "$KEY" -out "$TEMP_DIR/signature.bin" "$TEMP_DIR/challenge.bin"
echo "    Podpis cyfrowy RSA-SHA256 został wygenerowany i odesłany drogą radiową."

echo ""
echo "[KROK 5] Stacja Bravo weryfikuje podpis kluczem publicznym z certyfikatu..."
openssl x509 -in "$CERT" -pubkey -noout > "$TEMP_DIR/node_pubkey.pem"
if openssl dgst -sha256 -verify "$TEMP_DIR/node_pubkey.pem" -signature "$TEMP_DIR/signature.bin" "$TEMP_DIR/challenge.bin" >/dev/null 2>&1; then
    echo "    [OK] Podpis wyzwania zweryfikowany pomyślnie!"
else
    echo "    [BŁĄD] Podpis nie zgadza się! Odmowa uwierzytelnienia."
    exit 1
fi

echo ""
echo "================================================================================"
echo " SUKCES: WĘZEŁ ZOSTAŁ KRYPTOGRAFICZNIE UWIERZYTELNIONY W TRYBIE OFFLINE!"
echo " Transmisja radiowa pomiędzy węzłami została autoryzowana."
echo "================================================================================"
