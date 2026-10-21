#!/usr/bin/env bash
# ==============================================================================
# DEMONSTRACJA UWIERZYTELNIANIA WĘZŁÓW BRZEGOWYCH W ŚRODOWISKU OFFLINE (RADIO/VM)
# Wykorzystuje standardowe polecenia OpenSSL (dostępne domyślnie na każdym Linuksie).
#
# Skrypt wyłącznie WERYFIKUJE. Nie czyta klucza prywatnego Root CA i niczego nim
# nie podpisuje – certyfikaty wystawia CA (admin/backend) przez API.
#
# Przebieg (bez argumentów):
#   FAZA ONLINE  – wydanie certyfikatu węzła „alfa” i odwołanego „mallory” przez API
#                  CA, pobranie certyfikatu CA i CRL z portalu klienta (jak węzeł polowy).
#   FAZA OFFLINE – od tej chwili bez sieci: weryfikacja łańcucha i statusu w CRL,
#                  odrzucenie odwołanego certyfikatu, wyzwanie–podpis–weryfikacja.
#
# Użycie:
#   bash scripts/demo_offline_auth.sh [--no-revoked]
#   bash scripts/demo_offline_auth.sh CERT KEY [CA] [CRL]   # brakujące CA/CRL pobierane z portalu
#
# Zmienne środowiskowe:
#   ADMIN_URL  (domyślnie http://localhost:5000) – API CA (admin)
#   PORTAL_URL (domyślnie http://localhost:5001) – portal klienta (źródło CA i CRL)
#
# Uwaga (AGENTS.md, reguła 7): gdy CA zacznie publikować delta-CRL, weryfikacja musi
# używać `openssl verify -crl_check -use_deltas` – bez tej flagi OpenSSL ignoruje
# deltę i akceptuje certyfikat odwołany tylko w delcie.
# ==============================================================================

set -euo pipefail
shopt -s inherit_errexit   # błąd w $(...) też przerywa skrypt

ADMIN_URL="${ADMIN_URL:-http://localhost:5000}"
PORTAL_URL="${PORTAL_URL:-http://localhost:5001}"

WITH_REVOKED=1
if [ "${1:-}" = "--no-revoked" ]; then
    WITH_REVOKED=0
    shift
fi

CERT="${1:-}"
KEY="${2:-}"
CA="${3:-}"
CRL="${4:-}"

if { [ -n "$CERT" ] && [ -z "$KEY" ]; }; then
    echo "BŁĄD: Podano certyfikat bez klucza. Użycie: $0 CERT KEY [CA] [CRL]"
    exit 1
fi

# --- Wymagane narzędzia --------------------------------------------------------
MISSING=()
for tool in curl python3 openssl; do
    command -v "$tool" >/dev/null 2>&1 || MISSING+=("$tool")
done
if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "BŁĄD: Brak wymaganych narzędzi: ${MISSING[*]}"
    echo "      Zainstaluj je, np.: sudo apt install ${MISSING[*]}"
    exit 1
fi

TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT
umask 077

echo "================================================================================"
echo " SYMULACJA UWIERZYTELNIANIA WĘZŁA BRZEGOWEGO W ŚRODOWISKU OFFLINE (RADIO/VM)"
echo " Medium: Fale radiowe / Odizolowana maszyna wirtualna (Brak dostępu do sieci)"
echo " Narzędzie kryptograficzne: OpenSSL"
echo "================================================================================"

# --- Pomocnicze funkcje HTTP ---------------------------------------------------
# api_post URL JSON → wypisuje ciało odpowiedzi; kończy skrypt przy kodzie != 2xx
api_post() {
    local url="$1" body="$2" out code
    out="$TEMP_DIR/resp.json"
    code=$(curl -sS -m 15 -o "$out" -w '%{http_code}' \
        -H 'Content-Type: application/json' -d "$body" "$url") || {
        echo "    [BŁĄD] Brak połączenia z $url" >&2; exit 1; }
    if [ "${code:0:1}" != "2" ]; then
        echo "    [BŁĄD] $url zwrócił HTTP $code: $(cat "$out")" >&2
        exit 1
    fi
    cat "$out"
}

# fetch_pem URL PLIK – pobiera surowy PEM (np. CA lub CRL z portalu)
fetch_pem() {
    local url="$1" dest="$2"
    if ! curl -sSf -m 15 -o "$dest" "$url"; then
        echo "    [BŁĄD] Nie udało się pobrać $url" >&2
        exit 1
    fi
}

# issue_node NAZWA – rejestruje węzeł i wystawia mu certyfikat; zapisuje
# $TEMP_DIR/NAZWA_cert.pem, $TEMP_DIR/NAZWA_private.key, wypisuje id certyfikatu.
# Klucz prywatny węzła generuje serwer CA – w demo to akceptujemy; docelowo węzeł
# generuje klucz sam i wysyła CSR (Etap 3 planu wdrożenia).
# json_get POLE – odczyt pola z JSON na stdin (python3 zamiast jq, bez dodatkowych pakietów).
json_get() {
    python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

issue_node() {
    local name="$1" ts user_json user_id cert_json
    ts="$(date +%s)_${RANDOM}"
    user_json=$(api_post "$ADMIN_URL/api/users" \
        "{\"username\": \"radio_node_${name}_${ts}\", \"email\": \"${name}_${ts}@radio.local\", \"role\": \"user\"}")
    user_id=$(json_get id <<<"$user_json")
    cert_json=$(api_post "$ADMIN_URL/api/certificates" "{\"userId\": ${user_id}}")
    json_get certificate_pem <<<"$cert_json" > "$TEMP_DIR/${name}_cert.pem"
    json_get private_key <<<"$cert_json" > "$TEMP_DIR/${name}_private.key"
    chmod 600 "$TEMP_DIR/${name}_private.key"
    echo "    Wydano certyfikat węzła CN=radio_node_${name}_${ts} (seryjny: $(json_get serial_number <<<"$cert_json"))" >&2
    json_get id <<<"$cert_json"
}

MALLORY_CERT=""

# ==============================================================================
# FAZA ONLINE
# ==============================================================================
if [ -z "$CERT" ] || [ -z "$CA" ] || [ -z "$CRL" ]; then
    echo ""
    echo "--------------------------------------------------------------------------------"
    echo " FAZA ONLINE – łącze do centrum PKI dostępne"
    echo "   CA (admin):      $ADMIN_URL"
    echo "   Portal klienta:  $PORTAL_URL"
    echo "--------------------------------------------------------------------------------"

    if [ -z "$CERT" ]; then
        echo "[*] Sprawdzanie dostępności CA..."
        if ! curl -sSf -m 5 "$ADMIN_URL/api/health" >/dev/null; then
            echo "    [BŁĄD] CA niedostępne pod $ADMIN_URL. Uruchom: docker compose up --build -d"
            exit 1
        fi
        echo "    [OK] CA odpowiada."

        echo "[*] Wydawanie certyfikatu węzła „alfa”..."
        issue_node alfa >/dev/null
        CERT="$TEMP_DIR/alfa_cert.pem"
        KEY="$TEMP_DIR/alfa_private.key"

        if [ "$WITH_REVOKED" -eq 1 ]; then
            echo "[*] Wydawanie certyfikatu węzła „mallory” i jego odwołanie (keyCompromise)..."
            MALLORY_ID=$(issue_node mallory)
            api_post "$ADMIN_URL/api/certificates/revoke" \
                "{\"certId\": ${MALLORY_ID}, \"reason\": \"keyCompromise\"}" >/dev/null
            echo "    Certyfikat „mallory” odwołany w CA."
            MALLORY_CERT="$TEMP_DIR/mallory_cert.pem"
        fi
    fi

    if [ -z "$CA" ]; then
        echo "[*] Pobieranie certyfikatu Root CA z portalu klienta..."
        CA="$TEMP_DIR/ca_certificate.pem"
        fetch_pem "$PORTAL_URL/api/certificates/ca" "$CA"
        echo "    Root CA: $(openssl x509 -in "$CA" -noout -subject)"
        echo "    Odcisk SHA-256: $(openssl x509 -in "$CA" -noout -fingerprint -sha256 | cut -d= -f2)"
    fi
    if [ -z "$CRL" ]; then
        echo "[*] Pobieranie aktualnej CRL z portalu klienta (po odwołaniach)..."
        CRL="$TEMP_DIR/crl.pem"
        fetch_pem "$PORTAL_URL/api/certificates/crl" "$CRL"
    fi
fi

for f in "$CERT" "$KEY" "$CA" "$CRL"; do
    if [ ! -f "$f" ]; then
        echo "BŁĄD: Nie znaleziono pliku $f"
        exit 1
    fi
done

# ==============================================================================
# FAZA OFFLINE
# ==============================================================================
echo ""
echo "================================================================================"
echo " FAZA OFFLINE – od tej chwili bez sieci"
echo " Do weryfikacji używane są wyłącznie lokalne pliki: certyfikat Root CA i CRL."
echo "================================================================================"

echo ""
echo "[KROK 0] Lokalna lista odwołań (CRL)..."
echo "    $(openssl crl -in "$CRL" -noout -lastupdate)"
echo "    $(openssl crl -in "$CRL" -noout -nextupdate)"
echo "    Numer CRL: $(openssl crl -in "$CRL" -noout -crlnumber 2>/dev/null | cut -d= -f2 || echo brak)"
if openssl crl -in "$CRL" -CAfile "$CA" -noout 2>&1 | grep -q "verify OK"; then
    echo "    [OK] Podpis CRL zweryfikowany kluczem publicznym Root CA."
else
    echo "    [BŁĄD] Podpis CRL nieprawidłowy – lista odrzucona."
    exit 1
fi

cat "$CA" "$CRL" > "$TEMP_DIR/trust_chain_with_crl.pem"

# verify_offline CERT LOG – weryfikacja łańcucha do Root CA, ważności i statusu w CRL.
# openssl verify -crl_check odrzuca także przeterminowaną CRL (nextUpdate w przeszłości).
# Przy delta-CRL należy dodać -use_deltas (AGENTS.md, reguła 7).
verify_offline() {
    openssl verify -CAfile "$TEMP_DIR/trust_chain_with_crl.pem" -crl_check "$1" > "$2" 2>&1
}

echo ""
echo "[KROK 1] Odczyt tożsamości węzła z certyfikatu publicznego X.509..."
SUBJECT=$(openssl x509 -in "$CERT" -noout -subject)
ISSUER=$(openssl x509 -in "$CERT" -noout -issuer)
SERIAL=$(openssl x509 -in "$CERT" -noout -serial)
echo "    Podmiot (Subject): $SUBJECT"
echo "    Wystawca (Issuer): $ISSUER"
echo "    Numer seryjny:     $SERIAL"

echo ""
echo "[KROK 2] Weryfikacja łańcucha zaufania i statusu w CRL (lokalnie, bez CA)..."
if verify_offline "$CERT" "$TEMP_DIR/verify.log"; then
    echo "    [OK] Certyfikat jest ważny i podpisany przez Root CA. Brak na liście CRL!"
else
    echo "    [BŁĄD] Weryfikacja nie powiodła się lub certyfikat został UNIEWAŻNIONY w CRL!"
    cat "$TEMP_DIR/verify.log"
    exit 1
fi

if [ -n "$MALLORY_CERT" ]; then
    echo ""
    echo "[KROK 2b] Próba uwierzytelnienia węzła z ODWOŁANYM certyfikatem („mallory”)..."
    echo "    $(openssl x509 -in "$MALLORY_CERT" -noout -subject)"
    if verify_offline "$MALLORY_CERT" "$TEMP_DIR/verify_mallory.log"; then
        echo "    [BŁĄD DEMO] Odwołany certyfikat został zaakceptowany!"
        cat "$TEMP_DIR/verify_mallory.log"
        exit 1
    elif grep -qi "revoked" "$TEMP_DIR/verify_mallory.log"; then
        echo "    [OK – OCZEKIWANE ODRZUCENIE] Certyfikat figuruje w lokalnej CRL (certificate revoked)."
        echo "    Odmowa połączenia radiowego – poprawny wynik demonstracji."
    else
        echo "    [BŁĄD DEMO] Certyfikat odrzucony z innego powodu niż odwołanie:"
        cat "$TEMP_DIR/verify_mallory.log"
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
echo "    Podpis cyfrowy SHA-256 został wygenerowany i odesłany drogą radiową."

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
if [ -n "$MALLORY_CERT" ]; then
    echo " Węzeł z odwołanym certyfikatem został poprawnie odrzucony na podstawie lokalnej CRL."
fi
echo "================================================================================"
