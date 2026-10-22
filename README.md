# System Generowania i Dystrybucji Certyfikatów Cyfrowych w Systemie o Ograniczonej Łączności Sieciowej

---

## O projekcie

Niniejszy projekt stanowi implementację i demonstrację systemu PKI. Umożliwia on:
* Utrzymanie i automatyczną inicjalizację lokalnego urzędu certyfikacji (**Root CA**).
* Wystawianie standardowych certyfikatów cyfrowych **X.509** (RSA + SHA-256) wraz z generowaniem par kluczy.
* Unieważnianie certyfikatów i zarządzanie rejestrem odwołań (**CRL – Certificate Revocation List**).
* Przechowywanie metadanych poświadczeń (odcisk palca SHA-256, okres ważności, format PEM).
* Podgląd i weryfikację stanu poświadczeń z perspektywy stacji polowej / operatora końcowego.

---


```


```
projekt_inzynierski/
├── docker-compose.yml           # Centrum: PostgreSQL, Admin CA, Client Portal (+ sieć internet_net)
├── client.sh                    # Skrypt pomocniczy do węzłów brzegowych (deleguje do edges/client.sh)
├── pytest.ini, requirements-dev.txt, tests/   # Testy (pytest)
├── README.md                    # Główna dokumentacja projektu
│
├── admin/                       # Panel Administratora Root CA
│   ├── backend/                 # Backend Urzędu Root CA (port 5000)
│   │   ├── Dockerfile           # Obraz oparty o python:3.11-slim
│   │   ├── requirements.txt     # Zależności (fastapi, uvicorn, asyncpg, pydantic, cryptography)
│   │   ├── main.py              # API Root CA, lifespan (inicjalizacja CA + DB), CORS
│   │   ├── database.py          # Pula połączeń PostgreSQL (asyncpg)
│   │   ├── schemas.py           # Modele walidacyjne Pydantic
│   │   ├── init.sql             # Schemat bazy (users, certificates, ca_certificates, crls) + rola pki_portal (tylko odczyt)
│   │   ├── pki_data/            # Klucz i certyfikat Root CA – montowane do kontenera, poza obrazem
│   │   ├── routers/             # Endpointy: /api/users, /api/certificates, /api/pki, /api/health
│   │   └── pki/                 # ca.py – ECDSA P-256, X.509 z SKI/AKI/KeyUsage, CRL z CRLNumber; store.py – CRL w bazie, co 24 h
│   └── frontend/                # Panel Administratora Root CA (port 3000)
│       ├── Dockerfile           # Środowisko Node.js 18
│       ├── package.json         # React 18, Vite, Tailwind CSS, Lucide
│       └── src/                 # App.jsx – węzły, wystawianie X.509, rejestr; PkiPanel.jsx – zakładka „PKI / CRL”
│
├── clients/                     # Panel Samoobsługowy Klienta
│   ├── backend/                 # Backend Portalu Klienta / Weryfikacji (port 5001)
│   │   ├── Dockerfile           # Obraz python:3.11-slim
│   │   ├── requirements.txt     # Zależności (fastapi, uvicorn, asyncpg, pydantic)
│   │   ├── main.py              # API Klienta / RA (BEZ DOSTĘPU DO KLUCZA ROOT CA!)
│   │   ├── database.py          # Połączenie do bazy kontem pki_portal (tylko odczyt)
│   │   ├── store.py             # Odczyt CA/CRL z bazy, DER/PEM, ETag
│   │   └── routers/             # Endpointy read-only: /api/users, /api/certificates, /pki/* (dla węzłów)
│   └── frontend/                # Portal Samoobsługowy Klienta / Węzłów Polowych (port 3001)
│       ├── Dockerfile           # Środowisko Node.js 18
│       ├── package.json         # React 18, Vite, Tailwind CSS, Lucide
│       └── src/                 # App.jsx – tożsamość węzła, pobieranie poświadczeń; PkiStatus.jsx – „Stan PKI dla węzłów”
│
├── edges/                       # Węzły brzegowe / statki (symulacja sieci P2P w trybie offline)
│   ├── docker-compose.yml       # Orkiestracja węzłów (client_1..3, gateway, początkowe łącza p2p_12/p2p_23)
│   ├── client.sh                # Skrypt sterowania węzłami, łączem WAN i łączami radiowymi
│   ├── client_node.py           # Aplikacja węzła brzegowego (FastAPI)
│   ├── neighbours.py            # Wykrywanie sąsiadów radiowych beaconem UDP
│   ├── routing.py               # Dostarczanie tylko do sąsiadów w zasięgu
│   ├── routers/                 # Endpointy P2P, diagnostyki sieci i testu łączności
│   ├── static/                  # Panel graficzny węzła brzegowego
│   └── nginx_gateway.conf       # Konfiguracja reverse proxy dla portów 8001–8003
│
└── scripts/                     # Skrypty demonstracyjne offline auth (OpenSSL / Python)
```

---

## Moduł Kryptograficzny i Certyfikaty X.509

System posiada wbudowany silnik kryptograficzny oparty o bibliotekę `cryptography`:

### 1. Główny Urząd Certyfikacji (Root CA)
* Podczas uruchamiania backendu funkcja `initialize_ca()` automatycznie sprawdza obecność certyfikatu i klucza prywatnego Root CA.
* Jeśli nie istnieją, tworzy parę kluczy **RSA 4096-bit** oraz samopodpisany certyfikat główny **X.509** (`Offline PKI Root CA`) z okresem ważności 10 lat i rozszerzeniem `BasicConstraints(ca=True)`.
* Pliki CA zapisywane są w katalogu wskazanym przez `PKI_DIR`. W Dockerze jest to `/app/pki_data`, montowany z hosta (`admin/backend/pki_data/`), dzięki czemu klucz nie trafia do obrazu (`.dockerignore`) ani do repozytorium (`.gitignore`) i przetrwa przebudowę. Katalog ma uprawnienia 0700, klucz prywatny 0600.
* **Uwaga:** usunięcie `pki_data/` oznacza wygenerowanie **nowego** Root CA przy następnym starcie (backend zapisze ostrzeżenie w logach) – wcześniej wydane certyfikaty i fingerprinty zapisane w węzłach przestaną pasować.

### 2. Certyfikaty Użytkowników / Węzłów
* Endpoint `POST /api/certificates` uruchamia procedurę `issue_user_certificate(username, email)`.
* Generowana jest para kluczy **RSA 2048-bit** dla węzła.
* Tworzony jest certyfikat X.509 podpisany kluczem Root CA z okresem ważności 1 roku.
* Certyfikat zawiera podmiot (`CN=username`, `EMAIL=email`), unikalny numer seryjny oraz wyliczony odcisk palca (**SHA-256 fingerprint**).
* Certyfikat publiczny w formacie PEM trafia do bazy PostgreSQL.
* **Klucz prywatny użytkownika zwracany jest jednorazowo** w odpowiedzi API przy wystawieniu certyfikatu.

---

## Stos Technologiczny

| Warstwa | Technologia | Zastosowanie |
| :--- | :--- | :--- |
| **Backend** | Python 3.11, FastAPI, Uvicorn | Wydajne, asynchroniczne REST API z automatyczną dokumentacją OpenAPI / Swagger |
| **Kryptografia** | Python `cryptography` (X.509 / hazmat) | Klucze ECDSA P-256, certyfikaty X.509 (SKI/AKI/KeyUsage), CRL z `CRLNumber` i AKI, DER/PEM/PKCS#8, SHA-256 fingerprint |
| **Baza Danych** | PostgreSQL 15, asyncpg | Relacyjny magazyn węzłów, certyfikatów X.509, fingerprintów i wpisów unieważnień |
| **Frontend** | React 18, Vite, Tailwind CSS | Nowoczesny, responsywny dashboard operatorski z obsługą ról |
| **Konteneryzacja** | Docker, Docker Compose | Powtarzalne, izolowane środowisko uruchomieniowe |

---

## Uruchomienie

```bash
docker compose up --build -d        # CA, portal klienta, baza
./client.sh up                      # węzły brzegowe (domyślnie OFFLINE)
./client.sh internet on 3           # węzeł 3 ma łącze WAN – widzi portal pod http://pki-client-backend:5001
```

Testy (pytest + openssl) uruchamia się w kontenerze, bez lokalnego Pythona:

```bash
docker compose --profile test run --rm tests                 # testy jednostkowe
docker compose --profile test run --rm tests pytest -m docker # testy integracyjne (działające centrum)
```

Centrum (`docker-compose.yml`) i węzły (`edges/docker-compose.yml`) to dwa osobne systemy. Jedynym stykiem
między nimi jest sieć `internet_net`: tworzy ją `docker compose up` centrum, portal klienta jest do niej
podłączony na stałe, a węzły – tylko po `./client.sh internet on`.


### Dostęp do usług (Rozdzielona Architektura)

| Usługa | Adres URL | Kontener | Opis |
| :--- | :--- | :--- | :--- |
| **Panel Administratora (Frontend)** | [http://localhost:3000](http://localhost:3000) | `pki-admin-frontend` | Zarządzanie Root CA, wystawianie certyfikatów, rejestr CRL |
| **Backend Administratora (API)** | [http://localhost:5000/docs](http://localhost:5000/docs) | `pki-admin-backend` | REST API Root CA z dostępem do klucza prywatnego CA |
| **Portal Klienta (Frontend)** | [http://localhost:3001](http://localhost:3001) | `pki-client-frontend` | Portal samoobsługowy dla węzłów brzegowych / użytkowników |
| **Backend Klienta (API)** | [http://localhost:5001/docs](http://localhost:5001/docs) | `pki-client-backend` | Publiczne API weryfikacji i pobierania poświadczeń (bez klucza CA!) |
| **Baza Danych PostgreSQL** | `localhost:5433` (wewn. `5432`) | `pki-db` | Relacyjny magazyn węzłów i certyfikatów |
| **Węzły brzegowe** | [http://localhost:8001](http://localhost:8001), `:8002`, `:8003` (Swagger: `/docs`) | `client_1..3` | Panel węzła przez gateway nginx |

---

## Węzły brzegowe (`edges/`)

Węzły („okręty”) komunikują się przez symulowane, wolne łącze radiowe P2P. Na starcie łącza tworzą łańcuch:

    client_1 ──p2p_12── client_2 ──p2p_23── client_3

Każde łącze radiowe to osobna sieć Docker `internal` (bez internetu), `p2p_<ab>` = 192.168.<ab>.0/24, a węzeł N
ma w niej adres 192.168.<ab>.N0. Łącze między dowolną inną parą tworzy na żądanie `./client.sh link up <a> <b>`
(np. `p2p_13`). Gateway nginx łączy się z każdym węzłem osobną siecią `mgmt_N` i odrzuca ruch od węzłów,
więc nie tworzy mostu między nimi.

**Węzeł nie zna topologii.** Co `BEACON_INTERVAL` (2 s) nadaje na każdym łączu radiowym beacon UDP
(broadcast, port `BEACON_PORT` 8999, ~60 B: id, nazwa, port). Sąsiad to węzeł usłyszany w ciągu ostatnich
`NEIGHBOUR_TIMEOUT` (7 s) – po `link down` znika z listy sam. Wiadomości i pliki trafiają **tylko do węzłów
w zasięgu**; do pozostałych węzeł zwraca „not in radio range”. Dostarczanie przez pośredników
(store-and-forward) to Etap 3. Beacon nie jest uwierzytelniany – mówi tylko, kto jest w zasięgu.

Konfiguracja węzła (zmienne środowiskowe):
- `NODE_ID`, `NODE_NAME` – identyfikator i nazwa (Edge App #N),
- `P2P_CIDR`, `BEACON_PORT`, `BEACON_INTERVAL`, `NEIGHBOUR_TIMEOUT` – wykrywanie sąsiadów (wartości domyślne w `edges/config.py`),
- `DATA_DIR` – trwałe dane węzła (wolumen `client_N_data`): `inbox.json`, `received_files/`, `pki/` (Etap 2),
- `PORTAL_URL` – adres portalu klienta w sieci `internet_net` (Etap 3).

Wiadomości mają `msg_id`, nadawcę pierwotnego i listę `hops`. Węzeł odrzuca wiadomość, która już przez niego
przeszła (pętla), a pliki są sprawdzane sumą SHA-256 na każdym skoku.

```bash
./client.sh status | links                # status węzłów i łączy radiowych
./client.sh internet on|off [1|2|3|all]   # łącze WAN (sieć internet_net, dostęp do portalu PKI)
./client.sh link down|up 1 2              # zerwanie / przywrócenie łącza radiowego 1↔2
./client.sh link up 1 3                   # nowe łącze 1↔3 (sieć p2p_13 tworzona na żądanie)
./client.sh msg 1 2 "tekst"               # wiadomość 1 → 2 (odbiorca musi być w zasięgu)
./client.sh send-file 1 2 plik.txt        # plik 1 → 2
./client.sh inbox 3 | files 3             # skrzynka / odebrane pliki węzła 3
./client.sh p2p-test [N]                  # test łączy do wszystkich sąsiadów
```

---

## Testy

Testy uruchamiane są w kontenerze (nic nie trzeba instalować lokalnie):

```bash
docker run --rm -v "$PWD":/repo:ro -w /repo python:3.11-slim \
  sh -c "pip install -q -r requirements-dev.txt && python -m pytest -p no:cacheprovider"
```

Testy integracyjne (`-m docker`, wymagają uruchomionego centrum) – to samo z `--network host` i
`python -m pytest -p no:cacheprovider -m docker`. Testy CA generują Root CA w katalogu tymczasowym
(`PKI_DIR`) – nigdy nie dotykają `admin/backend/pki_data`.

---

## Scenariusz Demonstracyjny

Aplikacja została zaprojektowana z myślą o czytelnej demonstracji działania PKI:

1. **Przegląd Węzłów i Tożsamości:**
   * Po wejściu na stronę główną widoczne są kluczowe metryki: całkowita liczba użytkowników, aktywne certyfikaty oraz liczba kluczy na liście odwołań (CRL).
2. **Rejestracja nowego węzła:**
   * Węzły dodaje się z poziomu kodu, a nie z panelu: dane startowe w `admin/backend/init.sql`
     albo `POST /api/users` (np. ze Swaggera CA lub ze skryptu).
3. **Wydanie certyfikatu X.509:**
   * Kliknij przycisk **„Issue Certificate”** przy utworzonym użytkowniku.
   * System wygeneruje klucz ECDSA P-256, podpisze certyfikat kluczem Root CA (z AKI/SKI/KeyUsage) i zwróci certyfikat wraz z jednorazowym kluczem prywatnym.
4. **Weryfikacja w Rejestrze Certyfikatów:**
   * Przejdź do zakładki *„Certificate Registry”*, aby zobaczyć pełną historię poświadczeń wraz ze znacznikami czasu, numerami seryjnymi i fingerprintami.
5. **Unieważnienie certyfikatu (CRL):**
   * Wybierz **„Revoke”** przy aktywnym użytkowniku, podaj przyczynę (np. *„Key Compromise / Token lost”*) i zatwierdź.
   * Certyfikat natychmiast zmienia status na `Revoked (CRL)` z zapisanym powodem i datą wycofania,
     a CA podpisuje nową CRL – jej numer, wpisy i historię widać w zakładce *„PKI / CRL”*.

---

## Podstawowe Endpointy API

| Metoda | Ścieżka | Opis |
| :---: | :--- | :--- |
| `GET` | `/api/users` | Pobranie listy zarejestrowanych węzłów i użytkowników ze statusem certyfikatu |
| `POST` | `/api/users` | Rejestracja nowego węzła w systemie |
| `DELETE`| `/api/users/{id}` | Usunięcie węzła: aktywny certyfikat zostaje odwołany (nowa CRL), wpisy certyfikatów zostają w rejestrze |
| `GET` | `/api/certificates` | Pobranie rejestru wszystkich certyfikatów (PEM, fingerprint, daty ważności, status) |
| `POST` | `/api/certificates` | Wystawienie certyfikatu X.509 podpisanego przez Root CA (zwraca certyfikat i klucz prywatny) |
| `POST` | `/api/certificates/revoke` | Unieważnienie certyfikatu i podpisanie nowej CRL (zwraca `crl_number`) |
| `GET` | `/api/certificates/ca/download` | Pobranie certyfikatu Root CA (`ca_certificate.pem`) do instalacji na węzłach polowych |
| `GET` | `/api/certificates/crl/download` | Pobranie ostatniej zapisanej CRL (`?format=pem` domyślnie, `der`) – nie podpisuje nowej |
| `GET` | `/api/pki/ca`, `/api/pki/crl`, `/api/pki/crls` | (CA) Metadane Root CA, bieżąca CRL z wpisami, historia CRL |
| `POST` | `/api/pki/crl` | (CA) Ręczne podpisanie nowej CRL |
| `GET` | `/pki/summary` | (portal) Numer i rozmiary CRL, fingerprint CA, liczba certyfikatów – węzeł porównuje przed pobraniem |
| `GET` | `/pki/ca`, `/pki/crl`, `/pki/certs`, `/pki/certs/{serial}` | (portal) Obiekty PKI w DER (`?format=pem`), ETag → 304 dla aktualnej wersji |
| `GET` | `/api/health` | Status działania serwera backendowego |
| `GET` | `/docs` | Interaktywna dokumentacja Swagger UI |

---

## Demonstracja Uwierzytelniania Offline (Radio / Maszyna Wirtualna)

Skrypty w `scripts/` pokazują, że węzeł polowy weryfikuje tożsamość sąsiada **bez dostępu do CA**,
wyłącznie na podstawie lokalnego certyfikatu Root CA i ostatniej pobranej CRL. Skrypty niczego nie
podpisują kluczem CA – certyfikaty wystawia CA przez API (klucz Root CA nie opuszcza `admin/backend`).

Wymagane działające centrum (`docker compose up --build -d`). Przebieg:

1. **Faza online** – rejestracja węzła `radio_node_alfa_<ts>` i wydanie mu certyfikatu; wydanie
   certyfikatu `radio_node_mallory_<ts>` i jego odwołanie (`keyCompromise`); pobranie certyfikatu
   Root CA i aktualnej CRL z portalu klienta (`/api/certificates/ca`, `/api/certificates/crl`).
2. **Faza offline (od tej chwili bez sieci)** – weryfikacja podpisu i świeżości CRL (`nextUpdate`),
   weryfikacja łańcucha i statusu certyfikatu „alfa” (OK), próba uwierzytelnienia „mallory”
   (oczekiwane odrzucenie: certyfikat odwołany), wyzwanie–podpis–weryfikacja dla „alfa”.

```bash
# OpenSSL (wymaga curl, python3, openssl):
bash scripts/demo_offline_auth.sh                 # pełny przebieg
bash scripts/demo_offline_auth.sh --no-revoked    # bez odwołanego certyfikatu „mallory”
bash scripts/demo_offline_auth.sh node_cert.pem node_private.key [ca_certificate.pem] [crl.pem]

# Python (wymaga cryptography >= 43):
python3 scripts/demo_offline_auth.py [--no-revoked]
python3 scripts/demo_offline_auth.py --cert node_cert.pem --key node_private.key --ca ca_certificate.pem --crl crl.pem
```

Adresy usług ustawia się zmiennymi `ADMIN_URL` (domyślnie `http://localhost:5000`) i `PORTAL_URL`
(domyślnie `http://localhost:5001`), a w skrypcie Python także opcjami `--admin-url` / `--portal-url`.
Każde uruchomienie tworzy w bazie nowych użytkowników demo (usunięcie użytkownika odwołuje jego
certyfikat i zostawia wpis w CRL).

> Klucz prywatny węzła w demo generuje serwer CA; docelowo węzeł wygeneruje go sam i wyśle CSR (Etap 3).


