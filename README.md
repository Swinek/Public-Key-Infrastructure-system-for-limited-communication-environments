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
├── docker-compose.yml           # Centrum: PostgreSQL, Panel administratora, backend Edge client 5001 (+ sieć internet_net)
├── docker-compose.edge.yml      # Węzły: Edge client client_1..3 + Edge app app_1..3, gateway, sieci P2P/mgmt/app_net
├── client.sh                    # „Łączność” z diagramu: łącze WAN (internet on/off), łącza radiowe (link up/down)
├── nginx_edge.conf              # Gateway UI: Edge app :8001–8003, Edge client :3011–3013
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
│       └── src/                 # App.jsx – węzły, wydawanie i odwoływanie X.509; PkiPanel.jsx – zakładka „PKI / CRL”
│
├── edge_client/                 # „Edge client” z diagramu: dystrybucja danych PKI do węzłów
│   ├── backend/                 # Publikacja CA/CRL/certyfikatów dla węzłów przez WAN (port 5001, bez UI)
│   │   ├── Dockerfile           # Obraz python:3.11-slim
│   │   ├── requirements.txt     # Zależności (fastapi, uvicorn, asyncpg, pydantic)
│   │   ├── main.py              # API Klienta / RA (BEZ DOSTĘPU DO KLUCZA ROOT CA!)
│   │   ├── database.py          # Połączenie do bazy kontem pki_portal (tylko odczyt)
│   │   ├── store.py             # Odczyt CA/CRL z bazy, DER/PEM, ETag
│   │   └── routers/             # Endpointy read-only: /api/users, /api/certificates, /pki/* (dla węzłów)
│   └── node/                    # Edge client N na węźle (kontenery client_1..3, UI :3011–3013)
│       ├── client_node.py       # Aplikacja FastAPI Edge clienta
│       ├── neighbours.py        # Sąsiedzi radiowi: jednorazowe hello przy zestawieniu łącza
│       ├── routing.py           # Bezpośrednie dostarczanie do sąsiadów w zasięgu
│       ├── contact.py           # Wyzwalacze kontaktu (internet on, hello, announce) – bez timerów
│       ├── pki_sync.py          # Synchronizacja CRL / Root CA z portalem i sąsiadami (summary → tylko nowsze)
│       ├── saf.py               # Store-and-forward wiadomości i plików do węzłów poza zasięgiem
│       ├── transfers.py, wire.py # Rejestr przesłanych bajtów (payload / wire) i HTTP z limitem rozmiaru
│       ├── certs.py             # Magazyn: jeden certyfikat węzła (+ klucz), Root CA i CRL
│       ├── routers/             # certs, pki (/pki/* dla sąsiadów), saf, stats, contact, p2p, diagnostyka WAN
│       └── static/              # Konsola Edge clienta
│
├── edge_app/                    # „Edge app” z diagramu: tylko użycie certyfikatu (kontenery app_1..3, UI :8001–8003)
│   ├── app_node.py              # Aplikacja FastAPI Edge app
│   ├── pki/                     # Magazyn (przypięty Root CA, certyfikat + klucz, CRL) i weryfikator offline
│   ├── routers/pki.py           # Pobranie certyfikatu, klucza, Root CA i CRL od Edge clienta; status
│   ├── routers/auth.py          # Wzajemne uwierzytelnianie Edge app: wyzwanie → podpis → weryfikacja offline
│   └── static/                  # Panel Edge app
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
./client.sh up                      # węzły: Edge client + Edge app (domyślnie bez WAN)
./client.sh internet on 3           # Edge client 3 ma łącze WAN – widzi portal pod http://pki-edge-client-backend:5001
```

Testy (pytest + openssl) uruchamia się w kontenerze, bez lokalnego Pythona:

```bash
docker compose --profile test run --rm tests                 # testy jednostkowe
docker compose --profile test run --rm tests pytest -m docker # testy integracyjne (działające centrum)
```

Centrum (`docker-compose.yml`) i węzły (`docker-compose.edge.yml`) to dwa osobne systemy. Jedynym stykiem
między nimi jest sieć `internet_net`: tworzy ją `docker compose up` centrum, portal klienta jest do niej
podłączony na stałe, a Edge clienty – tylko po `./client.sh internet on`. Edge app nigdy nie ma WAN.


### Dostęp do usług (Rozdzielona Architektura)

| Usługa | Adres URL | Kontener | Opis |
| :--- | :--- | :--- | :--- |
| **Panel Administratora (Frontend)** | [http://localhost:3000](http://localhost:3000) | `pki-admin-frontend` | Węzły, wydawanie i odwoływanie certyfikatów, Root CA i bieżąca CRL |
| **Backend Administratora (API)** | [http://localhost:5000/docs](http://localhost:5000/docs) | `pki-admin-backend` | REST API Root CA z dostępem do klucza prywatnego CA |
| **Backend Edge client (API)** | [http://localhost:5001/docs](http://localhost:5001/docs) | `pki-edge-client-backend` | Publikacja CA, CRL i certyfikatów dla węzłów przez WAN (tylko odczyt bazy, bez klucza CA!) |
| **Baza Danych PostgreSQL** | `localhost:5433` (wewn. `5432`) | `pki-db` | Relacyjny magazyn węzłów i certyfikatów |
| **Edge app 1–3** | [http://localhost:8001](http://localhost:8001), `:8002`, `:8003` (Swagger: `/docs`) | `app_1..3` | Przykładowa aplikacja: pobiera certyfikat od Edge clienta i uwierzytelnia się z inną Edge app |
| **Edge client 1–3 (węzły)** | [http://localhost:3011](http://localhost:3011), `:3012`, `:3013` (Swagger: `/docs`) | `client_1..3` | Certyfikat węzła (automatyczny wniosek CSR, podgląd, pobranie), łącze WAN, łącza radiowe P2P |

---

## Węzły brzegowe (`edge_client/node/` + `edge_app/`)

Węzeł N to para kontenerów z diagramu:

- **Edge client N** (`client_N`) – **przechowuje jeden certyfikat węzła** z kluczem i **zdobywa go sam**: generuje
  klucz EC P-256 (nie opuszcza węzła), przy kontakcie WAN wysyła wniosek CSR, a po zatwierdzeniu w panelu CA
  (zakładka *„Wnioski CSR”*) pobiera i instaluje certyfikat, który zastępuje poprzedni. Nowy wniosek idzie sam, gdy
  certyfikatu brak, jest odwołany albo kończy się za `RENEW_BEFORE_DAYS` dni; po odrzuceniu – tylko na żądanie
  (`client.sh csr N`). Nie ma wgrywania certyfikatu, klucza ani Root CA: Root CA jest przypięty przy wdrożeniu
  (`CA_FINGERPRINT` w `.env`, zapisuje go `client.sh up`) i pobierany z portalu. Certyfikat można pobrać (PEM, bez klucza). Trzyma też Root CA i najnowszą CRL i **w każdej chwili
  sprawdza offline** swój certyfikat albo dowolny inny
  (łańcuch do Root CA, ważność, status w CRL – ten sam weryfikator co Edge app, `edge_app/pki`, dołączany do obrazu
  przy budowaniu). Poza tym: łącze WAN do centrum, łącza radiowe P2P, wiadomości i pliki. Niczego nie podpisuje.
- **Edge app N** (`app_N`) – przykładowa aplikacja, która **tylko się uwierzytelnia**. Panel ma jeden formularz:
  wybór partnera i „Authenticate”. Przed uwierzytelnieniem aplikacja sama pobiera od swojego Edge clienta
  certyfikat z kluczem, Root CA i CRL (strzałka „cert”, sieć `mgmt_N`; pakiet z kluczem Edge client wydaje tylko
  adresowi swojej Edge app), sprawdza je względem przypiętego Root CA i uwierzytelnia się z drugą Edge app
  (wyzwanie → podpis → weryfikacja offline) w odrębnym kanale `app_net`. Gdy Edge client jest niedostępny, używa
  ostatnio pobranej kopii. Nie ma WAN ani P2P.

```bash
./client.sh csr 1                         # nowy klucz + wniosek (np. po odrzuceniu); zatwierdza administrator
./client.sh crl-upload 1 crl.der          # CRL z nośnika (tylko podpisana przez CA i nowsza)
./client.sh certs 1                       # certyfikat, Root CA i CRL w Edge client 1
./client.sh cert-download 1 [plik.pem]    # pobranie certyfikatu (PEM, bez klucza)
./client.sh cert-check 1 [plik]           # sprawdzenie offline w Edge client 1 (domyślnie jego certyfikat)
./client.sh fetch 1                       # app_1 pobiera certyfikat od Edge client 1 (auth robi to sam)
./client.sh pki [N]                       # magazyn PKI Edge app
./client.sh auth 1 2                      # app_1 ↔ app_2: wzajemne uwierzytelnienie certyfikatami
```

Edge clienty („okręty”) komunikują się przez symulowane, wolne łącze radiowe P2P. Na starcie łącza tworzą łańcuch:

    client_1 ──p2p_12── client_2 ──p2p_23── client_3

Każde łącze radiowe to osobna sieć Docker `internal` (bez internetu), `p2p_<ab>` = 192.168.<ab>.0/24, a węzeł N
ma w niej adres 192.168.<ab>.N0. Łącze między dowolną inną parą tworzy na żądanie `./client.sh link up <a> <b>`
(np. `p2p_13`). Gateway nginx łączy się z każdym węzłem osobną siecią `mgmt_N` i odrzuca ruch od węzłów,
więc nie tworzy mostu między nimi.

**Węzeł nie zna topologii, a łączność ustala się raz.** Przy zestawieniu łącza (`link up`, a dla łączy
początkowych – przy starcie węzła) każdy węzeł wysyła **jeden** pakiet UDP hello (broadcast, port `HELLO_PORT`
8999: id, nazwa, port), a sąsiad odpowiada **jednym** hello-ack. Potem po łączu nie krąży nic (brak
okresowych beaconów i pingów). Sąsiad pozostaje sąsiadem, dopóki istnieje łącze: po `link down` węzeł traci
interfejs, więc wpis znika od razu – sprawdzane lokalnie, bez ruchu radiowego. Wiadomość lub plik do
sąsiada w zasięgu idzie bezpośrednio; do węzła poza zasięgiem trafia do kolejki **store-and-forward** (status
`QUEUED`) i wędruje z sąsiadami. Hello nie jest uwierzytelniane – mówi tylko, kto jest na łączu.

**Wymiana danych tylko przy kontakcie** (`edge_client/node/contact.py`, bez timerów i odpytywania). Kontakt to:
**wydanie nowej CRL w CA** (CA wysyła `pg_notify`, portal – `edge_client/backend/announce.py` – od razu budzi
węzły, które mają internet: `POST /api/contact/wan`), `internet on` (portal), odebrane hello / hello-ack (sąsiad)
oraz `announce` – krótka informacja od sąsiada, że ma nowe dane. Przy `link up a b` hello wysyła tylko węzeł a i tylko na nowym łączu, więc każda strona wymienia dane
z drugą dokładnie raz. Przy każdym kontakcie węzeł **sam pobiera** od drugiej strony:

1. **PKI** (`pki_sync.py`): `GET /pki/summary`, potem tylko brakujący obiekt – CRL o wyższym `CRLNumber`, Root CA
   gdy go nie ma. Edge client udostępnia sąsiadom te same `/pki/summary|ca|crl` co portal, więc to jeden kod dla
   WAN i radia. Przed zapisem: podpis CA, issuer, rosnący numer (`certs.update_crl`); pobieranie przerywane po
   przekroczeniu rozmiaru z `summary` (niezaufany) i `MAX_PKI_OBJECT_BYTES`. Nowa CRL jest ogłaszana pozostałym
   sąsiadom (`announce`), więc dociera łańcuchem 1 → 2 → 3. Root CA od sąsiada tylko przy przypiętym
   `CA_FINGERPRINT` – od portalu i od sąsiada; bez przypięcia węzeł nie przyjmie żadnego CA.
2. **Store-and-forward** (`saf.py`, wariant epidemiczny): `POST /api/saf/offer` z listą znanych `msg_id`
   (16 znaków hex), w odpowiedzi tylko brakujące elementy; plik osobno, ze sprawdzeniem rozmiaru i SHA-256. Każdy
   węzeł trzyma kopię do `SAF_TTL_HOURS` (TTL liczone od utworzenia, pośrednik nie może go przedłużyć), limit
   skoków `P2P_MAX_HOPS`, pętle odrzucane. Adresat dostarcza element do skrzynki / `received_files`.

Każde wysłanie i odbiór jest zapisywane w rejestrze (`transfers.py`, `DATA_DIR/transfers.jsonl`): rodzaj
(`summary`, `crl_full`, `ca_cert`, `msg`, `file`, `saf_offer`, `announce`), kierunek, sąsiad, `payload_bytes`
(sam obiekt), `wire_bytes` (żądanie + odpowiedź HTTP z nagłówkami), status (`ok`, `skipped` – nie wysłano, bo
druga strona już miała, z `saved_bytes`; `rejected`; `aborted`). Podgląd: `./client.sh stats`,
`GET /api/stats/transfers` (`?format=csv`).

Konfiguracja Edge clienta (zmienne środowiskowe, wartości domyślne w `edge_client/node/config.py`):
- `NODE_ID`, `NODE_NAME` – identyfikator (= CN certyfikatu węzła) i nazwa (Edge client #N),
- `P2P_CIDR`, `HELLO_PORT` – zakres adresów łączy radiowych i port hello,
- `DATA_DIR` – trwałe dane (wolumen `edge_client_N_data`): `inbox.json`, `received_files/`, `certs/`, `saf/`,
  `transfers.jsonl`,
- `PORTAL_URL` – adres portalu klienta w sieci `internet_net` (kontakt WAN),
- `CA_FINGERPRINT` – przypięty Root CA (SHA-256 hex); bez niego CA tylko z portalu lub ręcznie,
- `MAX_PKI_OBJECT_BYTES`, `SAF_TTL_HOURS`, `SAF_MAX_FILE_BYTES`, `P2P_MAX_HOPS` – limity wymiany,
- `EDGE_APP_URL` – Edge app tego węzła (`http://app_N:8000`, sieć `mgmt_N`).

Konfiguracja Edge app (`edge_app/config.py`): `NODE_ID` (CN certyfikatu), `APP_ID` (`app_N`), `DATA_DIR`
(wolumen `edge_app_N_data`, magazyn `pki/`), `CA_FINGERPRINT` (przypięty Root CA), `CHALLENGE_TTL_SECONDS`.

Wiadomości mają `msg_id`, nadawcę pierwotnego i listę `hops`. Węzeł odrzuca wiadomość, która już przez niego
przeszła (pętla), a pliki są sprawdzane sumą SHA-256 na każdym skoku.

Przykład (CRL i wiadomość docierają do odciętego węzła 3 przez węzeł 2):

```bash
./client.sh link down 2 3; ./client.sh stats-reset
./client.sh internet on 1                 # client_1 ma internet (portal zapamiętuje go jako online)
curl -X POST localhost:5000/api/pki/crl   # nowa CRL (albo odwołanie w panelu): impuls → client_1 pobiera,
                                          # announce → client_2 pobiera od 1 – bez żadnej komendy
./client.sh msg 1 3 "dla 3"               # QUEUED: kopia u client_1 i client_2
./client.sh link up 2 3                   # client_3 pobiera CRL i wiadomość od client_2
./client.sh inbox 3; ./client.sh stats
```

```bash
./client.sh status | links                # status węzłów i łączy radiowych
./client.sh internet on|off [1|2|3|all]   # łącze WAN (sieć internet_net, dostęp do portalu PKI)
./client.sh link down|up 1 2              # zerwanie / przywrócenie łącza radiowego 1↔2
./client.sh link up 1 3                   # nowe łącze 1↔3 (sieć p2p_13 tworzona na żądanie)
./client.sh msg 1 3 "tekst"               # wiadomość 1 → 3 (w zasięgu bezpośrednio, inaczej store-and-forward)
./client.sh send-file 1 3 plik.txt        # plik 1 → 3
./client.sh queue [N] | contacts N        # kolejka store-and-forward / ostatnie kontakty i wynik wymian
./client.sh stats [N] [csv] | stats-reset # bajty przesłane WAN/P2P wg rodzaju i sąsiada
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
3. **Certyfikat węzła (wniosek CSR):**
   * Edge client bez ważnego certyfikatu sam generuje klucz i przy kontakcie WAN wysyła wniosek – pojawia się on
     w zakładce **„Wnioski CSR”**. **„Zatwierdź”** podpisuje certyfikat na klucz z wniosku (klucz prywatny nie
     opuszcza węzła), odwołuje poprzedni certyfikat węzła (nowa CRL) i budzi węzeł, który od razu instaluje nowy.
     **„Odrzuć”** kończy wniosek – węzeł nie wysyła go ponownie sam.
   * Przycisk **„Issue Certificate”** (klucz generowany w CA) został tylko dla skryptów demonstracyjnych w `scripts/`.
4. **Podgląd w Edge clientcie:**
   * W panelu Edge clienta (:3011–3013, zakładka *„Certificates”*) widać certyfikat z wynikiem weryfikacji offline,
     stan wniosku, przycisk „New key + request” i awaryjne wgranie samej CRL.
5. **Unieważnienie certyfikatu (CRL):**
   * Wybierz **„Revoke”** przy aktywnym użytkowniku, podaj przyczynę (np. *„Key Compromise / Token lost”*) i zatwierdź.
   * Certyfikat natychmiast zmienia status na `Revoked (CRL)` z zapisanym powodem i datą wycofania,
     a CA podpisuje nową CRL – jej numer i datę ważności widać w zakładce *„PKI / CRL”*.

---

## Podstawowe Endpointy API

| Metoda | Ścieżka | Opis |
| :---: | :--- | :--- |
| `GET` | `/api/users` | Pobranie listy zarejestrowanych węzłów i użytkowników ze statusem certyfikatu |
| `POST` | `/api/users` | Rejestracja nowego węzła w systemie |
| `DELETE`| `/api/users/{id}` | Usunięcie węzła: aktywny certyfikat zostaje odwołany (nowa CRL), wpisy certyfikatów zostają w rejestrze |
| `GET` | `/api/certificates` | Pobranie rejestru wszystkich certyfikatów (PEM, fingerprint, daty ważności, status) |
| `POST` | `/api/certificates` | Wystawienie certyfikatu X.509 podpisanego przez Root CA (zwraca certyfikat i klucz prywatny) |
| `GET` | `/api/csr` | (CA) Wnioski CSR węzłów (`?status=PENDING`) |
| `POST` | `/api/csr/{id}/approve`, `/api/csr/{id}/reject` | (CA) Zatwierdzenie (certyfikat na klucz z wniosku, poprzedni odwołany) / odrzucenie |
| `POST` | `/pki/csr`; `GET` `/pki/csr/{odcisk klucza}` | (portal) Przyjęcie wniosku CSR od węzła / jego status i numer seryjny certyfikatu |
| `POST` | `/api/certificates/revoke` | Unieważnienie certyfikatu i podpisanie nowej CRL (zwraca `crl_number`) |
| `GET` | `/api/certificates/ca/download` | Pobranie certyfikatu Root CA (`ca_certificate.pem`) do instalacji na węzłach polowych |
| `GET` | `/api/certificates/crl/download` | Pobranie ostatniej zapisanej CRL (`?format=pem` domyślnie, `der`) – nie podpisuje nowej |
| `GET` | `/api/pki/ca`, `/api/pki/crl`, `/api/pki/crls` | (CA) Metadane Root CA, bieżąca CRL z wpisami, historia CRL |
| `POST` | `/api/pki/crl` | (CA) Ręczne podpisanie nowej CRL |
| `GET` | `/pki/summary` | (portal) Numer i rozmiary CRL, fingerprint CA, liczba certyfikatów – węzeł porównuje przed pobraniem |
| `GET` | `/pki/ca`, `/pki/crl`, `/pki/certs`, `/pki/certs/{serial}` | (portal) Obiekty PKI w DER (`?format=pem`), ETag → 304 dla aktualnej wersji |
| `GET` | `/pki/online` | (portal) Węzły, które dostaną impuls o nowej CRL |
| `GET` | `/pki/summary`, `/pki/ca`, `/pki/crl` | (Edge client) Te same obiekty dla sąsiadów – oryginały podpisane przez CA |
| `POST` | `/api/contact/wan`, `/api/contact/announce` | (Edge client) Kontakt z portalem (`internet on`) / sąsiad ma nowe dane |
| `GET` | `/api/contact/events` | (Edge client) Ostatnie kontakty i wynik wymian |
| `POST` | `/api/saf/offer`; `GET` `/api/saf/items/{id}/content`, `/api/saf/queue` | (Edge client) Store-and-forward |
| `GET`/`DELETE` | `/api/stats/transfers` | (Edge client) Rejestr przesłanych bajtów (`?format=csv`) / wyczyszczenie |
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


