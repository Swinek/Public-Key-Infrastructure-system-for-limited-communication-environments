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
├── docker-compose.yml           # Orkiestracja kontenerów (PostgreSQL, Admin CA, Client Portal)
├── client.sh                    # Skrypt pomocniczy do węzłów brzegowych (deleguje do edges/client.sh)
├── README.md                    # Główna dokumentacja projektu
│
├── admin/                       # Panel Administratora Root CA
│   ├── backend/                 # Backend Urzędu Root CA (port 5000)
│   │   ├── Dockerfile           # Obraz oparty o python:3.11-slim
│   │   ├── requirements.txt     # Zależności (fastapi, uvicorn, asyncpg, pydantic, cryptography)
│   │   ├── main.py              # API Root CA, lifespan (inicjalizacja CA + DB), CORS
│   │   ├── database.py          # Pula połączeń PostgreSQL (asyncpg)
│   │   ├── schemas.py           # Modele walidacyjne Pydantic
│   │   ├── init.sql             # Schemat bazy danych (tabele users, certificates)
│   │   ├── pki_data/            # Klucze Root CA (ca_private_key.pem, ca_certificate.pem, crl.pem)
│   │   ├── routers/             # Endpointy: /api/users, /api/certificates, /api/health
│   │   └── pki/                 # Silnik CA (ca.py - RSA 4096, X.509, generowanie CRL)
│   └── frontend/                # Panel Administratora Root CA (port 3000)
│       ├── Dockerfile           # Środowisko Node.js 18
│       ├── package.json         # React 18, Vite, Tailwind CSS, Lucide
│       └── src/App.jsx          # Pulpit zarządzania węzłami, wystawiania X.509 i rejestru CRL
│
├── clients/                     # Panel Samoobsługowy Klienta
│   ├── backend/                 # Backend Portalu Klienta / Weryfikacji (port 5001)
│   │   ├── Dockerfile           # Obraz python:3.11-slim
│   │   ├── requirements.txt     # Zależności (fastapi, uvicorn, asyncpg, pydantic, httpx)
│   │   ├── main.py              # API Klienta / RA (BEZ DOSTĘPU DO KLUCZA ROOT CA!)
│   │   ├── database.py          # Połączenie do bazy (odczyt poświadczeń węzłów)
│   │   └── routers/             # Endpointy read-only: /api/users, /api/certificates, proxy CA/CRL
│   └── frontend/                # Portal Samoobsługowy Klienta / Węzłów Polowych (port 3001)
│       ├── Dockerfile           # Środowisko Node.js 18
│       ├── package.json         # React 18, Vite, Tailwind CSS, Lucide
│       └── src/App.jsx          # Wybór tożsamości węzła, pobieranie certyfikatu PEM, Root CA i CRL
│
├── edges/                       # Węzły brzegowe / statki (symulacja sieci P2P w trybie offline)
│   ├── docker-compose.yml       # Orkiestracja węzłów (client_1, client_2, gateway)
│   ├── client.sh                # Skrypt sterowania węzłami i symulacją łącza Internet/P2P
│   ├── client_node.py           # Aplikacja węzła brzegowego (FastAPI)
│   ├── routers/                 # Endpointy P2P, diagnostyki sieci i testu łączności
│   ├── static/                  # Panel graficzny węzła brzegowego
│   └── nginx_gateway.conf       # Konfiguracja reverse proxy dla portów 8001 i 8002
│
└── scripts/                     # Skrypty demonstracyjne offline auth (OpenSSL / Python)
```

---

## Moduł Kryptograficzny i Certyfikaty X.509

System posiada wbudowany silnik kryptograficzny oparty o bibliotekę `cryptography`:

### 1. Główny Urząd Certyfikacji (Root CA)
* Podczas uruchamiania backendu funkcja `initialize_ca()` automatycznie sprawdza obecność certyfikatu i klucza prywatnego Root CA.
* Jeśli nie istnieją, tworzy parę kluczy **RSA 4096-bit** oraz samopodpisany certyfikat główny **X.509** (`Offline PKI Root CA`) z okresem ważności 10 lat i rozszerzeniem `BasicConstraints(ca=True)`.
* Pliki CA zapisywane są w katalogu `pki_data/` (klucz prywatny CA jest chroniony i wykluczony w `.gitignore`).

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
| **Kryptografia** | Python `cryptography` (X.509 / hazmat) | Generowanie kluczy RSA (4096/2048 bit), tworzenie i podpisywanie certyfikatów X.509, formatowanie PEM/PKCS#8, SHA-256 fingerprint |
| **Baza Danych** | PostgreSQL 15, asyncpg | Relacyjny magazyn węzłów, certyfikatów X.509, fingerprintów i wpisów unieważnień |
| **Frontend** | React 18, Vite, Tailwind CSS | Nowoczesny, responsywny dashboard operatorski z obsługą ról |
| **Konteneryzacja** | Docker, Docker Compose | Powtarzalne, izolowane środowisko uruchomieniowe |

---

## Uruchomienie
```bash
docker compose up --build -d
```


### Dostęp do usług (Rozdzielona Architektura)

| Usługa | Adres URL | Kontener | Opis |
| :--- | :--- | :--- | :--- |
| **Panel Administratora (Frontend)** | [http://localhost:3000](http://localhost:3000) | `pki-admin-frontend` | Zarządzanie Root CA, wystawianie certyfikatów, rejestr CRL |
| **Backend Administratora (API)** | [http://localhost:5000/docs](http://localhost:5000/docs) | `pki-admin-backend` | REST API Root CA z dostępem do klucza prywatnego CA |
| **Portal Klienta (Frontend)** | [http://localhost:3001](http://localhost:3001) | `pki-client-frontend` | Portal samoobsługowy dla węzłów brzegowych / użytkowników |
| **Backend Klienta (API)** | [http://localhost:5001/docs](http://localhost:5001/docs) | `pki-client-backend` | Publiczne API weryfikacji i pobierania poświadczeń (bez klucza CA!) |
| **Baza Danych PostgreSQL** | `localhost:5433` (wewn. `5432`) | `pki-db` | Relacyjny magazyn węzłów i certyfikatów |

---

## Scenariusz Demonstracyjny

Aplikacja została zaprojektowana z myślą o czytelnej demonstracji działania PKI:

1. **Przegląd Węzłów i Tożsamości:**
   * Po wejściu na stronę główną widoczne są kluczowe metryki: całkowita liczba użytkowników, aktywne certyfikaty oraz liczba kluczy na liście odwołań (CRL).
2. **Rejestracja nowego węzła:**
   * W formularzu *„Add New User”* 
3. **Wydanie certyfikatu X.509:**
   * Kliknij przycisk **„Issue Certificate”** przy utworzonym użytkowniku.
   * System wygeneruje klucz RSA 2048-bit, podpisze certyfikat kluczem Root CA i zwróci certyfikat wraz z jednorazowym kluczem prywatnym.
4. **Weryfikacja w Rejestrze Certyfikatów:**
   * Przejdź do zakładki *„Certificate Registry”*, aby zobaczyć pełną historię poświadczeń wraz ze znacznikami czasu, numerami seryjnymi i fingerprintami.
5. **Unieważnienie certyfikatu (CRL):**
   * Wybierz **„Revoke”** przy aktywnym użytkowniku, podaj przyczynę (np. *„Key Compromise / Token lost”*) i zatwierdź.
   * Certyfikat natychmiast zmienia status na `Revoked (CRL)` z zapisanym powodem i datą wycofania.

---

## Podstawowe Endpointy API

| Metoda | Ścieżka | Opis |
| :---: | :--- | :--- |
| `GET` | `/api/users` | Pobranie listy zarejestrowanych węzłów i użytkowników ze statusem certyfikatu |
| `POST` | `/api/users` | Rejestracja nowego węzła w systemie |
| `DELETE`| `/api/users/{id}` | Usunięcie węzła wraz z kaskadowym wyczyszczeniem jego certyfikatów |
| `GET` | `/api/certificates` | Pobranie rejestru wszystkich certyfikatów (PEM, fingerprint, daty ważności, status) |
| `POST` | `/api/certificates` | Wystawienie certyfikatu X.509 podpisanego przez Root CA (zwraca certyfikat i klucz prywatny) |
| `POST` | `/api/certificates/revoke` | Unieważnienie certyfikatu i aktualizacja rejestru odwołań (CRL) |
| `GET` | `/api/certificates/ca/download` | Pobranie certyfikatu Root CA (`ca_certificate.pem`) do instalacji na węzłach polowych |
| `GET` | `/api/certificates/crl/download` | Pobranie aktualnej listy odwołań (`crl.pem`) do weryfikacji offline |
| `GET` | `/api/health` | Status działania serwera backendowego |
| `GET` | `/docs` | Interaktywna dokumentacja Swagger UI |

---

## Demonstracja Uwierzytelniania Offline (Radio / Maszyna Wirtualna)

W katalogu `scripts/` przygotowano gotowe narzędzia demonstracyjne symulujące handshake i autoryzację węzłów w odciętym środowisku (fale radiowe / brak Internetu):

1. **Weryfikacja OpenSSL (uniwersalna, bez zależności):**
   ```bash
   bash scripts/demo_offline_auth.sh
   # Lub z własnymi pobranymi plikami:
   bash scripts/demo_offline_auth.sh node_cert.pem node_private.key ca_certificate.pem crl.pem
   ```

2. **Weryfikacja Python (z biblioteką cryptography):**
   ```bash
   python3 scripts/demo_offline_auth.py --cert node_cert.pem --key node_private.key --ca ca_certificate.pem --crl crl.pem
   ```


