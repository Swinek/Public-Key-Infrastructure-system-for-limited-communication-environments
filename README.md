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

### Struktura katalogów

Kod backendu zorganizowano w sposób modułowy, separując punkty wejścia API, modele walidacyjne i silnik kryptograficzny:

```text
projekt_inzynierski/
├── docker-compose.yml       # Orkiestracja kontenerów (PostgreSQL, Backend, Frontend)
├── README.md                # Główna dokumentacja projektu
├── backend/
│   ├── Dockerfile           # Obraz backendu oparty o python:3.11-slim
│   ├── requirements.txt     # Zależności (fastapi, uvicorn, asyncpg, pydantic, cryptography)
│   ├── main.py              # Inicjalizacja FastAPI, lifespan (CA + DB), CORS, rejestracja routerów
│   ├── database.py          # Asynchroniczny pool połączeń PostgreSQL (asyncpg)
│   ├── schemas.py           # Modele walidacyjne Pydantic (UserCreate, CertificateCreate, CertificateRevoke)
│   ├── init.sql             # Schemat bazy danych (tabele users, certificates)
│   ├── routers/             # Moduły punktów końcowych API
│   │   ├── __init__.py
│   │   ├── users.py         # Zarządzanie węzłami/użytkownikami (/api/users)
│   │   ├── certificates.py  # Wystawianie X.509, rejestr certyfikatów i CRL (/api/certificates)
│   │   └── health.py        # Status i kondycja serwera (/api/health)
│   └── pki/                 # Moduł kryptograficzny PKI
│       ├── __init__.py
│       └── ca.py            # Generowanie Root CA (RSA 4096) oraz certyfikatów X.509
└── frontend/
    ├── Dockerfile           # Obraz środowiska deweloperskiego Node.js
    ├── package.json         # Zależności (react, axios, lucide-react, tailwindcss)
    ├── vite.config.js       # Konfiguracja serwera deweloperskiego Vite
    ├── tailwind.config.js   # Konfiguracja Tailwind CSS
    └── src/
        ├── App.jsx          # Główny dashboard (widok administratora i stacji polowej)
        ├── main.jsx         # Punkt startowy aplikacji React
        └── index.css        # Style bazowe i dyrektywy Tailwind
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
* **Klucz prywatny użytkownika zwracany jest jednorazowo** w odpowiedzi API przy wystawieniu certyfikatu (nie jest zapisywany w centralnej bazie danych, co odpowiada dobrym praktykom bezpieczeństwa).

---

## Stos Technologiczny

| Warstwa | Technologia | Zastosowanie |
| :--- | :--- | :--- |
| **Backend** | Python 3.11, FastAPI, Uvicorn | Wydajne, asynchroniczne REST API z automatyczną dokumentacją OpenAPI / Swagger |
| **Kryptografia** | Python `cryptography` (X.509 / hazmat) | Generowanie kluczy RSA (4096/2048 bit), tworzenie i podpisywanie certyfikatów X.509, formatowanie PEM/PKCS#8, SHA-256 fingerprint |
| **Baza Danych** | PostgreSQL 15, asyncpg | Relacyjny magazyn węzłów, certyfikatów X.509, fingerprintów i wpisów unieważnień |
| **Frontend** | React 18, Vite, Tailwind CSS | Nowoczesny, responsywny dashboard operatorski z obsługą ról |
| **Ikony & UI** | Lucide Icons, Inter Font | Minimalistyczny i czytelny interfejs użytkownika |
| **Konteneryzacja** | Docker, Docker Compose | Powtarzalne, izolowane środowisko uruchomieniowe |

---

## Szybki Start (Uruchomienie)

Wymagania wstępne:
* Zainstalowany **Docker** oraz wtyczka **Docker Compose** (`docker compose version`).

### 1. Klonowanie repozytorium
```bash
git clone https://github.com/Swinek/Public-Key-Infrastructure-system-for-limited-communication-environments.git
cd Public-Key-Infrastructure-system-for-limited-communication-environments
```

### 2. Uruchomienie aplikacji w kontenerach
W katalogu głównym projektu wykonaj:

```bash
docker compose up --build -d
```

Polecenie automatycznie:
1. Pobierze i uruchomi kontener bazy danych **PostgreSQL 15** wraz z inicjalizacją schematu (`init.sql`).
2. Zbuduje i uruchomi kontener z backendem **FastAPI**, inicjalizując bazę oraz Root CA (`pki_data/`).
3. Zbuduje i uruchomi kontener z panelem frontendowym **React/Vite** na porcie `3000`.

### 3. Dostęp do usług

| Usługa | Adres URL | Opis |
| :--- | :--- | :--- |
| **Frontend)* | [http://localhost:3000](http://localhost:3000) | Główny pulpit zarządzania PKI |
|  **Backend** | [http://localhost:5000/docs](http://localhost:5000/docs) | Interaktywna dokumentacja REST API |

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
6. **Symulacja perspektywy Stacji Polowej:**
   * Użyj selektora w prawym górnym rogu (*„Logged in as:”*), aby przełączyć się z widoku Administratora na konto konkretnego użytkownika.
   * Zobacz, jak stacja końcowa widzi stan swoich poświadczeń (aktywne vs unieważnione).

---

## Podstawowe Endpointy API

| Metoda | Ścieżka | Opis |
| :---: | :--- | :--- |
| `GET` | `/api/users` | Pobranie listy zarejestrowanych węzłów i użytkowników ze statusem certyfikatu |
| `POST` | `/api/users` | Rejestracja nowego węzła w systemie |
| `DELETE`| `/api/users/{id}` | Usunięcie węzła wraz z kaskadowym wyczyszczeniem jego certyfikatów |
| `GET` | `/api/certificates` | Pobranie rejestru wszystkich certyfikatów (PEM, fingerprint, daty ważności, status) |
| `POST` | `/api/certificates` | Wystawienie certyfikatu X.509 podpisanego przez Root CA (zwraca certyfikat i klucz prywatny) |
| `POST` | `/api/certificates/revoke` | Unieważnienie certyfikatu i dodanie wpisu do rejestru odwołań (CRL) |
| `GET` | `/api/health` | Status działania serwera backendowego |
| `GET` | `/docs` | Interaktywna dokumentacja Swagger UI |

---

---

