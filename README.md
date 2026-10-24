# System generowania i dystrybucji certyfikatów cyfrowych w systemie o ograniczonej łączności sieciowej

Praca inżynierska. System PKI (Root CA, certyfikaty X.509, listy odwołań CRL) dla sieci, w której węzły
**nie mają stałego dostępu do centrum** – mogą być odcięte nawet przez kilka dni i kontaktują się ze sobą tylko
przez wolne łącza radiowe P2P. Węzeł musi wtedy:

- **zweryfikować certyfikat offline** – łańcuch do Root CA, okres ważności, status w ostatniej otrzymanej CRL,
- **dostać nową CRL pośrednio** – od sąsiada, który ma internet albo dostał ją od kogoś innego (store-and-forward),
- **uzyskać własny certyfikat bez internetu** – wniosek CSR idzie przez sąsiadów do CA, a certyfikat wraca tą
  samą drogą,
- **nie ufać pośrednikom** – wszystko, co przychodzi przez inne węzły, jest podpisane przez CA (CRL, certyfikat)
  albo przez sam węzeł (CSR) i sprawdzane przed użyciem.

---

## Spis treści

1. [Architektura](#architektura)
2. [Szybki start](#szybki-start)
3. [Adresy usług](#adresy-usług)
4. [Panel administratora (CA)](#panel-administratora-ca)
5. [Edge Client Console (węzeł)](#edge-client-console-węzeł)
6. [Sterowanie łącznością](#sterowanie-łącznością) – internet (WAN) i sieć P2P
7. [Wymiana danych przy kontakcie](#wymiana-danych-przy-kontakcie)
8. [Nadawanie certyfikatów przez CSR](#nadawanie-certyfikatów-przez-csr)
9. [Odwoływanie certyfikatów i dystrybucja CRL](#odwoływanie-certyfikatów-i-dystrybucja-crl)
10. [Wiadomości i pliki (store-and-forward)](#wiadomości-i-pliki-store-and-forward)
11. [Pomiary przesłanych bajtów](#pomiary-przesłanych-bajtów)
12. [Edge App](#edge-app)
13. [Bezpieczeństwo – zasady](#bezpieczeństwo--zasady)
14. [Ściąga `client.sh`](#ściąga-clientsh)
15. [Testy](#testy)
16. [Struktura repozytorium](#struktura-repozytorium)
17. [API](#api)

---

## Architektura

System składa się z dwóch osobnych części uruchamianych dwoma plikami Docker Compose:

```
                CENTRUM (docker-compose.yml)                                 WĘZŁY (docker-compose.edge.yml)
 ┌──────────────────────────────────────────────────────┐
 │  Panel administratora  :3000  (React)                │
 │          │                                           │
 │  Backend CA  :5000  ── klucz prywatny Root CA        │
 │          │  podpisuje certyfikaty i CRL              │
 │  PostgreSQL :5433  ── NOTIFY crl_issued / cert_issued│
 │          │                                           │
 │  Portal (backend Edge client) :5001                  │      internet on/off        ┌──────────┐
 │  tylko odczyt bazy + przyjmowanie wniosków CSR       │◄──────── internet_net ─────►│ client_N │
 └──────────────────────────────────────────────────────┘    (łącze WAN, sterowane)   └──────────┘

                         client_1 ──p2p_12── client_2 ──p2p_23── client_3       (łącza radiowe, sterowane)
                         (+ dowolne łącze na żądanie, np. p2p_13)
```

| Komponent | Katalog | Rola |
| :--- | :--- | :--- |
| **Panel administratora** | `admin/frontend` (port 3000) | Węzły, certyfikaty, odwołania, CRL, zatwierdzanie wniosków CSR |
| **Backend CA** | `admin/backend` (port 5000) | Jedyne miejsce z kluczem prywatnym Root CA: podpisuje certyfikaty i CRL |
| **Portal** | `edge_client/backend` (port 5001, bez UI) | Publikuje Root CA, CRL i certyfikaty dla węzłów przez WAN, przyjmuje wnioski CSR. Konto bazy tylko do odczytu (wyjątek: dopisywanie wniosków) – niczego nie podpisuje |
| **Edge client N** | `edge_client/node` (kontenery `client_1..3`, konsola 3011–3013) | Węzeł brzegowy: trzyma swój certyfikat, Root CA i CRL, sprawdza je offline, rozprowadza dane PKI do sąsiadów, wiadomości i pliki |
| **Edge app N** | `edge_app` (kontenery `app_1..3`, 8001–8003) | Aplikacja używająca certyfikatu – zob. [Edge App](#edge-app) |
| **Łączność** | `client.sh` | Sterowanie łączem WAN każdego węzła i łączami radiowymi między węzłami |

Kryptografia: Root CA i certyfikaty węzłów to **ECDSA P-256 + SHA-256** (mniejsze podpisy i CRL niż RSA – ważne
na wolnych łączach), certyfikaty X.509 z SKI/AKI/KeyUsage, CRL z `CRLNumber`, obiekty przesyłane w DER.
Root CA ważny 10 lat, certyfikat węzła 1 rok, CRL ważna `CRL_VALIDITY_HOURS` (domyślnie 168 h = 7 dni)
i podpisywana na nowo przy każdym odwołaniu, ręcznie albo co `CRL_REISSUE_HOURS` (24 h).

---

## Szybki start

Wszystko działa w Dockerze (w WSL / Linuksie), nic nie trzeba instalować lokalnie.

```bash
docker compose up --build -d     # centrum: baza, backend CA, portal, panel administratora
./client.sh up                   # węzły client_1..3 (+ app_1..3), domyślnie BEZ internetu
./client.sh status               # stan węzłów i łączy radiowych
```

`./client.sh up` przy starcie liczy odcisk publicznego certyfikatu Root CA (`admin/backend/pki_data/ca_certificate.pem`)
i zapisuje go jako `CA_FINGERPRINT` w `.env` – węzły przyjmą **tylko** ten Root CA (przypięcie przy wdrożeniu).
`./client.sh up --online` startuje węzły od razu z internetem.

Pierwszy certyfikat węzła:

```bash
./client.sh internet on 1        # client_1 łączy się z portalem, pobiera Root CA i CRL, wysyła wniosek CSR
# Panel administratora → zakładka „Wnioski CSR” → „Zatwierdź”
./client.sh certs 1              # certyfikat zainstalowany, werdykt offline: valid
```

---

## Adresy usług

| Usługa | Adres | Kontener |
| :--- | :--- | :--- |
| **Panel administratora** | http://localhost:3000 | `pki-admin-frontend` |
| Backend CA (Swagger) | http://localhost:5000/docs | `pki-admin-backend` |
| Portal dla węzłów (Swagger) | http://localhost:5001/docs | `pki-edge-client-backend` |
| **Edge Client Console 1–3** | http://localhost:3011, :3012, :3013 (Swagger: `/docs`) | `client_1..3` |
| Edge App 1–3 | http://localhost:8001, :8002, :8003 | `app_1..3` |
| PostgreSQL | `localhost:5433` | `pki-db` |

---

## Panel administratora (CA)

http://localhost:3000 – stanowisko operatora urzędu certyfikacji. Na górze liczniki: użytkownicy / węzły,
aktywne certyfikaty, liczba wpisów na CRL. Trzy zakładki:

### „Users & Edge Nodes”
Lista zarejestrowanych węzłów z ich aktualnym certyfikatem (numer seryjny, ważność, status).
- **Revoke** – odwołanie certyfikatu węzła: podajesz przyczynę (np. utrata klucza), CA od razu podpisuje nową CRL
  i rozsyła ją do węzłów (zob. [Odwoływanie certyfikatów](#odwoływanie-certyfikatów-i-dystrybucja-crl)).
- Węzeł pojawia się na liście sam, gdy administrator zatwierdzi jego pierwszy wniosek CSR (CN wniosku = nazwa
  węzła). Ręcznie węzły można dodać przez `POST /api/users` (Swagger CA).

### „PKI / CRL”
Root CA (podmiot, algorytmy, ważność, odcisk SHA-256 – ten sam, który węzły mają przypięty) i bieżąca CRL:
numer `CRLNumber`, `thisUpdate` / `nextUpdate`, liczba odwołanych certyfikatów, rozmiar w DER i PEM. Przyciskiem
można ręcznie podpisać nową CRL (np. żeby przedłużyć `nextUpdate`) – trafi do węzłów tak samo jak po odwołaniu.

### „Wnioski CSR”
Wnioski o certyfikat złożone przez węzły – **każdy wymaga decyzji administratora**:
- kolumny: węzeł (CN), odcisk klucza publicznego (SHA-256), data, status `PENDING` / `APPROVED` / `REJECTED`,
- wniosek przyniesiony przez sąsiadów ma pod nazwą węzła **trasę**, np. *przez client_3 → client_2 → client_1*,
  oraz pełny odcisk klucza,
- **Zatwierdź** – CA podpisuje certyfikat na klucz z wniosku, odwołuje poprzedni certyfikat węzła (nowa CRL)
  i budzi węzły online, które pobierają certyfikat,
- **Odrzuć** – z podaniem powodu; węzeł nie wysyła wtedy wniosku ponownie sam.

---

## Edge Client Console (węzeł)

http://localhost:3011 (client_1), :3012 (client_2), :3013 (client_3) – konsola operatora węzła. W nagłówku
nazwa węzła i jego stan. Dwie zakładki:

### „Certificates”
- **Certificate** – certyfikat węzła (podmiot, numer seryjny, ważność) z **werdyktem offline** `VALID` /
  `REVOKED` / `INVALID` / `UNKNOWN` liczonym lokalnie z przechowywanego Root CA i CRL, plus numer i ważność CRL.
  Przycisk pobrania certyfikatu (PEM, bez klucza).
- **Certificate request** – stan wniosku: `NEW` (jeszcze nie wysłany), `RELAYED` (w drodze przez sąsiadów),
  `PENDING` (w CA), `REJECTED`, wraz z **pełnym odciskiem klucza** – ten sam odcisk widzi administrator.
  Przycisk **„New key + request”** generuje nowy klucz i wniosek (np. po odrzuceniu).
- **CRL from removable media** – wgranie CRL z nośnika (np. pendrive); przyjęta tylko, jeśli podpisał ją
  przypięty Root CA i ma wyższy numer niż obecna.
- **Check offline** – sprawdzenie dowolnego certyfikatu (plik) albo własnego, bez sieci; opcjonalnie w podanej
  chwili czasu.

### „Radio neighbours”
Sąsiedzi aktualnie w zasięgu radiowym: nazwa, id, adres na łączu i od kiedy są połączeni. Lista zmienia się
na żywo po `link up` / `link down`.

Nie ma wgrywania certyfikatu, klucza ani Root CA – klucz powstaje w węźle i nigdy go nie opuszcza, certyfikat
przychodzi z CA, Root CA jest przypięty.

---

## Sterowanie łącznością

Całą łącznością steruje `client.sh` (to „Łączność” z diagramu architektury). **Nic nie dzieje się samo z siebie:**
nie ma timerów, okresowych beaconów, pingów ani symulowanych opóźnień. Topologię zmieniasz wyłącznie poleceniami
poniżej, a każda zmiana jest *kontaktem*, przy którym węzły wymieniają dane. Dzięki temu demonstracja jest
w pełni powtarzalna.

### Internet (łącze WAN do centrum)

```bash
./client.sh internet on 1        # client_1 dostaje internet
./client.sh internet on all      # wszystkie węzły
./client.sh internet off 2       # client_2 traci internet
./client.sh internet-check 3     # czy client_3 widzi portal ("has_internet": true/false)
```

Jak to działa:
- Portal jest na stałe podłączony do sieci Docker `internet_net`. Węzeł **nie** jest – dopóki nie wykonasz
  `internet on`.
- `internet on N` podłącza kontener `client_N` do `internet_net` (`docker network connect`) i wysyła mu
  `POST /api/contact/wan` – to jest *kontakt WAN*: węzeł od razu pobiera od portalu to, czego mu brakuje
  (Root CA, nowszą CRL), wysyła / sprawdza swój wniosek CSR i przekazuje wnioski niesione dla innych.
  Ponowne `internet on` przy włączonym internecie wywołuje kontakt jeszcze raz.
- Portal zapamiętuje węzły, które się z nim kontaktowały, jako **online**. Gdy CA wyda nową CRL albo zatwierdzi
  wniosek, portal sam „budzi” węzły online (impuls `POST /api/contact/wan`), więc nowe dane trafiają do nich
  od razu, bez żadnej komendy.
- `internet off N` odłącza węzeł od `internet_net`. Węzeł działa dalej offline na danych, które ma.
- Domyślnie po `./client.sh up` wszystkie węzły są **bez internetu**.

### Sieć P2P (łącza radiowe między węzłami)

```bash
./client.sh links                # jakie łącza istnieją i kto w nich jest
./client.sh link down 2 3        # zerwanie łącza client_2 ↔ client_3 (client_3 odcięty)
./client.sh link up 2 3          # przywrócenie łącza
./client.sh link up 1 3          # nowe łącze client_1 ↔ client_3 (sieć p2p_13 tworzona na żądanie)
./client.sh p2p-test             # test łączności do wszystkich sąsiadów
```

Jak to działa:
- Na starcie łącza tworzą łańcuch `client_1 ──p2p_12── client_2 ──p2p_23── client_3`.
- Każde łącze radiowe to osobna sieć Docker `p2p_<ab>` typu `internal` (bez internetu), adresy
  `192.168.<ab>.0/24`, węzeł N ma adres `192.168.<ab>.N0`. Łącze między dowolną parą można utworzyć
  i zerwać – `link up/down` podłącza / odłącza oba kontenery od tej sieci.
- **Węzeł nie zna topologii.** Przy zestawieniu łącza węzeł wysyła na nim **jeden** pakiet UDP *hello*
  (port 8999: id, nazwa, port), a sąsiad odpowiada **jednym** *hello-ack*. To wystarcza, żeby obie strony
  wiedziały o sobie – potem po łączu nie krąży nic. Odebrane hello / hello-ack to *kontakt radiowy*:
  obie strony od razu wymieniają dane (CRL, wnioski, certyfikaty, wiadomości).
- Po `link down` węzeł traci interfejs sieciowy, więc sąsiad znika z listy od razu (sprawdzane lokalnie).
- Ruch między węzłami idzie **tylko** przez łącza radiowe – gateway konsol (`mgmt_N`) nie tworzy mostu między
  nimi.

Typowe topologie do demonstracji:

```bash
# client_3 odcięty od wszystkich
./client.sh link down 2 3
# tylko client_1 ma internet, pozostałe dostają dane łańcuchem 1 → 2 → 3
./client.sh internet off all; ./client.sh internet on 1
# trójkąt – dwie drogi do client_3
./client.sh link up 1 3
```

---

## Wymiana danych przy kontakcie

Kontakt to: `internet on` / impuls z portalu (WAN), hello przy zestawieniu łącza (radio) oraz **announce** –
krótka wiadomość od sąsiada „mam nowe dane”, po której odbiorca od razu pobiera je od niego. Przy każdym
kontakcie węzeł **sam pobiera** od drugiej strony (zasada *pull*) i sprawdza dane przed zapisaniem:

1. **PKI** – `GET /pki/summary` (numer i rozmiar CRL, odcisk CA), potem tylko brakujący obiekt: CRL o wyższym
   `CRLNumber`, Root CA gdy go nie ma. Węzeł udostępnia sąsiadom te same `/pki/summary|ca|crl` co portal, więc
   kod jest jeden dla WAN i radia. Przed zapisem: podpis przypiętego Root CA, wyższy numer, limity rozmiaru.
2. **Store-and-forward** – wymiana listy znanych identyfikatorów i pobranie tylko brakujących elementów:
   wiadomości, plików, wniosków CSR i certyfikatów niesionych dla innych węzłów.
3. **Własny certyfikat** – wysłanie / sprawdzenie wniosku CSR (przez WAN albo przez sąsiadów).
4. **Wnioski niesione dla innych** (tylko WAN) – przekazanie ich do portalu i odebranie decyzji CA.

Gdy węzeł dostanie coś nowego, ogłasza to pozostałym sąsiadom (announce), więc dane rozchodzą się łańcuchem
natychmiast – bez czekania na kolejną zmianę topologii. Podgląd kontaktów i wyników wymian:
`./client.sh contacts N`.

---

## Nadawanie certyfikatów przez CSR

Klucz prywatny węzła **nigdy nie podróżuje**. Węzeł sam generuje klucz EC P-256 i wniosek PKCS#10 (CSR) z
`CN = NODE_ID`, a CA zwraca tylko certyfikat. Wniosek i certyfikat to dane publiczne – mogą przejść przez
dowolnych pośredników.

### Kiedy węzeł składa wniosek
- automatycznie, gdy nie ma certyfikatu, jego certyfikat jest odwołany / nie od tego CA albo wygasa w ciągu
  `RENEW_BEFORE_DAYS` (30) dni,
- ręcznie: `./client.sh csr N` albo przycisk **„New key + request”** w konsoli (np. po odrzuceniu).

Do czasu zatwierdzenia nowego wniosku węzeł używa dotychczasowego certyfikatu.

### Wariant A – węzeł z internetem

```bash
./client.sh internet on 1        # client_1 wysyła wniosek do portalu → status PENDING
# Panel administratora → „Wnioski CSR” → „Zatwierdź”
#   CA podpisuje certyfikat, portal budzi client_1, który pobiera i instaluje certyfikat
./client.sh certs 1
```

### Wariant B – węzeł bez internetu (przez sąsiadów)

```bash
./client.sh internet off all; ./client.sh internet on 1     # internet tylko na client_1, łańcuch 1 ↔ 2 ↔ 3
./client.sh csr 3                # client_3: nowy klucz + wniosek → status RELAYED
#   wniosek idzie 3 → 2 → 1 jako element store-and-forward; client_1 (ma internet) od razu oddaje go do portalu
# Panel administratora → „Wnioski CSR”: wniosek client_3 z trasą „przez client_3 → client_2 → client_1”
#   porównaj odcisk klucza z konsolą client_3 (:3013) → „Zatwierdź”
#   portal budzi client_1 → pobiera certyfikat → odsyła go 1 → 2 → 3
./client.sh certs 3              # certyfikat zainstalowany u client_3, który nadal nie ma internetu
./client.sh stats all            # ile bajtów kosztował wniosek i certyfikat na każdym skoku
```

Co się dzieje po drodze:
- **Każdy pośrednik sprawdza dane, zanim przyjmie je do kolejki** – wniosek: poprawny podpis CSR i CN równe
  węzłowi, który go wysłał; certyfikat: podpis przypiętego Root CA i CN równe adresatowi. Śmieci nie zajmują
  łącza na kolejnych skokach.
- Identyfikator elementu jest stały (odcisk klucza dla CSR, SHA-256 dla certyfikatu), więc kopie od kilku
  pośredników to **jeden** wniosek w CA i jeden certyfikat w sieci.
- Węzeł instaluje certyfikat **tylko na swój własny oczekujący klucz** – certyfikat na cudzy klucz jest odrzucany,
  kto by go nie przyniósł.
- Odrzucenie wniosku wraca do węzła tylko jako podpowiedź (pośrednik mógłby ją sfałszować); ostateczny status
  potwierdza własny kontakt WAN węzła.
- Jeśli węzeł dostanie internet zanim certyfikat wróci przez sąsiadów, dokończy sprawę bezpośrednio z tym
  samym kluczem.

### Dlaczego administrator porównuje odcisk klucza
Pośrednik nie jest zaufany – mógłby złożyć wniosek z `CN = client_3` i **własnym** kluczem. Dlatego każdy wniosek
wymaga zatwierdzenia, a przy wnioskach przyniesionych przez sąsiadów odcisk klucza z panelu CA należy porównać
z odciskiem w konsoli węzła **poza systemem** (np. przez radio, telefon). Zgodny odcisk = wniosek naprawdę od
tego węzła.

Po zatwierdzeniu CA odwołuje poprzedni certyfikat węzła (przyczyna *superseded*) – węzeł ma zawsze jeden
ważny certyfikat.

---

## Odwoływanie certyfikatów i dystrybucja CRL

Odwołać certyfikat może tylko CA (panel administratora), ale **informacja o odwołaniu – nowa CRL – dociera do
węzłów różnymi drogami**: przez internet, od sąsiadów, przez kilku pośredników albo z nośnika. Każda kopia jest
tym samym obiektem podpisanym przez CA, więc pośrednik nie może jej zmienić ani podsunąć starszej.

### Co powoduje odwołanie
- **Revoke** w zakładce „Users & Edge Nodes” (z przyczyną, np. kompromitacja klucza),
- zatwierdzenie nowego wniosku węzła – stary certyfikat jest odwoływany jako *superseded*,
- usunięcie węzła (`DELETE /api/users/{id}`).

Każde odwołanie od razu podpisuje nową CRL z wyższym `CRLNumber`.

### Jak CRL dociera do węzłów

```
CA: Revoke → nowa CRL (nr 63) → NOTIFY crl_issued
   → portal budzi węzły online (np. client_1)          [WAN]
      → client_1 pobiera CRL 63, ogłasza sąsiadom       [announce]
         → client_2 pobiera od client_1, ogłasza dalej   [radio]
            → client_3 pobiera od client_2               [radio]
```

Przykład – odwołanie, gdy węzeł 3 jest odcięty:

```bash
./client.sh internet off all; ./client.sh internet on 1
./client.sh link down 2 3; ./client.sh stats-reset all
# Panel administratora → Revoke wybranego certyfikatu
./client.sh certs 2              # client_2 ma już nową CRL (dostał ją od client_1 bez żadnej komendy)
./client.sh certs 3              # client_3 – jeszcze stara CRL
./client.sh link up 2 3          # kontakt radiowy: client_3 pobiera nową CRL od client_2
./client.sh cert-check 3 cert.pem   # odwołany certyfikat → REVOKED, sprawdzone offline
./client.sh stats all            # ile bajtów i skoków kosztowała dystrybucja
```

Inne drogi:
- **Dowolny węzeł z internetem** może być źródłem – CRL wchodzi do sieci przez ten węzeł, który akurat ma
  internet, i rozchodzi się od niego. Przy kilku drogach (np. trójkąt `link up 1 3`) węzeł pobiera CRL tylko raz:
  przed pobraniem porównuje numer w `summary`.
- **Nośnik** – `./client.sh crl-upload N crl.der` albo „CRL from removable media” w konsoli. CRL wgrana do
  dowolnego węzła jest od razu ogłaszana jego sąsiadom i idzie dalej tak samo jak z internetu. CRL do pobrania:
  `GET http://localhost:5000/api/certificates/crl/download?format=der`.
- **Starsza albo podrobiona CRL jest odrzucana** – liczy się podpis przypiętego Root CA i rosnący `CRLNumber`;
  węzeł zostaje przy poprzedniej.

### Weryfikacja offline
Węzeł sprawdza certyfikat lokalnie: łańcuch do przypiętego Root CA, okres ważności i status w ostatniej CRL.
Wynik: `valid`, `revoked`, `invalid` (np. obce CA, wygasły) albo `unknown` (brak aktualnych danych, np. CRL
po `nextUpdate`). Sprawdzenie: `./client.sh cert-check N [plik]`, zakładka „Check offline” albo
`POST /api/certs/verify` (opcjonalny czas `at` – sprawdzenie „na dany moment”).

---

## Wiadomości i pliki (store-and-forward)

```bash
./client.sh msg 1 3 "tekst"          # w zasięgu – bezpośrednio, inaczej do kolejki (status QUEUED)
./client.sh send-file 1 3 plik.txt
./client.sh queue all                # co który węzeł niesie dla innych
./client.sh inbox 3 | files 3        # skrzynka / odebrane pliki
```

Element dla węzła poza zasięgiem wędruje z sąsiadami (wariant epidemiczny: kopia u każdego pośrednika).
Duplikaty eliminuje wymiana list znanych identyfikatorów, rozprzestrzenianie ogranicza czas życia
`SAF_TTL_HOURS` (liczony od utworzenia, pośrednik nie może go przedłużyć) i limit skoków `P2P_MAX_HOPS`;
pętle są odrzucane, pliki sprawdzane sumą SHA-256 na każdym skoku. Tym samym mechanizmem podróżują wnioski
CSR i certyfikaty.

---

## Pomiary przesłanych bajtów

Każde wysłanie i odbiór jest zapisywane w rejestrze węzła (`transfers.jsonl`): rodzaj (`summary`, `crl_full`,
`ca_cert`, `csr`, `cert`, `msg`, `file`, `saf_offer`, `announce`), kierunek, sąsiad, `payload_bytes` (sam obiekt),
`wire_bytes` (żądanie + odpowiedź HTTP z nagłówkami) i status (`ok`, `skipped` – nie wysłano, bo druga strona już
miała, `rejected`, `aborted`).

```bash
./client.sh stats-reset all          # wyczyść przed scenariuszem
./client.sh stats all                # podsumowanie wg rodzaju, sąsiada i kierunku
./client.sh stats all csv            # każdy rekord – do tabel w pracy
```

---

## Edge App

> **W przygotowaniu – to be continued.** Edge App (`edge_app/`, kontenery `app_1..3`, porty 8001–8003) to
> aplikacja, która będzie **tylko używać** certyfikatu otrzymanego od Edge clienta swojego węzła (weryfikacja
> offline, uwierzytelnianie w odrębnym kanale). Opis zostanie uzupełniony po zakończeniu prac nad tym komponentem.

---

## Bezpieczeństwo – zasady

- Klucz prywatny Root CA (`admin/backend/pki_data/ca_private_key.pem`) istnieje **tylko** w backendzie CA – nie
  trafia do obrazu, repozytorium (`pki_data/`, `*.pem`, `*.key` w `.gitignore`) ani do innych komponentów.
  Usunięcie `pki_data/` = nowy Root CA przy następnym starcie (stare certyfikaty i przypięte odciski przestają
  pasować).
- Portal i węzły **niczego nie podpisują kluczem CA** – tylko weryfikują.
- Klucz prywatny węzła powstaje w węźle i go nie opuszcza (poza przekazaniem do Edge App tego samego węzła).
- Root CA przypięty odciskiem (`CA_FINGERPRINT`) – węzeł nie przyjmie innego CA ani od portalu, ani od sąsiada.
- Dane od pośredników są niezaufane i zawsze sprawdzane: podpis CA, rosnący numer CRL, rozmiar, SHA-256,
  podpis CSR, własny klucz przy instalacji certyfikatu. Hello na łączu radiowym nie jest uwierzytelniane – mówi
  tylko, kto jest na łączu.

---

## Ściąga `client.sh`

```bash
# cykl życia
./client.sh up [--offline|--online] | down | restart | status | links | logs [N]
# łączność
./client.sh internet on|off [1|2|3|all]
./client.sh link up|down <a> <b>
./client.sh internet-test [N] | internet-check [N] | p2p-test [N] | contacts N
# certyfikaty
./client.sh csr N                    # nowy klucz + wniosek
./client.sh certs [N]                # certyfikat, wniosek, Root CA, CRL
./client.sh cert-download N [plik]   # certyfikat (PEM, bez klucza)
./client.sh cert-check N [plik]      # weryfikacja offline
./client.sh crl-upload N crl.der     # CRL z nośnika
# wiadomości i pomiary
./client.sh msg A B "tekst" | send-file A B plik | inbox N | files N | queue [N]
./client.sh stats [N] [csv] | stats-reset [N]
./client.sh call N <ścieżka>         # dowolny endpoint węzła
```

`N` = numer węzła (1–3) albo `all`. Pełna lista: `./client.sh help`.

---

## Testy

Testy (pytest + openssl) uruchamia się w kontenerze:

```bash
docker compose --profile test run --rm tests                  # testy jednostkowe
docker compose --profile test run --rm tests pytest -m docker # testy integracyjne (wymaga działającego centrum)
```

Testy CA generują Root CA w katalogu tymczasowym – nigdy nie dotykają `admin/backend/pki_data`. Testy węzłów
podstawiają portal i łącza; `tests/edge_client/test_relay.py` symuluje trzy węzły (wniosek CSR 3 → 2 → 1 →
portal i certyfikat z powrotem, złośliwi pośrednicy).

Skrypty demonstracji weryfikacji offline przez OpenSSL / Python (wymagają działającego centrum):

```bash
bash scripts/demo_offline_auth.sh
python3 scripts/demo_offline_auth.py
```

---

## Struktura repozytorium

```
projekt_inzynierski/
├── docker-compose.yml        # centrum: PostgreSQL, backend CA, portal, panel administratora (+ sieć internet_net)
├── docker-compose.edge.yml   # węzły: client_1..3, app_1..3, gateway, sieci p2p_*, mgmt_*, app_net
├── client.sh                 # „Łączność”: internet on/off, link up/down, polecenia węzłów
├── admin/
│   ├── backend/              # CA (5000): pki/ca.py – ECDSA P-256, X.509, CRL; routers/csr.py – zatwierdzanie
│   └── frontend/             # panel administratora (3000): App.jsx, PkiPanel.jsx, CsrPanel.jsx
├── edge_client/
│   ├── backend/              # portal (5001): /pki/* dla węzłów, /pki/csr, impulsy do węzłów online (announce.py)
│   └── node/                 # Edge client (client_N, konsola 3011–3013)
│       ├── contact.py        #   wyzwalacze kontaktu (WAN, hello, announce) – bez timerów
│       ├── neighbours.py     #   sąsiedzi radiowi (hello / hello-ack)
│       ├── pki_sync.py       #   Root CA i CRL od portalu / sąsiadów
│       ├── enroll.py         #   własny klucz i wniosek CSR (WAN albo przez sąsiadów)
│       ├── relay.py          #   wnioski niesione dla innych → portal, certyfikat z powrotem
│       ├── saf.py            #   store-and-forward: wiadomości, pliki, CSR, certyfikaty
│       ├── certs.py          #   magazyn: certyfikat + klucz węzła, Root CA, CRL
│       ├── transfers.py      #   rejestr przesłanych bajtów
│       └── static/           #   Edge Client Console
├── edge_app/                 # Edge App (w przygotowaniu)
├── scripts/                  # demonstracja weryfikacji offline (OpenSSL / Python)
└── tests/                    # pytest
```

---

## API

Pełna dokumentacja: Swagger pod `/docs` każdej usługi. Najważniejsze endpointy:

| Metoda | Ścieżka | Usługa | Opis |
| :---: | :--- | :--- | :--- |
| `GET` / `POST` | `/api/users` | CA | Węzły i użytkownicy / rejestracja węzła |
| `DELETE` | `/api/users/{id}` | CA | Usunięcie węzła (certyfikat odwołany, nowa CRL) |
| `GET` | `/api/certificates` | CA | Rejestr certyfikatów |
| `POST` | `/api/certificates/revoke` | CA | Odwołanie certyfikatu i nowa CRL |
| `GET` | `/api/certificates/ca/download`, `/api/certificates/crl/download` | CA | Root CA / ostatnia CRL (`?format=der`) |
| `GET` / `POST` | `/api/pki/crl`; `GET` `/api/pki/ca`, `/api/pki/crls` | CA | Bieżąca CRL / ręczne podpisanie; Root CA, historia CRL |
| `GET` | `/api/csr` | CA | Wnioski CSR (`?status=PENDING`), z trasą `relayed_via` |
| `POST` | `/api/csr/{id}/approve`, `/api/csr/{id}/reject` | CA | Zatwierdzenie / odrzucenie wniosku |
| `GET` | `/pki/summary`, `/pki/ca`, `/pki/crl`, `/pki/certs/{serial}` | portal, węzeł | Obiekty PKI w DER; węzeł udostępnia sąsiadom to samo co portal |
| `POST` | `/pki/csr` | portal | Przyjęcie wniosku (nagłówek `X-PKI-Route` – trasa przez sąsiadów) |
| `GET` | `/pki/csr/{odcisk klucza}` | portal | Status wniosku i numer seryjny certyfikatu |
| `GET` | `/pki/online` | portal | Węzły, które dostaną impuls |
| `GET` | `/api/certs`; `POST` `/api/certs/csr`, `/api/certs/crl`, `/api/certs/verify` | węzeł | Stan certyfikatu / nowy wniosek / CRL z nośnika / weryfikacja offline |
| `POST` | `/api/contact/wan`, `/api/contact/announce`; `GET` `/api/contact/events` | węzeł | Kontakt WAN / „mam nowe dane” / historia kontaktów |
| `POST` | `/api/saf/offer`; `GET` `/api/saf/items/{id}/content`, `/api/saf/queue` | węzeł | Store-and-forward |
| `GET` / `DELETE` | `/api/stats/transfers` | węzeł | Rejestr bajtów (`?format=csv`) / wyczyszczenie |
