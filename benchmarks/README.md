# Pomiary

Pomiary wykorzystywane w pracy. Uruchamiane w kontenerze testowym (`tests`: Python, cryptography,
OpenSSL), z katalogu projektu w WSL.

## Podpis RSA a ECDSA (`signature_bench.py`, podrozdział 4.3.4)

Rozmiar klucza publicznego (DER) i podpisu oraz liczba podpisów i weryfikacji na sekundę
(`openssl speed`, jeden wątek) dla RSA-2048, RSA-3072 i ECDSA P-256 z SHA-256.

```bash
docker compose --profile test run --rm tests python benchmarks/signature_bench.py
```

Opcje: `--runs` (liczba przebiegów, domyślnie 5), `--seconds` (czas jednej operacji, domyślnie 2),
`--samples` (liczba podpisów ECDSA do wyznaczenia rozmiaru, domyślnie 2000).

Wyniki w `results/`, z prefiksem daty i godziny pomiaru:

- `*_summary.csv` – podsumowanie (mediana, min. i maks. z przebiegów) – źródło tabeli w pracy,
- `*_speed_raw.csv` – każdy przebieg osobno,
- `*_env.txt` – środowisko pomiaru (procesor, wersje OpenSSL i cryptography).

Szybkość zależy od procesora i zasilania (laptop na baterii jest wolniejszy), dlatego
w pracy należy podawać środowisko z `*_env.txt`. Rozmiary nie zależą od sprzętu.
