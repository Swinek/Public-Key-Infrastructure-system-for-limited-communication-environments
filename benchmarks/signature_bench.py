#!/usr/bin/env python3
"""
Pomiar rozmiarów i szybkości podpisu RSA oraz ECDSA (materiał do podrozdziału 4.3.4 pracy).

Mierzone algorytmy: RSA-2048, RSA-3072 (PKCS #1 v1.5) i ECDSA P-256, wszystkie z SHA-256.
  - szybkość: `openssl speed -mr` (podpisy/s i weryfikacje/s, jeden wątek), powtórzone
    --runs razy; w podsumowaniu mediana z przebiegów,
  - rozmiary: klucz publiczny w DER (SubjectPublicKeyInfo) i podpis, wyznaczone biblioteką
    cryptography; dla ECDSA min/max z --samples podpisów (DER ma zmienną długość).

Wyniki trafiają do --out (domyślnie benchmarks/results/):
  <znacznik>_speed_raw.csv  – każdy przebieg osobno,
  <znacznik>_summary.csv    – podsumowanie (tabela do pracy),
  <znacznik>_env.txt        – środowisko pomiaru (OpenSSL, CPU, wersje).

Użycie (z katalogu projektu, w WSL):
    docker compose --profile test run --rm tests python benchmarks/signature_bench.py [--runs 5] [--seconds 2]
"""

import argparse
import csv
import os
import platform
import re
import statistics
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

# Nazwa algorytmu -> (nazwa w `openssl speed`, poziom bezpieczeństwa wg NIST SP 800-57)
ALGORITHMS = {
    "RSA-2048": ("rsa2048", 112),
    "RSA-3072": ("rsa3072", 128),
    "ECDSA P-256": ("ecdsap256", 128),
}

# Wiersze -mr: +F2 = RSA, +F4 = ECDSA; pola: indeks, bity, podpisy/s, weryfikacje/s[, ...]
SPEED_LINE = re.compile(r"^\+F([24]):\d+:(\d+):([\d.]+):([\d.]+)")
SPEED_KEY = {("2", "2048"): "RSA-2048", ("2", "3072"): "RSA-3072", ("4", "256"): "ECDSA P-256"}

MESSAGE = b"x" * 100


def run_openssl_speed(seconds: int) -> dict[str, tuple[float, float]]:
    cmd = ["openssl", "speed", "-seconds", str(seconds), "-mr"] + [n for n, _ in ALGORITHMS.values()]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    result = {}
    for line in out.splitlines():
        m = SPEED_LINE.match(line)
        if m and (m[1], m[2]) in SPEED_KEY:
            result[SPEED_KEY[(m[1], m[2])]] = (float(m[3]), float(m[4]))
    missing = set(ALGORITHMS) - set(result)
    if missing:
        sys.exit(f"Brak wyników openssl speed dla: {', '.join(sorted(missing))}")
    return result


def measure_sizes(samples: int) -> dict[str, tuple[int, int, int]]:
    """Algorytm -> (klucz publiczny DER, min. podpis, maks. podpis) w bajtach."""
    def spki_len(key) -> int:
        return len(key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))

    sizes = {}
    for name, bits in (("RSA-2048", 2048), ("RSA-3072", 3072)):
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        sig = len(key.sign(MESSAGE, padding.PKCS1v15(), hashes.SHA256()))
        sizes[name] = (spki_len(key), sig, sig)
    key = ec.generate_private_key(ec.SECP256R1())
    lengths = [len(key.sign(MESSAGE, ec.ECDSA(hashes.SHA256()))) for _ in range(samples)]
    sizes["ECDSA P-256"] = (spki_len(key), min(lengths), max(lengths))
    return sizes


def environment() -> list[str]:
    cpu = platform.processor() or "?"
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    openssl = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout.strip()
    return [
        f"data: {datetime.now().isoformat(timespec='seconds')}",
        f"procesor: {cpu} (logicznych rdzeni: {os.cpu_count()}, pomiar na jednym wątku)",
        f"openssl: {openssl}",
        f"cryptography: {cryptography.__version__} ({default_backend().openssl_version_text()})",
        f"python: {platform.python_version()}",
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--runs", type=int, default=5, help="liczba przebiegów openssl speed (domyślnie 5)")
    parser.add_argument("--seconds", type=int, default=2, help="czas pomiaru jednej operacji w s (domyślnie 2)")
    parser.add_argument("--samples", type=int, default=2000, help="liczba podpisów ECDSA do rozmiaru (domyślnie 2000)")
    parser.add_argument("--out", type=Path, default=Path(__file__).parent / "results")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    env = environment()
    print("\n".join(env))

    raw = []
    for run in range(1, args.runs + 1):
        print(f"Przebieg {run}/{args.runs}...", flush=True)
        for name, (sign, verify) in run_openssl_speed(args.seconds).items():
            raw.append((run, name, sign, verify))
    sizes = measure_sizes(args.samples)

    with open(args.out / f"{stamp}_speed_raw.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["run", "algorithm", "sign_per_s", "verify_per_s"])
        w.writerows((r, n, f"{s:.1f}", f"{v:.1f}") for r, n, s, v in raw)

    summary = []
    for name, (_, level) in ALGORITHMS.items():
        signs = [s for _, n, s, _ in raw if n == name]
        verifies = [v for _, n, _, v in raw if n == name]
        spki, sig_min, sig_max = sizes[name]
        summary.append([name, level, spki, sig_min, sig_max,
                        round(statistics.median(signs)), round(statistics.median(verifies)),
                        round(min(signs)), round(max(signs)), round(min(verifies)), round(max(verifies)),
                        args.runs])
    with open(args.out / f"{stamp}_summary.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["algorithm", "security_bits", "public_key_der_bytes", "signature_bytes_min",
                    "signature_bytes_max", "sign_per_s_median", "verify_per_s_median",
                    "sign_per_s_min", "sign_per_s_max", "verify_per_s_min", "verify_per_s_max", "runs"])
        w.writerows(summary)
    (args.out / f"{stamp}_env.txt").write_text(
        "\n".join(env + [f"przebiegi: {args.runs} x {args.seconds} s na operację",
                         f"próbki podpisów ECDSA: {args.samples}"]) + "\n")

    print(f"\n{'Algorytm':<12} {'Poziom':>6} {'Klucz pub.':>10} {'Podpis':>9} {'Podpisy/s':>10} {'Weryfikacje/s':>14}")
    for name, level, spki, smin, smax, sign, verify, *_ in summary:
        sig = f"{smin} B" if smin == smax else f"{smin}-{smax} B"
        print(f"{name:<12} {level:>6} {spki:>8} B {sig:>9} {sign:>10} {verify:>14}")
    print(f"\nZapisano: {args.out}/{stamp}_*.csv, {stamp}_env.txt (mediana z {args.runs} przebiegów)")


if __name__ == "__main__":
    main()
