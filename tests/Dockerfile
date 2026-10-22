# Obraz testów: zależności wszystkich komponentów + pytest + openssl (porównanie weryfikacji z OpenSSL).
# Kod repozytorium jest montowany jako wolumen (/repo), do obrazu trafiają tylko pliki requirements.
FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /repo
COPY requirements-dev.txt ./
COPY admin/backend/requirements.txt admin/backend/
COPY clients/backend/requirements.txt clients/backend/
COPY edges/requirements.txt edges/
RUN pip install --no-cache-dir -r requirements-dev.txt
