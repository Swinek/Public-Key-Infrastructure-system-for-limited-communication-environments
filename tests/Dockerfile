# Obraz testów: zależności wszystkich komponentów + pytest + openssl (porównanie weryfikacji z OpenSSL).
# Kod repozytorium jest montowany jako wolumen (/repo), do obrazu trafiają tylko pliki requirements.
FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /repo
COPY requirements-dev.txt ./
COPY admin/backend/requirements.txt admin/backend/
COPY edge_client/backend/requirements.txt edge_client/backend/
COPY edge_client/node/requirements.txt edge_client/node/
COPY edge_app/requirements.txt edge_app/
RUN pip install --no-cache-dir -r requirements-dev.txt
