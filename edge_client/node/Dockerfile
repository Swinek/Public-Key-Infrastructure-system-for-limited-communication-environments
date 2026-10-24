FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iproute2 \
    iputils-ping \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
# Offline verifier shared with the edge app (single source: edge_app/pki), build context "pki" in docker-compose.edge.yml.
COPY --from=pki . ./pki/

EXPOSE 8000

CMD ["uvicorn", "client_node:app", "--host", "0.0.0.0", "--port", "8000"]
