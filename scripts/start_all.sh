#!/usr/bin/env bash
# Uruchamia cały system: centrum (baza, CA + panel administratora, backend publikacji)
# oraz węzły: Edge client client_1..3 i Edge app app_1..3.
#   bash scripts/start_all.sh            # węzły bez internetu (domyślnie)
#   bash scripts/start_all.sh --online   # węzły od razu z łączem WAN
#   bash scripts/start_all.sh down       # zatrzymuje wszystko
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = "down" ]; then
    ./client.sh down || true
    docker compose down
    exit 0
fi

echo "[*] Centrum: baza, CA, panel administratora, backend publikacji..."
docker compose up --build -d

echo -n "[*] Czekam na CA (http://localhost:5000/api/health)"
for _ in $(seq 1 60); do
    if curl -fs http://localhost:5000/api/health >/dev/null; then echo " OK"; break; fi
    echo -n "."; sleep 2
done
curl -fs http://localhost:5000/api/health >/dev/null || { echo " CA nie odpowiada"; exit 1; }

echo "[*] Węzły: client_1..3 + app_1..3..."
./client.sh up "$@"

echo
echo "Panel administratora: http://localhost:3000"
echo "Edge client:          http://localhost:3011  3012  3013"
echo "Edge app:             http://localhost:8001  8002  8003"
