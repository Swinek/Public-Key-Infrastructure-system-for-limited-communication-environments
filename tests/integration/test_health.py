"""Testy integracyjne – wymagają `docker compose up --build -d`.

Uruchamianie: pytest -m docker
(w kontenerze testów adresy usług biorą się z ADMIN_URL / PORTAL_URL).
"""

import os

import httpx
import pytest

pytestmark = pytest.mark.docker


@pytest.mark.parametrize("url", [
    os.getenv("ADMIN_URL", "http://localhost:5000") + "/api/health",  # CA (admin)
    os.getenv("PORTAL_URL", "http://localhost:5001") + "/api/health",  # portal klienta
])
def test_health(url):
    response = httpx.get(url, timeout=5.0)
    assert response.status_code == 200
