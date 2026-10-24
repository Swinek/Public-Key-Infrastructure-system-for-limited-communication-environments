"""Fixture dla testów edge_app/ (Edge app – użytkownik certyfikatu).

Dane PKI aplikacji trafiają do DATA_DIR – przed importem modułów trzeba
przekierować go do katalogu tymczasowego.
"""

from __future__ import annotations

import sys

import pytest

from tests.helpers import purge_colliding_modules, use_component


@pytest.fixture
def edge_app_env(tmp_path, monkeypatch):
    """Ustawia katalog danych aplikacji na tmp i przygotowuje import modułów edge_app/.

    Zwraca katalog tymczasowy; moduły (np. ``config``) importuje sam test.
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    saved_path = list(sys.path)
    use_component("edge_app")
    yield tmp_path
    sys.path[:] = saved_path
    purge_colliding_modules()
