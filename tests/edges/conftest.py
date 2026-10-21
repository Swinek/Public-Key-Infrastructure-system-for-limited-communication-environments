"""Fixture dla testów edges/ (węzeł brzegowy).

edges/config.py tworzy katalogi przy imporcie – przed importem trzeba
przekierować DATA_DIR/STORAGE_DIR do katalogu tymczasowego.
"""

from __future__ import annotations

import sys

import pytest

from tests.helpers import purge_colliding_modules, use_component


@pytest.fixture
def edges_env(tmp_path, monkeypatch):
    """Ustawia katalogi danych węzła na tmp i przygotowuje import modułów edges/.

    Zwraca katalog tymczasowy; moduły (np. ``config``) importuje sam test.
    """
    data_dir = tmp_path / "data"
    storage_dir = tmp_path / "received_files"
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("STORAGE_DIR", str(storage_dir))
    saved_path = list(sys.path)
    use_component("edges")
    yield tmp_path
    sys.path[:] = saved_path
    purge_colliding_modules()
