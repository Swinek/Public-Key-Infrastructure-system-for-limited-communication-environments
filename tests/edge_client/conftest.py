"""Fixture dla testów edge_client/node (Edge client węzła: łącza WAN/P2P, przekazanie „cert” do Edge app).

edge_client/node/config.py tworzy katalogi przy imporcie – przed importem trzeba
przekierować DATA_DIR do katalogu tymczasowego.
"""

from __future__ import annotations

import sys

import pytest

from tests.helpers import purge_colliding_modules, use_component


@pytest.fixture
def edge_client_node_env(tmp_path, monkeypatch):
    """Ustawia katalog danych węzła na tmp i przygotowuje import modułów edge_client/node.

    Zwraca katalog tymczasowy; moduły (np. ``config``) importuje sam test.
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    saved_path = list(sys.path)
    use_component("edge_client_node")
    yield tmp_path
    sys.path[:] = saved_path
    purge_colliding_modules()
