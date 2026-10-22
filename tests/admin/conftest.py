"""Fixture CA dla testów admin/backend.

Klucz Root CA jest generowany w katalogu tymczasowym – testy NIGDY nie mogą
dotykać realnego admin/backend/pki_data (zawiera prawdziwy klucz prywatny CA).
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.helpers import COMPONENT_DIRS, purge_colliding_modules, use_component

REAL_PKI_DIR = (COMPONENT_DIRS["admin"] / "pki_data").resolve()

CA_PATH_GLOBALS = {
    "PKI_DIR": None,
    "CA_KEY_PATH": "ca_private_key.pem",
    "CA_CERT_PATH": "ca_certificate.pem",
}


def _assert_tmp_paths(ca_module, tmp_dir: Path) -> None:
    """Upewnia się, że wszystkie ścieżki modułu CA wskazują na katalog tymczasowy."""
    tmp_dir = tmp_dir.resolve()
    for name in CA_PATH_GLOBALS:
        path = Path(getattr(ca_module, name)).resolve()
        assert path == tmp_dir or tmp_dir in path.parents, (
            f"{name}={path} nie wskazuje na katalog tymczasowy {tmp_dir}"
        )
        assert path != REAL_PKI_DIR and REAL_PKI_DIR not in path.parents, (
            f"{name}={path} wskazuje na realne pki_data!"
        )


@pytest.fixture(scope="session")
def ca_env(tmp_path_factory):
    """Zainicjalizowane Root CA (ECDSA P-256) w katalogu tymczasowym, wspólne dla sesji.

    Zwraca obiekt z polami: ``ca`` (moduł pki.ca), ``pki_dir`` (Path).
    Działa zarówno z wersją ca.py liczącą PKI_DIR na sztywno, jak i czytającą
    zmienną środowiskową ``PKI_DIR`` – wszystkie globale ścieżek są nadpisywane.
    """
    pki_dir = tmp_path_factory.mktemp("pki_data")
    saved_path = list(sys.path)
    with pytest.MonkeyPatch.context() as mp:
        # Env ustawiony przed importem – na wypadek gdy ca.py czyta PKI_DIR z env.
        mp.setenv("PKI_DIR", str(pki_dir))
        use_component("admin")
        ca = importlib.import_module("pki.ca")

        for name, filename in CA_PATH_GLOBALS.items():
            mp.setattr(ca, name, pki_dir if filename is None else pki_dir / filename)
        _assert_tmp_paths(ca, pki_dir)

        ca.initialize_ca()
        _assert_tmp_paths(ca, pki_dir)

        yield SimpleNamespace(ca=ca, pki_dir=pki_dir)

    sys.path[:] = saved_path
    purge_colliding_modules()
