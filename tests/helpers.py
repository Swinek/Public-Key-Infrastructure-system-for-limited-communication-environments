"""Wspólne narzędzia testowe (import modułów komponentów).

Komponenty (admin/backend, clients/backend, edges) nie są pakietami Pythona –
ich importy absolutne zakładają, że katalog komponentu jest w sys.path
(np. ``from pki.ca import ...``, ``from database import ...``, ``import config``).
Nazwy modułów kolidują między komponentami (database, routers, main, config, ...),
dlatego przed importem z danego komponentu trzeba ustawić sys.path i usunąć
z sys.modules moduły załadowane wcześniej z innego komponentu.
"""

from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent

COMPONENT_DIRS = {
    "admin": REPO_ROOT / "admin" / "backend",
    "clients": REPO_ROOT / "clients" / "backend",
    "edges": REPO_ROOT / "edges",
}

# Moduły najwyższego poziomu, których nazwy mogą kolidować między komponentami.
COLLIDING_MODULES = (
    "database",
    "routers",
    "main",
    "schemas",
    "pki",
    "config",
    "state",
    "utils",
    "models",
    "client_node",
)


def purge_colliding_modules() -> None:
    for name in list(sys.modules):
        top = name.split(".", 1)[0]
        if top in COLLIDING_MODULES:
            del sys.modules[name]


def use_component(component: str) -> Path:
    """Przygotowuje import modułów danego komponentu.

    Usuwa z sys.path katalogi pozostałych komponentów, dodaje katalog wskazanego
    na początek i czyści z sys.modules kolidujące moduły. Zwraca katalog komponentu.
    """
    if component not in COMPONENT_DIRS:
        raise ValueError(f"Nieznany komponent: {component!r}")
    target = COMPONENT_DIRS[component]
    other = {str(p) for p in COMPONENT_DIRS.values()}
    sys.path[:] = [p for p in sys.path if p not in other]
    sys.path.insert(0, str(target))
    purge_colliding_modules()
    return target
