"""Wspólne fixture testów – szczegóły w tests/helpers.py."""

import sys

import pytest

from tests.helpers import purge_colliding_modules, use_component


@pytest.fixture
def component_importer():
    """Fixture zwracająca ``use_component`` i sprzątająca sys.path/sys.modules po teście."""
    saved_path = list(sys.path)
    yield use_component
    sys.path[:] = saved_path
    purge_colliding_modules()
