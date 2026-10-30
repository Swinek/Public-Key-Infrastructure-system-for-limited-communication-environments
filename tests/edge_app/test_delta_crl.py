"""Podpisana baza+delta: odrzucenia, offline, atomowość i restart."""
import os
from datetime import timedelta

import pytest
from tests.pki_factory import TestCA, der, NOW


@pytest.fixture
def module(edge_app_env):
    from pki import delta
    return delta


def test_delta_offline_and_restart(module, tmp_path):
    from pki.store import PkiStore
    from pki.verifier import verify, Status
    ca = TestCA()
    revoked, _ = ca.issue("revoked")
    good, _ = ca.issue("good")
    base = ca.crl(number=1)
    delta = ca.crl(revoked=[revoked], number=3, delta_base=1)
    store = PkiStore(tmp_path)
    store.install_ca(der(ca.cert))
    store.update_crl(der(base))
    assert store.update_revocation(der(delta), "delta", 3)
    assert store.crl() == base  # nie tworzymy fałszywej podpisanej pełnej listy
    restarted = PkiStore(tmp_path)
    assert restarted.revocation_number() == 3
    assert verify(revoked, ca.cert, restarted.crl(), NOW, restarted.delta()).status == Status.REVOKED
    assert verify(good, ca.cert, restarted.crl(), NOW, restarted.delta()).status == Status.VALID
    assert not restarted.update_crl(der(ca.crl(number=2)))
    assert restarted.update_crl(der(ca.crl(number=4)))
    assert restarted.delta() is None


@pytest.mark.parametrize("case", ["missing", "newer_base", "wrong_key", "wrong_number", "truncated", "future_base"])
def test_delta_rejections_keep_state(module, tmp_path, case):
    from pki.store import PkiStore, PkiError
    ca = TestCA()
    store = PkiStore(tmp_path)
    store.install_ca(der(ca.cert))
    if case != "missing":
        store.update_crl(der(ca.crl(number=2)))
    delta = ca.crl(number=4, delta_base=3 if case == "newer_base" else 1)
    if case == "wrong_key":
        delta = TestCA().crl(number=4, delta_base=1)
    if case == "future_base":
        store.update_crl(der(ca.crl(number=5)))
    before = store.revocation_number()
    data = der(delta)[:20] if case == "truncated" else der(delta)
    with pytest.raises(PkiError):
        store.update_revocation(data, "delta", expected=10 if case == "wrong_number" else 4)
    assert store.revocation_number() == before


def test_bundle_requires_both_signatures_and_roundtrips(module, tmp_path):
    from pki.store import PkiStore, PkiError
    ca = TestCA()
    base, delta = ca.crl(number=1), ca.crl(number=2, delta_base=1)
    store = PkiStore(tmp_path)
    store.install_ca(der(ca.cert))
    assert store.update_revocation(module.encode_state(base, delta), "bundle")
    assert store.revocation_number() == 2
    with pytest.raises(PkiError):
        store.update_revocation(module.encode_state(TestCA().crl(number=1), ca.crl(number=3, delta_base=1)), "bundle")
    assert store.revocation_number() == 2


def test_delta_write_crash_keeps_signed_state(module, tmp_path, monkeypatch):
    from pki.store import PkiStore
    ca = TestCA()
    store = PkiStore(tmp_path)
    store.install_ca(der(ca.cert))
    store.update_crl(der(ca.crl(number=1)))
    def crash(*args):
        raise OSError("przerwany zapis")
    monkeypatch.setattr(os, "replace", crash)
    with pytest.raises(OSError):
        store.update_revocation(der(ca.crl(number=2, delta_base=1)), "delta")
    assert PkiStore(tmp_path).revocation_number() == 1


def test_new_delta_replaces_previous_cumulative_delta(module, tmp_path):
    from pki.store import PkiStore
    from pki.verifier import verify, Status
    ca = TestCA()
    first, _ = ca.issue("one")
    second, _ = ca.issue("two")
    store = PkiStore(tmp_path)
    store.install_ca(der(ca.cert))
    store.update_crl(der(ca.crl(number=2)))
    store.update_revocation(der(ca.crl([first], number=3, delta_base=1)), "delta")
    store.update_revocation(der(ca.crl([first, second], number=4, delta_base=1)), "delta")
    for cert in (first, second):
        assert verify(cert, ca.cert, store.crl(), NOW, store.delta()).status == Status.REVOKED


def test_delta_freshness_uses_signed_delta_dates(module, tmp_path):
    from pki.store import PkiStore
    from pki.verifier import verify, Status
    ca = TestCA()
    cert, _ = ca.issue("one")
    store = PkiStore(tmp_path)
    store.install_ca(der(ca.cert))
    store.update_crl(der(ca.crl(number=1, this_update=NOW-timedelta(days=4), next_update=NOW-timedelta(days=2))))
    store.update_revocation(der(ca.crl(number=2, delta_base=1)), "delta")
    assert verify(cert, ca.cert, store.crl(), NOW, store.delta()).status == Status.VALID
    assert verify(cert, ca.cert, store.crl(), NOW+timedelta(days=2), store.delta()).status == Status.UNKNOWN
