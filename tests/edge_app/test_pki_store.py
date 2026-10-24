"""Etap 2: lokalny magazyn PKI węzła (edge_app/pki/store.py) – przypięcie CA, instalacja, CRL, zapis atomowy."""

from __future__ import annotations

import os
import stat

import pytest

from tests.pki_factory import TestCA, der, key_pem, pem


@pytest.fixture
def store_mod(edge_app_env):
    from pki import store
    return store


@pytest.fixture
def store(store_mod, tmp_path):
    return store_mod.PkiStore(tmp_path / "pki")


@pytest.fixture(scope="module")
def ca():
    return TestCA()


@pytest.fixture(scope="module")
def node(ca):
    return ca.issue("client_1")


def test_install_stores_der_and_pins_ca(store, store_mod, ca, node):
    cert, key = node
    store.install(pem(ca.cert), pem(cert), key_pem(key))

    assert (store.root / "ca.der").read_bytes() == der(ca.cert)
    assert (store.root / "node.der").read_bytes() == der(cert)
    assert store.pinned_fingerprint() == store_mod.fingerprint(ca.cert)
    assert store.private_key().public_key() == cert.public_key()

    status = store.status()
    assert status["ca"]["fingerprint"] == status["ca"]["pinned"]
    assert status["node"]["serial_number"] == str(cert.serial_number)
    assert status["node"]["has_private_key"] and status["crl"] is None
    assert "PRIVATE" not in str(status)


@pytest.mark.skipif(os.name != "posix", reason="uprawnienia POSIX")
def test_private_key_is_owner_only(store, ca, node):
    cert, key = node
    store.install(der(ca.cert), der(cert), key_pem(key))
    assert stat.S_IMODE((store.root / "node_key.pem").stat().st_mode) == 0o600


def test_configured_pin_rejects_other_ca(store_mod, tmp_path, ca):
    store = store_mod.PkiStore(tmp_path / "pki", "AA:BB:" + "00" * 30)
    with pytest.raises(store_mod.PkiError, match="przypiętym"):
        store.install_ca(der(ca.cert))
    assert store.ca() is None


def test_configured_pin_accepts_matching_ca(store_mod, tmp_path, ca):
    fp = store_mod.fingerprint(ca.cert)
    pinned = ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)).upper()
    store = store_mod.PkiStore(tmp_path / "pki", pinned)
    store.install_ca(der(ca.cert))
    assert not (store.root / "ca.pin").exists()  # pin pochodzi z konfiguracji


def test_first_ca_is_pinned_and_cannot_be_replaced(store, store_mod, ca):
    store.install_ca(der(ca.cert))
    store.install_ca(der(ca.cert))  # ponowna instalacja tego samego CA jest dozwolona
    with pytest.raises(store_mod.PkiError):
        store.install_ca(der(TestCA("Rogue CA").cert))
    assert store.ca() == ca.cert


@pytest.mark.parametrize("kwargs", [{"ca_flag": False}, {"crl_sign": False}])
def test_rejects_certificate_that_cannot_act_as_ca(store, store_mod, kwargs):
    with pytest.raises(store_mod.PkiError):
        store.install_ca(der(TestCA(**kwargs).cert))
    assert store.ca() is None and store.pinned_fingerprint() == ""


def test_install_node_requires_ca(store, store_mod, node):
    cert, key = node
    with pytest.raises(store_mod.PkiError, match="Root CA"):
        store.install_node(der(cert), key_pem(key))


def test_install_node_rejects_foreign_certificate(store, store_mod, ca):
    store.install_ca(der(ca.cert))
    cert, key = TestCA("Foreign CA").issue("client_1")
    with pytest.raises(store_mod.PkiError):
        store.install_node(der(cert), key_pem(key))
    assert store.node_certificate() is None


def test_install_node_rejects_mismatched_key(store, store_mod, ca, node):
    store.install_ca(der(ca.cert))
    cert, _ = node
    _, other_key = ca.issue("client_2")
    with pytest.raises(store_mod.PkiError, match="nie pasuje"):
        store.install_node(der(cert), key_pem(other_key))
    assert store.node_certificate() is None and store.private_key() is None


# ---- CRL ----------------------------------------------------------------------------------------

@pytest.fixture
def ready(store, ca):
    store.install_ca(der(ca.cert))
    return store


def test_update_crl_only_accepts_newer(ready, ca, store_mod):
    assert ready.update_crl(pem(ca.crl(number=5))) is True  # PEM na wejściu, DER w magazynie
    assert store_mod.crl_number(ready.crl()) == 5
    assert ready.update_crl(der(ca.crl(number=5))) is False
    assert ready.update_crl(der(ca.crl(number=4))) is False  # podsunięta starsza lista
    assert store_mod.crl_number(ready.crl()) == 5
    assert ready.update_crl(der(ca.crl(number=6))) is True
    assert store_mod.crl_number(ready.crl()) == 6


def _forged_variants(ca):
    good = der(ca.crl(number=10))
    tampered = bytearray(good)
    tampered[-5] ^= 0xFF  # uszkodzony podpis
    return {
        "foreign_ca": der(TestCA("Foreign CA").crl(number=10)),
        "same_name_other_key": der(TestCA("Test Root CA").crl(number=10)),
        "tampered_signature": bytes(tampered),
        "truncated": good[: len(good) // 2],  # przerwany transfer
        "delta": der(ca.crl(number=10, delta_base=1)),
        "no_number": der(ca.crl(number=None)),
        "garbage": b"\x00" * 64,
    }


@pytest.mark.parametrize("variant", ["foreign_ca", "same_name_other_key", "tampered_signature", "truncated",
                                     "delta", "no_number", "garbage"])
def test_untrusted_crl_is_rejected_and_state_kept(ready, ca, store_mod, variant):
    ready.update_crl(der(ca.crl(number=2)))
    before = (ready.root / "crl.der").read_bytes()
    with pytest.raises(store_mod.PkiError):
        ready.update_crl(_forged_variants(ca)[variant])
    assert (ready.root / "crl.der").read_bytes() == before


def test_update_crl_requires_ca(store, store_mod, ca):
    with pytest.raises(store_mod.PkiError):
        store.update_crl(der(ca.crl()))


def test_crash_during_write_keeps_previous_crl(ready, ca, store_mod, monkeypatch):
    ready.update_crl(der(ca.crl(number=1)))

    def broken_replace(src, dst):
        raise OSError("zerwane łącze / awaria zasilania")

    monkeypatch.setattr(os, "replace", broken_replace)
    with pytest.raises(OSError):
        ready.update_crl(der(ca.crl(number=2)))
    monkeypatch.undo()

    assert store_mod.crl_number(ready.crl()) == 1  # poprzednia lista nienaruszona i czytelna
    assert ready.update_crl(der(ca.crl(number=2))) is True  # pozostały plik .tmp nie blokuje kolejnego zapisu
