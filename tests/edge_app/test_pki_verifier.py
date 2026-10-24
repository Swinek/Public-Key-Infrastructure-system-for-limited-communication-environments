"""Etap 2: weryfikator offline edge_app/pki/verifier.py, z wynikiem porównanym z `openssl verify -crl_check`."""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime

import pytest

from tests.pki_factory import DAY, NOW, TestCA, der, pem


@pytest.fixture
def pki(edge_app_env):
    import pki
    return pki


@pytest.fixture(scope="module")
def ca():
    return TestCA()


@pytest.fixture(scope="module")
def scenarios(ca):
    """Scenariusz -> (certyfikat, CA węzła, CRL lub None, teraz, oczekiwany status)."""
    good, _ = ca.issue("client_1")
    revoked, _ = ca.issue("mallory")
    expired, _ = ca.issue("old", not_before=NOW - 30 * DAY, not_after=NOW - DAY)
    future, _ = ca.issue("future", not_before=NOW + DAY, not_after=NOW + 30 * DAY)
    crl = ca.crl(revoked=[revoked], number=7)

    foreign = TestCA("Foreign CA")
    foreign_cert, _ = foreign.issue("client_1")
    impostor = TestCA("Test Root CA")  # ta sama nazwa co zaufane CA, inny klucz
    impostor_cert, _ = impostor.issue("client_1")

    return {
        "valid": (good, ca.cert, crl, NOW, "valid"),
        "revoked": (revoked, ca.cert, crl, NOW, "revoked"),
        "expired": (expired, ca.cert, crl, NOW, "invalid"),
        "not_yet_valid": (future, ca.cert, crl, NOW, "invalid"),
        "foreign_ca": (foreign_cert, ca.cert, crl, NOW, "invalid"),
        "impostor_same_name": (impostor_cert, ca.cert, crl, NOW, "invalid"),
        "no_crl": (good, ca.cert, None, NOW, "unknown"),
        "crl_stale": (good, ca.cert, crl, NOW + 2 * DAY, "unknown"),
        "crl_from_future": (good, ca.cert, ca.crl(number=8, this_update=NOW + DAY, next_update=NOW + 2 * DAY),
                            NOW, "unknown"),
        "crl_of_foreign_ca": (good, ca.cert, foreign.crl(number=99), NOW, "unknown"),
        "crl_forged_same_name": (good, ca.cert, impostor.crl(number=99), NOW, "unknown"),
    }


SCENARIOS = ["valid", "revoked", "expired", "not_yet_valid", "foreign_ca", "impostor_same_name",
             "no_crl", "crl_stale", "crl_from_future", "crl_of_foreign_ca", "crl_forged_same_name"]


@pytest.mark.parametrize("name", SCENARIOS)
def test_verdict(pki, scenarios, name):
    cert, ca_cert, crl, now, expected = scenarios[name]
    verdict = pki.verify(cert, ca_cert, crl, now)
    assert verdict.status.value == expected, verdict.reason
    assert verdict.serial_number == str(cert.serial_number)
    assert verdict.reason


# Kody błędów `openssl verify` (X509_V_ERR_*) -> wynik weryfikatora węzła.
OPENSSL_CODES = {
    23: "revoked",                                  # certificate revoked
    7: "invalid", 9: "invalid", 10: "invalid",      # signature failure, not yet valid, expired
    20: "invalid", 21: "invalid",                   # unable to get (local) issuer
    3: "unknown", 8: "unknown",                     # unable to get CRL, CRL signature failure
    11: "unknown", 12: "unknown",                   # CRL not yet valid, CRL has expired
}


def openssl_verdict(tmp_path, cert, ca_cert, crl, now: datetime) -> str:
    (tmp_path / "ca.pem").write_bytes(pem(ca_cert))
    (tmp_path / "leaf.pem").write_bytes(pem(cert))
    cmd = ["openssl", "verify", "-attime", str(int(now.timestamp())), "-CAfile", str(tmp_path / "ca.pem"),
           "-crl_check"]
    if crl is not None:
        (tmp_path / "crl.pem").write_bytes(pem(crl))
        cmd += ["-CRLfile", str(tmp_path / "crl.pem")]
    result = subprocess.run(cmd + [str(tmp_path / "leaf.pem")], capture_output=True, text=True)
    if result.returncode == 0:
        return "valid"
    out = result.stdout + result.stderr
    for code, status in OPENSSL_CODES.items():
        if f"error {code} at" in out:
            return status
    raise AssertionError(f"Nieoczekiwany wynik openssl:\n{out}")


@pytest.mark.skipif(shutil.which("openssl") is None, reason="brak openssl")
@pytest.mark.parametrize("name", SCENARIOS)
def test_matches_openssl(pki, scenarios, tmp_path, name):
    cert, ca_cert, crl, now, expected = scenarios[name]
    assert openssl_verdict(tmp_path, cert, ca_cert, crl, now) == expected
    assert pki.verify(cert, ca_cert, crl, now).status.value == expected


def test_revoked_stays_revoked_on_stale_crl(pki, ca):
    # Odwołanie jest ostateczne: nieaktualna CRL nie potwierdza ważności, ale nadal dowodzi odwołania.
    # (openssl zgłosi tu najpierw „CRL has expired”, dlatego scenariusz jest poza porównaniem.)
    cert, _ = ca.issue("mallory")
    crl = ca.crl(revoked=[cert], number=3)
    verdict = pki.verify(cert, ca.cert, crl, NOW + 10 * DAY)
    assert verdict.status is pki.Status.REVOKED
    assert verdict.crl_number == 3


def test_stale_crl_reports_age(pki, ca):
    cert, _ = ca.issue()
    verdict = pki.verify(cert, ca.cert, ca.crl(number=5), NOW + 4 * DAY)
    assert verdict.status is pki.Status.UNKNOWN
    assert "nieaktualne" in verdict.reason and "72.0 h" in verdict.reason


def test_delta_crl_alone_is_not_enough(pki, ca):
    cert, _ = ca.issue()
    verdict = pki.verify(cert, ca.cert, ca.crl(number=6, delta_base=5), NOW)
    assert verdict.status is pki.Status.UNKNOWN


def test_expired_root_ca_invalidates_everything(pki):
    old_ca = TestCA(not_before=NOW - 20 * DAY, not_after=NOW - DAY)
    cert, _ = old_ca.issue(not_before=NOW - 10 * DAY)
    assert pki.verify(cert, old_ca.cert, old_ca.crl(), NOW).status is pki.Status.INVALID


def test_missing_ca_is_unknown(pki, ca):
    cert, _ = ca.issue()
    assert pki.verify(cert, None, ca.crl(), NOW).status is pki.Status.UNKNOWN


def test_now_must_be_timezone_aware(pki, ca):
    cert, _ = ca.issue()
    with pytest.raises(ValueError):
        pki.verify(cert, ca.cert, ca.crl(), NOW.replace(tzinfo=None))


def test_check_certificate_uses_local_store(pki, ca):
    cert, key = ca.issue("client_2")
    store = pki.get_store()
    store.install_ca(der(ca.cert))
    assert pki.check_certificate(pem(cert), now=NOW).status is pki.Status.UNKNOWN  # jeszcze bez CRL

    store.update_crl(der(ca.crl(number=1)))
    verdict = pki.check_certificate(der(cert), now=NOW)
    assert verdict.ok and verdict.to_dict()["status"] == "valid"


def test_check_certificate_rejects_garbage(pki):
    verdict = pki.check_certificate(b"not a certificate", now=NOW)
    assert verdict.status is pki.Status.INVALID
