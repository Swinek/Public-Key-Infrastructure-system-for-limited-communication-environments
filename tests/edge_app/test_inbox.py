"""Skrzynka Edge appa (edge_app/routers/messages.py): czytelne powody, gdy koperty nie da się (lub nie trzeba) otworzyć."""

from __future__ import annotations

import base64
import importlib

import pytest

from tests.pki_factory import TestCA, der, key_pem


@pytest.fixture(scope="module")
def ca():
    return TestCA()


@pytest.fixture
def messages(edge_app_env, monkeypatch):
    monkeypatch.setenv("NODE_ID", "client_3")
    monkeypatch.setenv("APP_ID", "app_3")
    return importlib.import_module("routers.messages")


def _install(messages, ca, cert, key):
    store = importlib.import_module("pki").get_store()
    store.install_ca(der(ca.cert))
    store.install_node(der(cert), key_pem(key))


def _envelope(messages, recipient_cert, recipient="client_3", sender="client_1"):
    env = messages.Envelope(sender=sender, recipient=recipient, recipient_serial=str(recipient_cert.serial_number),
                            ephemeral_key="", nonce="", ciphertext="")
    point, nonce, ct = messages.ecies.encrypt(recipient_cert.public_key(), b'{"text":""}', messages._aad(env))
    b64 = lambda b: base64.b64encode(b).decode()
    env.ephemeral_key, env.nonce, env.ciphertext = b64(point), b64(nonce), b64(ct)
    return env


def test_carried_and_sent_envelopes_are_not_decrypted(messages, ca):
    cert, key = ca.issue("client_3")
    _install(messages, ca, cert, key)
    other, _ = ca.issue("client_2")
    env = _envelope(messages, other, recipient="client_2")
    carried = messages._entry(env, "carrier", [], None)
    assert carried["readable"] is False and "Przenoszona do client_2" in carried["reason"]
    assert "zmieniona" not in carried["reason"]  # nic nie sugeruje manipulacji
    sent = messages._entry(env, "sender", [], None)
    assert "Wysłana do client_2" in sent["reason"]


def test_message_for_the_previous_certificate_says_so(messages, ca):
    old, _ = ca.issue("client_3")
    new, new_key = ca.issue("client_3")  # klucz wymieniony po nowym wniosku CSR
    _install(messages, ca, new, new_key)
    entry = messages._entry(_envelope(messages, old), "recipient", [], None)
    assert entry["readable"] is False
    assert "poprzedniego certyfikatu" in entry["reason"] and str(old.serial_number) in entry["reason"]
