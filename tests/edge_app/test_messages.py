"""Szyfrowanie wiadomości dla certyfikatu odbiorcy (edge_app/routers/messages.py, edge_app/pki/ecies.py)."""

from __future__ import annotations

import importlib

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException

from tests.pki_factory import TestCA


@pytest.fixture(scope="module")
def ca():
    return TestCA()


@pytest.fixture
def messages(edge_app_env, monkeypatch):
    monkeypatch.setenv("NODE_ID", "client_1")
    monkeypatch.setenv("APP_ID", "app_1")
    return importlib.import_module("routers.messages")


def test_recipient_with_key_agreement_is_accepted(messages, ca):
    cert, _ = ca.issue("client_2")
    messages._require_key_agreement(cert, "client_2")


def test_recipient_without_key_agreement_is_rejected(messages, ca):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = ca.issue_for(key.public_key(), "client_2", key_agreement=False)
    with pytest.raises(HTTPException) as exc:
        messages._require_key_agreement(cert, "client_2")
    assert exc.value.status_code == 403
    assert "keyAgreement" in exc.value.detail


def test_ecies_round_trip_and_wrong_key(messages, ca):
    cert, key = ca.issue("client_2")
    point, nonce, ciphertext = messages.ecies.encrypt(cert.public_key(), b"tajne", b"aad")
    assert messages.ecies.decrypt(key, point, nonce, ciphertext, b"aad") == b"tajne"
    with pytest.raises(messages.ecies.DecryptionError):
        messages.ecies.decrypt(ec.generate_private_key(ec.SECP256R1()), point, nonce, ciphertext, b"aad")
    with pytest.raises(messages.ecies.DecryptionError):
        messages.ecies.decrypt(key, point, nonce, ciphertext, b"inne aad")
