"""ECIES: encryption for the holder of a certificate (its EC public key), decryption with the own private key.

Sender:    ephemeral key pair (e, E);  S = ECDH(e, Q_recipient);  K = HKDF-SHA256(S);  C = AES-256-GCM(K, text)
           sends E + nonce + C, forgets e.
Recipient: S = ECDH(d_recipient, E) - the same S, so the same K. Any other private key gives a different K
           and AES-GCM rejects the ciphertext (InvalidTag) instead of returning garbage.
`aad` (sender, recipient, recipient's certificate serial) is authenticated but not encrypted.
"""

from __future__ import annotations

import os
from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HKDF_INFO = b"edge-app-msg v1"
NONCE_BYTES = 12


class DecryptionError(Exception):
    pass


def _derive_key(shared_secret: bytes, ephemeral_point: bytes) -> bytes:
    # The ephemeral point in the salt binds the key to this one message.
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=ephemeral_point, info=HKDF_INFO).derive(shared_secret)


def encrypt(recipient_key, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes, bytes]:
    """Returns (ephemeral public point, nonce, ciphertext+tag) for the owner of `recipient_key`."""
    if not isinstance(recipient_key, ec.EllipticCurvePublicKey):
        raise ValueError(f"Szyfrowanie wymaga klucza EC odbiorcy, a nie {type(recipient_key).__name__}.")
    ephemeral = ec.generate_private_key(recipient_key.curve)
    point = ephemeral.public_key().public_bytes(serialization.Encoding.X962,
                                                 serialization.PublicFormat.UncompressedPoint)
    key = _derive_key(ephemeral.exchange(ec.ECDH(), recipient_key), point)
    nonce = os.urandom(NONCE_BYTES)
    return point, nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(private_key, ephemeral_point: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Raises DecryptionError when the message was not encrypted for this private key (or was modified)."""
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise DecryptionError("Klucz prywatny węzła nie jest kluczem EC.")
    try:
        ephemeral = ec.EllipticCurvePublicKey.from_encoded_point(private_key.curve, ephemeral_point)
    except ValueError as exc:
        raise DecryptionError(f"Niepoprawny klucz efemeryczny: {exc}")
    key = _derive_key(private_key.exchange(ec.ECDH(), ephemeral), ephemeral_point)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise DecryptionError("Nie można odszyfrować: wiadomość nie jest zaszyfrowana dla klucza tego węzła "
                              "albo została zmieniona po drodze.")
