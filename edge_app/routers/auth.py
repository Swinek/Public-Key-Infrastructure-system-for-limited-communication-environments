"""Final use of the certificate: mutual challenge-response authentication between edge apps.

Separate channel from the PKI distribution (diagram: optional isolated network between edge apps, app_net).
Protocol (both directions, so each app proves possession of its private key to the other):
    1. verifier issues a random single-use nonce        GET  /api/auth/challenge
    2. prover signs  "edge-app-auth" | nonce | verifier_id  with its private key
    3. verifier checks the signature with the public key of the presented certificate
       and the certificate itself offline (chain to Root CA, validity, local CRL)  POST /api/auth/verify
The verifier id in the signed message binds the proof to one verifier, so it cannot be replayed to another app.
"""
import base64
import re
import secrets
import threading
import time
from typing import Any, Dict, Optional

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

import config
import pki
from routers.pki import current_source, ensure_certificate

router = APIRouter(prefix="/api/auth", tags=["Authentication (edge apps)"])

PEER_ID = re.compile(r"^app_\d+$")
NONCE_BYTES = 32

_challenges: Dict[str, float] = {}
_lock = threading.Lock()


class VerifyRequest(BaseModel):
    nonce: str
    certificate: str  # PEM
    signature: str  # base64


class ProveRequest(BaseModel):
    nonce: str
    verifier: str


class PeerRequest(BaseModel):
    peer: str


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def signed_message(nonce: str, verifier: str) -> bytes:
    return b"edge-app-auth\x00" + nonce.encode() + b"\x00" + verifier.encode()


def sign(key, message: bytes) -> bytes:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(message, ec.ECDSA(hashes.SHA256()))
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    raise ValueError(f"Nieobsługiwany typ klucza: {type(key).__name__}")


def signature_valid(cert: x509.Certificate, signature: bytes, message: bytes) -> bool:
    public_key = cert.public_key()
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
    except InvalidSignature:
        return False
    return True


def issue_challenge() -> str:
    nonce = secrets.token_urlsafe(NONCE_BYTES)
    now = time.monotonic()
    with _lock:
        for old, expires in list(_challenges.items()):
            if expires < now:
                del _challenges[old]
        _challenges[nonce] = now + config.CHALLENGE_TTL_SECONDS
    return nonce


def consume_challenge(nonce: str) -> bool:
    """True if the nonce was issued here, has not expired and was not used before (single use)."""
    with _lock:
        expires = _challenges.pop(nonce, None)
    return expires is not None and expires >= time.monotonic()


def _common_name(cert: x509.Certificate) -> str:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def verify_proof(nonce: str, certificate_pem: str, signature_b64: str) -> Dict[str, Any]:
    """Checks a proof presented to this app. Never raises on a bad proof - returns authenticated=False."""
    def result(ok: bool, reason: str, cert: Optional[x509.Certificate] = None, verdict=None) -> Dict[str, Any]:
        return {
            "authenticated": ok,
            "reason": reason,
            "peer": None if cert is None else _common_name(cert),
            "verdict": None if verdict is None else verdict.to_dict(),
        }

    if not consume_challenge(nonce):
        return result(False, "Nieznane, wygasłe albo już użyte wyzwanie (nonce).")
    try:
        cert = pki.store.load_certificate(certificate_pem.encode())
        signature = base64.b64decode(signature_b64, validate=True)
    except (pki.PkiError, ValueError) as exc:
        return result(False, f"Niepoprawny certyfikat lub podpis: {exc}")

    verdict = pki.check_certificate(certificate_pem.encode())
    if not verdict.ok:
        return result(False, f"Certyfikat odrzucony ({verdict.status.value}): {verdict.reason}", cert, verdict)
    if not signature_valid(cert, signature, signed_message(nonce, config.APP_ID)):
        return result(False, "Podpis wyzwania nie pasuje do klucza publicznego certyfikatu.", cert, verdict)
    return result(True, "Certyfikat ważny i potwierdzone posiadanie klucza prywatnego.", cert, verdict)


def make_proof(nonce: str, verifier: str) -> Dict[str, str]:
    store = pki.get_store()
    cert, key = store.node_certificate(), store.private_key()
    if cert is None or key is None:
        raise HTTPException(status_code=409, detail="Edge app nie ma jeszcze certyfikatu i klucza od edge clienta.")
    return {
        "app_id": config.APP_ID,
        "certificate": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "signature": _b64(sign(key, signed_message(nonce, verifier))),
    }


@router.get("/challenge", summary="Issue a single-use nonce for a peer to sign")
def get_challenge():
    # A peer starts authenticating: refresh own certificate, Root CA and CRL from the edge client first
    # (without it, the last taken copy is used; with no copy at all, /verify and /prove fail with a reason).
    try:
        ensure_certificate()
    except HTTPException as exc:
        print(f"[AUTH] No certificate from the edge client: {exc.detail}")
    return {"app_id": config.APP_ID, "nonce": issue_challenge(), "expires_in": config.CHALLENGE_TTL_SECONDS}


@router.post("/verify", summary="Verify a peer's proof: signed nonce + certificate checked offline")
def post_verify(body: VerifyRequest):
    verdict = verify_proof(body.nonce, body.certificate, body.signature)
    print(f"[AUTH] Proof from {verdict['peer'] or '?'}: {'OK' if verdict['authenticated'] else 'REJECTED'} - {verdict['reason']}")
    return verdict


@router.post("/prove", summary="Sign a verifier's nonce with the own private key")
def post_prove(body: ProveRequest):
    return make_proof(body.nonce, body.verifier)


@router.post("/peer", summary="Mutually authenticate with another edge app (e.g. app_2)")
def authenticate_peer(body: PeerRequest):
    peer = body.peer.strip()
    if not PEER_ID.match(peer) or peer == config.APP_ID:
        raise HTTPException(status_code=400, detail=f"Niepoprawny partner '{peer}' (oczekiwane app_<N> inne niż {config.APP_ID}).")
    base = config.PEER_URL_TEMPLATE.format(peer=peer)
    # Everything needed to authenticate comes from this node's edge client (offline: the last taken copy).
    warning = ensure_certificate()

    try:
        # 1. The peer authenticates us: its nonce, our signature.
        challenge = requests.get(f"{base}/api/auth/challenge", timeout=config.PEER_TIMEOUT).json()
        proof = make_proof(challenge["nonce"], peer)
        peer_verified_us = requests.post(
            f"{base}/api/auth/verify",
            json={"nonce": challenge["nonce"], "certificate": proof["certificate"], "signature": proof["signature"]},
            timeout=config.PEER_TIMEOUT,
        ).json()

        # 2. We authenticate the peer: our nonce, its signature.
        nonce = issue_challenge()
        resp = requests.post(f"{base}/api/auth/prove", json={"nonce": nonce, "verifier": config.APP_ID},
                             timeout=config.PEER_TIMEOUT)
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Brak połączenia z {peer} w kanale edge app: {exc}")

    if resp.ok:
        peer_proof = resp.json()
        we_verified_peer = verify_proof(nonce, peer_proof["certificate"], peer_proof["signature"])
    else:
        consume_challenge(nonce)
        detail = resp.json().get("detail", resp.text)
        we_verified_peer = {"authenticated": False, "reason": f"{peer} nie przedstawił dowodu: {detail}",
                            "peer": None, "verdict": None}

    authenticated = bool(peer_verified_us.get("authenticated") and we_verified_peer["authenticated"])
    print(f"[AUTH] Mutual authentication with {peer}: {'OK' if authenticated else 'FAILED'}")
    return {
        "peer": peer,
        "authenticated": authenticated,
        "certificate_serial": (current_source() or {}).get("serial_number"),
        "warning": warning,
        "peer_verified_us": peer_verified_us,
        "we_verified_peer": we_verified_peer,
    }
