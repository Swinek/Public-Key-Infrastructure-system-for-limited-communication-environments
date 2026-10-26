"""Use of the certificate for confidentiality: messages encrypted for the recipient's certificate (ECIES).

The encrypted envelope travels over the same radio links as the PKI data: the edge app hands it to the edge
client of its node (mgmt_N), which sends it like any P2P message - directly to a neighbour in range, otherwise by
store-and-forward. Carriers on the way hold a copy they cannot read. Flow, e.g. app_1 -> client_1 -> client_2 ->
client_3 -> app_3:
    1. sender takes the recipient node's certificate from its own edge client (node certificates travel with the
       PKI sync, edge_client/node/pki_sync.py) and checks it offline: chain to Root CA, validity, local CRL, CN.
       A revoked recipient gets nothing.
    2. sender encrypts with the public key of that certificate (pki/ecies.py)       POST /api/messages/send
    3. the edge client sends "<MARKER><envelope JSON>" as an ordinary P2P message
    4. every app opens what its edge client holds with its own private key           GET  /api/messages/inbox
       delivered here -> text; carried for another node -> only ciphertext and the reason

Sign, then encrypt (as S/MIME): inside the ciphertext is {text, sender certificate, ECDSA signature by the sender's
private key}. The signature covers sender | recipient | recipient's certificate serial | text, so a recipient
cannot pass the message on as if it had been written for someone else. The recipient checks the sender's
certificate offline (Root CA, validity, local CRL, CN = "sender" of the envelope) and the signature: only then
is the sender known. Carriers see neither the text nor the sender's certificate.
"""
import base64
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, ValidationError

import config
import pki
from pki import ecies
from routers.auth import sign, signature_valid
from routers.pki import ensure_certificate

router = APIRouter(prefix="/api/messages", tags=["Encrypted messages (over the radio links)"])

MARKER = "edge-app-msg/2 "  # prefix of the P2P message text that carries an envelope
NODE_REF = re.compile(r"^(?:app_|client_)?(\d+)$")
# The edge client carries up to 10 000 characters per message; the sender certificate and signature take ~1 KB,
# base64 and the envelope fields ~1/3 more.
MAX_TEXT_BYTES = 5000


class SendRequest(BaseModel):
    to: str = Field(description="Recipient: app_N, client_N or N")
    text: str = Field(min_length=1)


class Envelope(BaseModel):
    sender: str  # node id (CN), e.g. client_1
    recipient: str  # node id (CN) whose certificate was used
    recipient_serial: str
    ephemeral_key: str  # base64, uncompressed EC point
    nonce: str  # base64
    ciphertext: str  # base64, AES-256-GCM with tag


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _aad(env: Envelope) -> bytes:
    return b"\x00".join(s.encode() for s in ("edge-app-msg", env.sender, env.recipient, env.recipient_serial))


def _signed_message(env: Envelope, text: bytes) -> bytes:
    return _aad(env).replace(b"edge-app-msg", b"edge-app-msg-sig", 1) + b"\x00" + text


def _common_name(cert) -> str:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def _node_id(ref: str) -> str:
    match = NODE_REF.match(ref.strip())
    if not match:
        raise HTTPException(status_code=400, detail=f"Niepoprawny odbiorca '{ref}' (oczekiwane app_N, client_N albo N).")
    node = f"client_{match.group(1)}"
    if node == config.NODE_ID:
        raise HTTPException(status_code=400, detail="Nie można wysłać zaszyfrowanej wiadomości do własnego węzła.")
    return node


def _edge_client(method: str, path: str, **kwargs) -> requests.Response:
    try:
        return requests.request(method, f"{config.EDGE_CLIENT_URL}{path}", timeout=config.EDGE_CLIENT_TIMEOUT, **kwargs)
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Edge client ({config.EDGE_CLIENT_URL}) jest nieosiągalny: {exc}")


def _detail(resp: requests.Response) -> Any:
    try:
        return resp.json().get("detail", resp.text)
    except ValueError:
        return resp.text


def _recipient_certificate(node: str):
    """Certificate of the recipient node from this node's edge client, verified offline before encrypting for it."""
    resp = _edge_client("GET", f"/api/certs/nodes/{node}")
    if resp.status_code != 200:
        raise HTTPException(status_code=409, detail=_detail(resp))
    verdict = pki.check_certificate(resp.content)
    if not verdict.ok:
        raise HTTPException(status_code=403, detail={
            "error": f"Certyfikat odbiorcy {node} odrzucony ({verdict.status.value}): {verdict.reason} – nie szyfruję.",
            "verdict": verdict.to_dict(),
        })
    cert = pki.store.load_certificate(resp.content)
    if _common_name(cert) != node:
        raise HTTPException(status_code=403, detail=f"Certyfikat należy do '{_common_name(cert) or '?'}', "
                                                    f"a nie do {node} – nie szyfruję.")
    return cert, verdict


def _envelope(text: Any) -> Optional[Envelope]:
    if not isinstance(text, str) or not text.startswith(MARKER):
        return None
    try:
        return Envelope(**json.loads(text[len(MARKER):]))
    except (ValueError, TypeError, ValidationError):
        return None


def _check_sender(env: Envelope, text: bytes, cert_b64: Any, signature_b64: Any) -> Dict[str, Any]:
    """Who wrote it: the sender's certificate checked offline, then its signature over the message."""
    def result(ok: bool, reason: str, verdict=None) -> Dict[str, Any]:
        return {"sender_verified": ok, "sender_reason": reason,
                "sender_certificate": None if verdict is None else verdict.to_dict()}

    try:
        cert_der = base64.b64decode(cert_b64, validate=True)
        signature = base64.b64decode(signature_b64, validate=True)
        cert = pki.store.load_certificate(cert_der)
    except (pki.PkiError, ValueError, TypeError) as exc:
        return result(False, f"Brak lub niepoprawny certyfikat/podpis nadawcy: {exc}")
    verdict = pki.check_certificate(cert_der)
    if not verdict.ok:
        return result(False, f"Certyfikat nadawcy odrzucony ({verdict.status.value}): {verdict.reason}", verdict)
    if _common_name(cert) != env.sender:
        return result(False, f"Certyfikat należy do '{_common_name(cert)}', a koperta podaje nadawcę {env.sender}.",
                      verdict)
    if not signature_valid(cert, signature, _signed_message(env, text)):
        return result(False, "Podpis nie pasuje do treści lub certyfikatu nadawcy.", verdict)
    return result(True, f"Podpisane przez {env.sender} (certyfikat {cert.serial_number} ważny).", verdict)


def _open(env: Envelope) -> Dict[str, Any]:
    """Decrypts with the own private key and checks the sender. Never raises: an unreadable or unverified message
    is a valid outcome."""
    key = pki.get_store().private_key()
    if key is None:
        return {"readable": False, "reason": "Edge app nie ma jeszcze własnego klucza prywatnego."}
    try:
        inner = ecies.decrypt(key, base64.b64decode(env.ephemeral_key), base64.b64decode(env.nonce),
                              base64.b64decode(env.ciphertext), _aad(env))
        payload = json.loads(inner)
        text = base64.b64decode(payload["text"], validate=True)
    except (ecies.DecryptionError, ValueError, TypeError, KeyError) as exc:
        return {"readable": False, "reason": str(exc)}
    return {"readable": True, "text": text.decode("utf-8", errors="replace"),
            **_check_sender(env, text, payload.get("certificate"), payload.get("signature"))}


def _entry(env: Envelope, role: str, route: List[str], at: Optional[str]) -> Dict[str, Any]:
    return {"from": env.sender, "to": env.recipient, "role": role, "route": route, "at": at,
            "ciphertext": env.ciphertext, **_open(env)}


@router.post("/send", summary="Encrypt for the recipient's certificate and hand to the edge client (radio links)")
def send_message(body: SendRequest):
    node = _node_id(body.to)
    plaintext = body.text.encode()
    if len(plaintext) > MAX_TEXT_BYTES:
        raise HTTPException(status_code=413, detail=f"Wiadomość przekracza {MAX_TEXT_BYTES} B.")

    # Fresh CRL from the edge client if possible (offline: the last taken copy).
    warning = ensure_certificate()
    store = pki.get_store()
    own_cert, own_key = store.node_certificate(), store.private_key()
    if own_cert is None or own_key is None:
        raise HTTPException(status_code=409, detail="Edge app nie ma jeszcze certyfikatu i klucza do podpisu.")
    own_verdict = pki.verify(own_cert, store.ca(), store.crl(), datetime.now(timezone.utc))
    if not own_verdict.ok:  # sent anyway: the recipient decides, with its own CRL
        warning = f"Własny certyfikat {own_verdict.status.value}: {own_verdict.reason} – odbiorca odrzuci podpis."
    cert, verdict = _recipient_certificate(node)

    env = Envelope(sender=config.NODE_ID, recipient=node, recipient_serial=str(cert.serial_number),
                   ephemeral_key="", nonce="", ciphertext="")
    inner = json.dumps({
        "text": _b64(plaintext),
        "certificate": _b64(own_cert.public_bytes(serialization.Encoding.DER)),
        "signature": _b64(sign(own_key, _signed_message(env, plaintext))),
    }, separators=(",", ":")).encode()
    point, nonce, ciphertext = ecies.encrypt(cert.public_key(), inner, _aad(env))
    env.ephemeral_key, env.nonce, env.ciphertext = _b64(point), _b64(nonce), _b64(ciphertext)

    message = MARKER + json.dumps(env.model_dump(), separators=(",", ":"))
    resp = _edge_client("POST", "/api/p2p/send-message", json={"to": node, "message": message})
    if not resp.ok:
        raise HTTPException(status_code=502, detail=f"Edge client nie wysłał wiadomości: {_detail(resp)}")
    delivery = resp.json()
    print(f"[MSG] Encrypted for {node} (certificate {env.recipient_serial}), edge client: {delivery.get('status')}")
    return {
        "to": node,
        "status": delivery.get("status"),
        "recipient_certificate": verdict.to_dict(),
        "own_certificate": own_verdict.to_dict(),
        "warning": warning,
        "plaintext_bytes": len(plaintext),
        "radio_bytes": len(message.encode()),
        "envelope": env.model_dump(),
        "delivery": delivery,
    }


@router.get("/inbox", summary="Envelopes held by this node's edge client, opened with the own private key if possible")
def get_inbox():
    inbox = _edge_client("GET", "/api/p2p/inbox")
    queue = _edge_client("GET", "/api/saf/queue")
    if not inbox.ok or not queue.ok:
        raise HTTPException(status_code=502, detail="Edge client nie zwrócił skrzynki lub kolejki.")

    out = []
    for msg in reversed(inbox.json().get("messages", [])):
        env = _envelope(msg.get("message"))
        if env is not None:
            out.append(_entry(env, "recipient", msg.get("route") or [], msg.get("received_at")))
    for item in queue.json().get("items", []):
        env = _envelope(item.get("message")) if item.get("type") == "msg" else None
        if env is not None:
            role = "sender" if env.sender == config.NODE_ID else "carrier"  # waiting here for a path / carried
            out.append(_entry(env, role, item.get("hops") or [], item.get("created_at")))
    return {"app_id": config.APP_ID, "node_id": config.NODE_ID, "messages": out}
