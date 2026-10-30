"""CRL and Root CA synchronisation on contact - one code for the portal (WAN) and for a radio neighbour.

On every contact (contact.py) this node pulls from the peer:
    1. GET /pki/summary                    small metadata: CA fingerprint, CRLNumber, sizes
    2. GET /pki/ca   only if this node has no CA yet and may take it from this peer (see below)
    3. GET /pki/crl  only if the peer's CRLNumber is higher than the stored one

Nothing the peer says is trusted: the declared size only caps the download (aborted when exceeded, never above
MAX_PKI_OBJECT_BYTES), and the CRL is stored only after certs.CertStore.update_crl has checked the CA signature,
the issuer and a higher CRLNumber (atomic write - a broken transfer leaves the previous CRL). A peer with the same
version costs only the summary; the object it did not have to send is recorded as saved bytes.

Root CA: only one matching CA_FINGERPRINT, pinned at deployment, is accepted - from the portal or a neighbour.
Without the pin no CA is taken (no trust on first use: whoever came first could plant their own CA).

A newly stored CRL is announced to the other neighbours, which pull it from here (CRL travels hop by hop).
"""
from __future__ import annotations

import zlib
import hashlib
import re
import peer_state

from typing import Any, Dict, List, Optional

from cryptography import x509

import certs
import config
import contact
import transfers
import wire


class PkiSyncError(Exception):
    pass


def _summary(peer: Dict[str, Any]) -> Dict[str, Any]:
    fetched = wire.get(wire.peer_url(peer, "/pki/summary"), config.MAX_SUMMARY_BYTES)
    transfers.record("summary", "in", peer["id"], len(fetched.body), fetched.wire_bytes, encoding="JSON")
    data = fetched.json()
    if not isinstance(data, dict):
        raise PkiSyncError("summary nie jest obiektem JSON")
    return data


def _limit(declared: Any) -> int:
    size = wire.optional_int(declared)
    if size is None or size <= 0:
        return config.MAX_PKI_OBJECT_BYTES
    if size > config.MAX_PKI_OBJECT_BYTES:
        raise PkiSyncError(f"zadeklarowany rozmiar {size} B przekracza limit {config.MAX_PKI_OBJECT_BYTES} B")
    return size


def _download(peer: Dict[str, Any], path: str, kind: str, declared: Any, number: Any = None) -> wire.Fetched:
    try:
        return wire.get(wire.peer_url(peer, path), _limit(declared))
    except (wire.WireError, PkiSyncError) as exc:
        transfers.record(kind, "in", peer["id"], status="aborted", encoding="DER", number=number, note=str(exc)[:200])
        raise PkiSyncError(f"{path}: {exc}") from exc


def may_take_ca_from(peer: Dict[str, Any]) -> bool:
    """Only a Root CA matching the pin set at deployment - from any peer, since the pin is what is trusted."""
    return bool(config.CA_FINGERPRINT)


def sync_ca(peer: Dict[str, Any], info: Optional[Dict[str, Any]]) -> Optional[str]:
    """Returns 'stored', 'same', or None when nothing was done."""
    if not info:
        return None
    store = certs.get_store()
    current = store.ca()
    declared_fp = str(info.get("fingerprint", "")).lower()
    if current is not None:
        if certs.fingerprint(current) == declared_fp:
            transfers.record("ca_cert", "in", peer["id"], status="skipped",
                             saved_bytes=wire.optional_int(info.get("size")) or 0, note="peer has the same CA")
            return "same"
        print(f"[PKI SYNC] {peer['id']} has another Root CA ({declared_fp[:16]}...) - ignored")
        return None
    if not may_take_ca_from(peer):
        print(f"[PKI SYNC] {peer['id']}: CA_FINGERPRINT not set - Root CA not taken (no trust on first use)")
        return None
    if config.CA_FINGERPRINT and declared_fp != config.CA_FINGERPRINT:
        print(f"[PKI SYNC] {peer['id']}: Root CA does not match CA_FINGERPRINT - not downloaded")
        return None
    fetched = _download(peer, "/pki/ca", "ca_cert", info.get("size"))
    try:
        store.set_ca(fetched.body)
    except certs.CertStoreError as exc:
        transfers.record("ca_cert", "in", peer["id"], len(fetched.body), fetched.wire_bytes, status="rejected",
                         encoding="DER", note=str(exc))
        raise PkiSyncError(f"Root CA od {peer['id']} odrzucony: {exc}") from exc
    ca = store.ca()
    transfers.record("ca_cert", "in", peer["id"], len(fetched.body), fetched.wire_bytes, encoding="DER",
                     signature=certs.signature_name(ca))
    print(f"[PKI SYNC] Root CA stored from {peer['id']} ({certs.fingerprint(ca)[:16]}...)")
    return "stored"


def sync_crl(peer: Dict[str, Any], info: Optional[Dict[str, Any]]) -> Optional[str]:
    """Returns 'stored', 'same' (peer not newer), or None when nothing was done."""
    if not info:
        peer_state.observe(peer["id"], None)
        return None
    peer_number = wire.optional_int(info.get("number"))
    peer_state.observe(peer["id"], peer_number)
    store = certs.get_store()
    if store.ca() is None:
        print(f"[PKI SYNC] {peer['id']} has CRL #{info.get('number')}, but there is no Root CA to check it")
        return None
    current = store.crl()
    local_number = store.revocation_number()
    if peer_number is None:
        raise PkiSyncError(f"{peer['id']}: summary bez numeru CRL")
    if local_number is not None and peer_number <= local_number:
        if peer_number == local_number:
            transfers.record("crl_full", "in", peer["id"], status="skipped", number=peer_number,
                             saved_bytes=wire.optional_int(info.get("size")) or 0, note="peer has the same CRL")
        if info.get("updates") is not None:
            _ack(peer, local_number)
        return "same"
    if info.get("updates") is not None:
        return _sync_update(peer, info, store, peer_number)
    raw_limit = _limit(info.get("size"))
    compressed_size = wire.optional_int(info.get("zlib_size"))
    compressed = compressed_size is not None and 0 < compressed_size < raw_limit
    encoding = "DER+zlib" if compressed else "DER"
    path = "/pki/crl?compression=zlib" if compressed else "/pki/crl"
    fetched = _download(peer, path, "crl_full", compressed_size if compressed else info.get("size"), peer_number)
    body = fetched.body
    if compressed:
        try:
            decoder = zlib.decompressobj()
            body = decoder.decompress(body, raw_limit + 1)
            if len(body) > raw_limit or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise ValueError("niepełna, nadmiarowa lub zbyt duża zawartość zlib")
        except (zlib.error, ValueError) as exc:
            transfers.record("crl_full", "in", peer["id"], len(fetched.body), fetched.wire_bytes,
                             status="rejected", encoding=encoding, number=peer_number, note=str(exc))
            raise PkiSyncError(f"CRL od {peer['id']} odrzucona: {exc}") from exc
    try:
        crl = x509.load_der_x509_crl(body)
        signature = certs.signature_name(crl)
    except ValueError:
        signature = None
    try:
        stored = store.update_crl(body)
    except certs.CertStoreError as exc:
        transfers.record("crl_full", "in", peer["id"], len(fetched.body), fetched.wire_bytes, status="rejected",
                         encoding=encoding, signature=signature, number=peer_number, note=str(exc))
        raise PkiSyncError(f"CRL od {peer['id']} odrzucona: {exc}") from exc
    number = store.revocation_number()
    transfers.record("crl_full", "in", peer["id"], len(fetched.body), fetched.wire_bytes,
                     status="ok" if stored else "skipped", encoding=encoding, signature=signature, number=number,
                     saved_bytes=max(0, len(body) - len(fetched.body)) if stored else 0,
                     note=None if stored else "not newer than the stored CRL")
    if not stored:
        return "same"
    print(f"[PKI SYNC] CRL #{number} stored from {peer['id']} (was #{local_number})")
    contact.announce(f"crl-{number}", exclude=peer["id"])
    return "stored"



def _ack(peer, number):
    if peer.get("kind") != "neighbour" or number is None:
        return
    try:
        fetched = wire.post_json(wire.peer_url(peer, "/pki/ack"), {"number": number}, 256)
        transfers.record("crl_ack", "out", peer["id"], 0, fetched.wire_bytes, number=number)
    except wire.WireError as exc:
        # Niepotwierdzona wersja nie jest zapamiętywana przez nadawcę. Kolejny kontakt ponawia ACK.
        print(f"[PKI] Potwierdzenie do {peer['id']} nie dotarło: {exc}")


def _sync_update(peer, info, store, target):
    candidates = info.get("updates")
    if not isinstance(candidates, list) or len(candidates) > 34:
        raise PkiSyncError("Niepoprawna lista aktualizacji CRL")
    local_base = None if store.crl() is None else certs.crl_number(store.crl())
    choices = []
    for obj in candidates:
        if not isinstance(obj, dict) or obj.get("number") != target:
            continue
        kind = obj.get("kind")
        floor = wire.optional_int(obj.get("base"))
        if kind == "delta" and (floor is None or local_base is None or not floor <= local_base < target):
            continue
        if kind not in ("full", "delta", "bundle") or not re.fullmatch(r"[0-9a-f]{64}", str(obj.get("id", ""))):
            continue
        size = wire.optional_int(obj.get("size"))
        zipped = wire.optional_int(obj.get("zlib_size"))
        if size is None or not 0 < size <= config.MAX_PKI_OBJECT_BYTES:
            continue
        compressed = zipped is not None and 0 < zipped < size
        choices.append((zipped if compressed else size, obj, compressed))
    if not choices:
        raise PkiSyncError("Brak zgodnej i mieszczącej się w limicie aktualizacji CRL")
    _, obj, compressed = min(choices, key=lambda v: v[0])
    kind = "crl_delta" if obj["kind"] == "delta" else "crl_full"
    path = f"/pki/updates/{obj['id']}" + ("?compression=zlib" if compressed else "")
    encoding = ("JSON" if obj["kind"] == "bundle" else "DER") + ("+zlib" if compressed else "")
    fetched = _download(peer, path, kind, obj["zlib_size"] if compressed else obj["size"], target)
    body = fetched.body
    try:
        if compressed:
            decoder = zlib.decompressobj()
            body = decoder.decompress(body, obj["size"] + 1)
            if len(body) > obj["size"] or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise ValueError("Przekroczony limit lub niepoprawna zawartość zlib")
        if hashlib.sha256(body).hexdigest() != obj["id"]:
            raise ValueError("SHA-256 aktualizacji różni się od zapowiedzianego")
        stored = store.update_revocation(body, obj["kind"], expected=target)
    except (ValueError, zlib.error) as exc:
        transfers.record(kind, "in", peer["id"], len(fetched.body), fetched.wire_bytes,
                         status="rejected", encoding=encoding, number=target, note=str(exc))
        raise PkiSyncError(f"Aktualizacja CRL odrzucona: {exc}") from exc
    # ACK wyłącznie po weryfikacji podpisów i atomowym zapisie (także przy wyścigu z innym odbiorcą).
    _ack(peer, store.revocation_number())
    reference = min((candidate[1]["size"] for candidate in choices if candidate[1]["kind"] != "delta"),
                    default=len(body))
    transfers.record(kind, "in", peer["id"], len(fetched.body), fetched.wire_bytes,
                     status="ok" if stored else "skipped", encoding=encoding, number=store.revocation_number(),
                     saved_bytes=max(0, reference - len(fetched.body)) if stored else 0,
                     note=f"{obj['kind']}, base={obj.get('base')}")
    if stored:
        contact.announce(f"crl-{target}", exclude=peer["id"])
    return "stored" if stored else "same"

def exchange(peer: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Contact handler: summary, then the Root CA and the CRL if this node needs them."""
    summary = _summary(peer)
    result: Dict[str, Optional[str]] = {}
    errors: List[str] = []
    for name, step in (("ca", sync_ca), ("crl", sync_crl)):  # CA first: the CRL is checked against it
        try:
            result[name] = step(peer, summary.get(name))
        except PkiSyncError as exc:
            result[name] = "rejected"
            errors.append(str(exc))
    if errors:
        raise PkiSyncError("; ".join(errors))
    return result


exchange.__name__ = "pki_sync"
contact.register(exchange)
