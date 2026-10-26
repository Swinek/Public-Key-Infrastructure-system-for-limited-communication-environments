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

Node certificates travel the same way: the summary lists CN -> serial of every node certificate the peer holds
(its own included), and this node pulls only the ones it does not have (GET /pki/node-cert/<CN>). Each is stored
only if valid against the Root CA and the stored CRL. The edge app needs them to encrypt for a node out of range.
"""
from __future__ import annotations

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
        return None
    store = certs.get_store()
    if store.ca() is None:
        print(f"[PKI SYNC] {peer['id']} has CRL #{info.get('number')}, but there is no Root CA to check it")
        return None
    peer_number = wire.optional_int(info.get("number"))
    current = store.crl()
    local_number = certs.crl_number(current) if current is not None else None
    if peer_number is None:
        raise PkiSyncError(f"{peer['id']}: summary bez numeru CRL")
    if local_number is not None and peer_number <= local_number:
        if peer_number == local_number:
            transfers.record("crl_full", "in", peer["id"], status="skipped", number=peer_number,
                             saved_bytes=wire.optional_int(info.get("size")) or 0, note="peer has the same CRL")
        return "same"
    fetched = _download(peer, "/pki/crl", "crl_full", info.get("size"), peer_number)
    try:
        crl = x509.load_der_x509_crl(fetched.body)
        signature = certs.signature_name(crl)
    except ValueError:
        signature = None
    try:
        stored = store.update_crl(fetched.body)
    except certs.CertStoreError as exc:
        transfers.record("crl_full", "in", peer["id"], len(fetched.body), fetched.wire_bytes, status="rejected",
                         encoding="DER", signature=signature, number=peer_number, note=str(exc))
        raise PkiSyncError(f"CRL od {peer['id']} odrzucona: {exc}") from exc
    number = certs.crl_number(store.crl())
    transfers.record("crl_full", "in", peer["id"], len(fetched.body), fetched.wire_bytes,
                     status="ok" if stored else "skipped", encoding="DER", signature=signature, number=number,
                     note=None if stored else "not newer than the stored CRL")
    if not stored:
        return "same"
    print(f"[PKI SYNC] CRL #{number} stored from {peer['id']} (was #{local_number})")
    contact.announce(f"crl-{number}", exclude=peer["id"])
    return "stored"


def sync_node_certs(peer: Dict[str, Any], info: Any) -> Optional[str]:
    """Returns 'stored' (at least one new node certificate), 'same', or None when nothing was done."""
    if not isinstance(info, dict):
        return None  # the portal (or an older node) does not list node certificates
    store = certs.get_store()
    if store.ca() is None:
        return None
    known = store.node_certificates()
    crl = store.crl()
    stored: List[str] = []
    errors: List[str] = []
    for cn, serial in info.items():
        if cn == config.NODE_ID or not certs.NODE_CN.match(str(cn)) or known.get(cn) == str(serial):
            continue
        number = wire.optional_int(serial)
        if crl is not None and number is not None and crl.get_revoked_certificate_by_serial_number(number):
            continue  # revoked according to the stored CRL: not worth the radio link

        try:
            fetched = _download(peer, f"/pki/node-cert/{cn}", "node_cert", None, serial)
        except PkiSyncError as exc:
            errors.append(str(exc))
            continue
        try:
            added = store.add_peer_certificate(fetched.body, config.NODE_ID)
        except certs.CertStoreError as exc:
            transfers.record("node_cert", "in", peer["id"], len(fetched.body), fetched.wire_bytes, status="rejected",
                             encoding="DER", number=serial, note=str(exc)[:200])
            errors.append(f"certyfikat {cn} od {peer['id']}: {exc}")
            continue
        transfers.record("node_cert", "in", peer["id"], len(fetched.body), fetched.wire_bytes,
                         status="ok" if added else "skipped", encoding="DER", number=serial,
                         note=None if added else "not newer than the stored certificate")
        if added:
            stored.append(cn)
            print(f"[PKI SYNC] Certificate of {cn} ({serial}) stored from {peer['id']}")
    if stored:
        contact.announce(f"node-certs-{len(known) + len(stored)}", exclude=peer["id"])
    if errors:
        raise PkiSyncError("; ".join(errors))
    return "stored" if stored else "same"


def exchange(peer: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Contact handler: summary, then the Root CA, the CRL and node certificates if this node needs them."""
    summary = _summary(peer)
    result: Dict[str, Optional[str]] = {}
    errors: List[str] = []
    # CA first: the CRL is checked against it; node certificates last: they are checked against the newest CRL
    for name, step in (("ca", sync_ca), ("crl", sync_crl), ("node_certs", sync_node_certs)):
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
