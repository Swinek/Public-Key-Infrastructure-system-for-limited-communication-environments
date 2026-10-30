"""Podpisana baza i skumulowana delta: przechowywanie i transport bez ponownego podpisu."""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import zlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from utils import atomic_write_bytes


def number(crl):
    return crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number


def base_number(crl):
    try:
        return crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator).value.crl_number
    except x509.ExtensionNotFound:
        return None


def der(crl):
    return crl.public_bytes(serialization.Encoding.DER)


def _extension(crl, cls):
    try:
        return crl.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


def check_object(crl, ca):
    # Import lokalny: store udostępnia dotychczasowe kontrole podpisu.
    from pki.store import PkiError, check_crl_signed_by
    check_crl_signed_by(crl, ca)
    try:
        if number(crl) < 0 or crl.next_update_utc is None or crl.next_update_utc <= crl.last_update_utc:
            raise ValueError()
    except (x509.ExtensionNotFound, ValueError):
        raise PkiError("CRL ma niepoprawny numer lub okres aktualności.") from None
    for ext in crl.extensions:
        if ext.critical and not isinstance(ext.value, (x509.DeltaCRLIndicator,)):
            raise PkiError("Nieobsługiwane krytyczne rozszerzenie CRL.")
    if _extension(crl, x509.IssuingDistributionPoint) is not None:
        raise PkiError("Obsługiwane są wyłącznie bezpośrednie CRL o pełnym zakresie.")
    for entry in crl:
        for ext in entry.extensions:
            if ext.critical or isinstance(ext.value, x509.CertificateIssuer):
                raise PkiError("Nieobsługiwane rozszerzenie wpisu CRL.")
    if base_number(crl) is not None and not crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator).critical:
        raise PkiError("DeltaCRLIndicator musi być krytyczne.")


def check_pair(base, delta, ca):
    from pki.store import PkiError
    check_object(base, ca)
    check_object(delta, ca)
    floor = base_number(delta)
    if base_number(base) is not None or floor is None or not floor <= number(base) < number(delta):
        raise PkiError("Delta-CRL nie pasuje do numeru pełnej bazy.")
    if delta.issuer != base.issuer or delta.last_update_utc < base.last_update_utc:
        raise PkiError("Delta-CRL ma innego wystawcę lub wcześniejsze thisUpdate.")
    if _extension(base, x509.AuthorityKeyIdentifier) != _extension(delta, x509.AuthorityKeyIdentifier):
        raise PkiError("Delta i baza mają różne identyfikatory klucza CA.")


def effective_entries(base, delta=None):
    entries = {e.serial_number: e for e in base}
    if delta is not None:
        for entry in delta:
            reason = _extension(entry, x509.CRLReason)
            if reason is not None and reason.reason == x509.ReasonFlags.remove_from_crl:
                entries.pop(entry.serial_number, None)
            else:
                entries[entry.serial_number] = entry
    return entries


def encode_state(base, delta=None):
    return json.dumps({"base": base64.b64encode(der(base)).decode(),
                       "delta": None if delta is None else base64.b64encode(der(delta)).decode()},
                      separators=(",", ":")).encode()


def decode_state(data):
    from pki.store import PkiError
    try:
        obj = json.loads(data)
        base = x509.load_der_x509_crl(base64.b64decode(obj["base"], validate=True))
        delta = None if obj.get("delta") is None else x509.load_der_x509_crl(base64.b64decode(obj["delta"], validate=True))
        return base, delta
    except (ValueError, TypeError, KeyError) as exc:
        raise PkiError("Niepoprawny pakiet bazy i delty CRL.") from exc


def descriptor(data, kind, target, base=None):
    return {"id": hashlib.sha256(data).hexdigest(), "kind": kind, "number": target,
            "base": base, "size": len(data), "zlib_size": len(zlib.compress(data))}


class CRLCache:
    """Stan atomowy; crl.der jest zgodną wstecznie kopią wyłącznie podpisanej pełnej bazy."""
    def __init__(self, root: Path):
        self.root = Path(root)
        self.lock = threading.RLock()

    def read(self):
        with self.lock:
            try:
                return decode_state((self.root / "crl_state.json").read_bytes())
            except FileNotFoundError:
                try:
                    return x509.load_der_x509_crl((self.root / "crl.der").read_bytes()), None
                except FileNotFoundError:
                    return None, None

    def current_number(self):
        base, delta = self.read()
        return None if base is None else number(delta if delta is not None else base)

    def update(self, data, ca, kind="full", expected=None):
        from pki.store import PkiError, load_crl
        with self.lock:
            old_base, old_delta = self.read()
            old_number = None if old_base is None else number(old_delta if old_delta is not None else old_base)
            if kind == "bundle":
                base, delta = decode_state(data)
            elif kind == "delta":
                base, delta = old_base, load_crl(data)
                if base is None:
                    raise PkiError("Delta-CRL wymaga pełnej bazy.")
            elif kind == "full":
                base, delta = load_crl(data), None
            else:
                raise PkiError("Nieznany rodzaj aktualizacji CRL.")
            check_object(base, ca)
            if base_number(base) is not None:
                raise PkiError("Potrzebna pełna baza, otrzymano deltę.")
            if delta is not None:
                check_pair(base, delta, ca)
            target = number(delta if delta is not None else base)
            if expected is not None and target != expected:
                raise PkiError("Podpisany numer CRL różni się od zapowiedzianego.")
            if old_number is not None and target <= old_number:
                return False
            if delta is None:
                atomic_write_bytes(self.root / "crl.der", der(base))
            atomic_write_bytes(self.root / "crl_state.json", encode_state(base, delta))
            return True

    def objects(self):
        base, delta = self.read()
        if base is None:
            return []
        if delta is None:
            data = der(base)
            return [(descriptor(data, "full", number(base)), data)]
        packed = encode_state(base, delta)
        data = der(delta)
        return [(descriptor(packed, "bundle", number(delta)), packed),
                (descriptor(data, "delta", number(delta), base_number(delta)), data)]
