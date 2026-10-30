"""Offline certificate verification: chain to the Root CA, validity period, status in the local CRL.

Pure function of (certificate, CA, CRL, now) - no network, no clock reading, no files - so the same
inputs always give the same verdict and tests can set "now" freely (stale CRL, clock skew).

Verdicts:
    valid    - issued by the CA, within its validity period, not on a CRL that is current at `now`
    revoked  - on the CRL signed by the CA (also when that CRL is already stale: revocation is final)
    invalid  - not issued by the trusted CA, expired or not yet valid
    unknown  - status cannot be established: no CRL, CRL not trustworthy, CRL stale or from the future

Grace period after nextUpdate and clock skew tolerance are Stage 4.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from cryptography import x509

from pki.store import PkiError, check_crl_signed_by, check_issued_by, crl_number, is_delta_crl


class Status(str, Enum):
    VALID = "valid"
    REVOKED = "revoked"
    INVALID = "invalid"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Verdict:
    status: Status
    reason: str
    serial_number: Optional[str] = None
    crl_number: Optional[int] = None

    @property
    def ok(self) -> bool:
        return self.status is Status.VALID

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        return result


def _hours(delta) -> str:
    return f"{delta.total_seconds() / 3600:.1f} h"


def verify(cert: x509.Certificate, ca: Optional[x509.Certificate],
           crl: Optional[x509.CertificateRevocationList], now: datetime,
           delta: Optional[x509.CertificateRevocationList] = None) -> Verdict:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware (UTC)")
    serial = str(cert.serial_number)

    def verdict(status: Status, reason: str, number: Optional[int] = None) -> Verdict:
        return Verdict(status, reason, serial, number)

    # 1. Chain to the Root CA
    if ca is None:
        return verdict(Status.UNKNOWN, "Brak certyfikatu Root CA w magazynie węzła.")
    if not ca.not_valid_before_utc <= now <= ca.not_valid_after_utc:
        return verdict(Status.INVALID, f"Certyfikat Root CA poza okresem ważności "
                                       f"({ca.not_valid_before_utc} – {ca.not_valid_after_utc}).")
    try:
        check_issued_by(cert, ca)
    except PkiError as exc:
        return verdict(Status.INVALID, str(exc))

    # 2. Validity period
    if now < cert.not_valid_before_utc:
        return verdict(Status.INVALID, f"Certyfikat jeszcze nieważny (ważny od {cert.not_valid_before_utc}).")
    if now > cert.not_valid_after_utc:
        return verdict(Status.INVALID, f"Certyfikat wygasł {cert.not_valid_after_utc}.")

    # 3. Status in the CRL
    if crl is None:
        return verdict(Status.UNKNOWN, "Brak CRL – nie można sprawdzić, czy certyfikat nie został odwołany.")
    try:
        check_crl_signed_by(crl, ca)
    except PkiError as exc:
        return verdict(Status.UNKNOWN, f"CRL odrzucona: {exc}")
    number = crl_number(crl)
    if is_delta_crl(crl):
        return verdict(Status.UNKNOWN, "Delta-CRL bez pełnej listy bazowej nie wystarcza.", number)

    if delta is not None:
        from pki.delta import check_pair, effective_entries, number as signed_number
        try:
            check_pair(crl, delta, ca)
        except PkiError as exc:
            return verdict(Status.UNKNOWN, f"Delta-CRL odrzucona: {exc}", number)
        entry = effective_entries(crl, delta).get(cert.serial_number)
        number = signed_number(delta)
        crl = delta  # pola aktualności pochodzą z podpisanej delty (RFC 5280 §5.2.4)
    else:
        entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if entry is not None:
        try:
            reason = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason.name
        except x509.ExtensionNotFound:
            reason = "unspecified"
        return verdict(Status.REVOKED, f"Certyfikat odwołany {entry.revocation_date_utc} "
                                       f"(powód: {reason}, CRL nr {number}).", number)

    # 4. Freshness of the CRL - absence from a stale list proves nothing
    if crl.next_update_utc is None:
        return verdict(Status.UNKNOWN, "CRL nie ma pola nextUpdate – nie można ocenić jej aktualności.", number)
    if now > crl.next_update_utc:
        return verdict(Status.UNKNOWN, f"Dane PKI nieaktualne: CRL nr {number} wygasła {crl.next_update_utc} "
                                       f"({_hours(now - crl.next_update_utc)} temu).", number)
    if now < crl.last_update_utc:
        return verdict(Status.UNKNOWN, f"CRL nr {number} wystawiona w przyszłości ({crl.last_update_utc}) – "
                                       f"możliwy rozjazd zegara węzła.", number)

    return verdict(Status.VALID, f"Certyfikat ważny (CRL nr {number}, ważna do {crl.next_update_utc}).", number)
