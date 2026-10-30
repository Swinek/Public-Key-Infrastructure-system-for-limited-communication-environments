"""CA: margines wygaśnięcia i równoważność skumulowanej delty z pełną CRL."""
from datetime import datetime, timedelta, timezone
from cryptography import x509


def test_expired_entries_keep_margin(ca_env):
    ca = ca_env.ca
    now = datetime.now(timezone.utc)
    margin = timedelta(hours=ca.CRL_EXPIRY_MARGIN_HOURS)
    records = [
        {"serial_number": "1", "revoked_at": now-timedelta(days=4), "valid_to": now-margin-timedelta(seconds=1)},
        {"serial_number": "2", "revoked_at": now-timedelta(days=4), "valid_to": now-margin},
        {"serial_number": "3", "revoked_at": now-timedelta(days=4), "valid_to": now+timedelta(days=1)},
        {"serial_number": "4", "revoked_at": now-timedelta(days=4), "valid_to": None},
    ]
    for item in records:
        item["expiry_crl_seen_at"] = now-timedelta(hours=1)
    records.append({"serial_number": "5", "valid_to": now-margin-timedelta(days=2)})
    crl = ca.generate_crl(records, 1, now)
    assert {e.serial_number for e in crl} == {2, 3, 4, 5}


def test_cumulative_delta_and_expired_removals(ca_env):
    ca = ca_env.ca
    now = datetime.now(timezone.utc)
    def record(serial):
        return {"serial_number": str(serial), "revoked_at": now-timedelta(hours=1)}
    base = ca.generate_crl([record(1), record(2)], 1, now)
    intermediate = ca.generate_crl([record(1), record(2), record(3)], 2, now)
    current = ca.generate_crl([record(2), record(4)], 3, now)
    delta = ca.generate_delta_crl(base, current, [intermediate])
    assert delta.extensions.get_extension_for_class(x509.DeltaCRLIndicator).critical
    assert delta.extensions.get_extension_for_class(x509.DeltaCRLIndicator).value.crl_number == 1
    assert delta.is_signature_valid(ca.load_ca_certificate().public_key())
    def merge(full):
        result = {e.serial_number for e in full}
        for entry in delta:
            try:
                remove = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason == x509.ReasonFlags.remove_from_crl
            except x509.ExtensionNotFound:
                remove = False
            if remove:
                result.discard(entry.serial_number)
            else:
                result.add(entry.serial_number)
        return result
    assert merge(base) == merge(intermediate) == {2, 4}
