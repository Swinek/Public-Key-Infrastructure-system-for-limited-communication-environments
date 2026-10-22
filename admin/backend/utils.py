import base64
import textwrap


def der_to_pem(der: bytes, label: str) -> bytes:
    """Koduje bajty DER jako PEM (RFC 7468): base64 po 64 znaki między nagłówkami."""
    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode(), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n".encode()
