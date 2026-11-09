from datetime import date, datetime, time, timedelta, timezone
from functools import lru_cache
import logging

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import APIRouter, Request, Response

from database import get_pool
from pki.ca import CURVE, HASH, LEAF_KEY_USAGE, load_ca

router = APIRouter(tags=["OCSP"])
logger = logging.getLogger(__name__)
MAX_REQUEST_BYTES = 4096
RESPONSE_LIFETIME = timedelta(minutes=5)


@lru_cache(maxsize=1)
def _responder(day: date):
    """Keep one short-lived delegated signing key in memory per UTC day."""
    ca_key, issuer = load_ca()
    key = ec.generate_private_key(CURVE)
    midnight = datetime.combine(day, time.min, timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Offline PKI OCSP")]))
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(max(midnight, issuer.not_valid_before_utc))
        .not_valid_after(min(midnight + timedelta(days=2), issuer.not_valid_after_utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(LEAF_KEY_USAGE, critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=True)
        .add_extension(x509.OCSPNoCheck(), critical=False)
        .sign(ca_key, HASH)
    )
    return issuer, key, certificate


def _reply(message):
    if isinstance(message, ocsp.OCSPResponseStatus):
        message = ocsp.OCSPResponseBuilder.build_unsuccessful(message)
    return Response(
        message.public_bytes(serialization.Encoding.DER),
        media_type="application/ocsp-response",
        headers={"Cache-Control": "no-store"},
    )


def _status(row, issuer):
    if row is not None and row["certificate_pem"]:
        # Rows from a previous CA must not be reported as issued by the current CA.
        try:
            certificate = x509.load_pem_x509_certificate(row["certificate_pem"].encode("ascii"))
            certificate.verify_directly_issued_by(issuer)
        except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
            return ocsp.OCSPCertStatus.UNKNOWN, None
        if row["status"] == "REVOKED":
            if row["revoked_at"] is None:
                raise ValueError("Brak daty odwołania w bazie")
            return ocsp.OCSPCertStatus.REVOKED, row["revoked_at"]
        if row["status"] == "ACTIVE":
            return ocsp.OCSPCertStatus.GOOD, None
    return ocsp.OCSPCertStatus.UNKNOWN, None


@router.post("/ocsp", summary="Sprawdź status certyfikatu przez OCSP")
async def respond(request: Request):
    malformed = ocsp.OCSPResponseStatus.MALFORMED_REQUEST
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_REQUEST_BYTES:
            return _reply(malformed)
        body.extend(chunk)

    try:
        query = ocsp.load_der_ocsp_request(bytes(body))
        algorithm = query.hash_algorithm
        serial = query.serial_number
        if not 0 < serial < 1 << 160:
            return _reply(malformed)
        name_hash, key_hash = query.issuer_name_hash, query.issuer_key_hash
        nonce = None
        for ext in query.extensions:
            if isinstance(ext.value, x509.OCSPNonce):
                nonce = ext.value
                if not 1 <= len(nonce.nonce) <= 128:
                    return _reply(malformed)
            elif ext.critical:
                return _reply(malformed)
    except (ValueError, UnsupportedAlgorithm, x509.DuplicateExtension):
        return _reply(malformed)

    try:
        now = datetime.now(timezone.utc)
        issuer, key, responder = _responder(now.date())
        expected = ocsp.OCSPRequestBuilder().add_certificate(issuer, issuer, algorithm).build()
        if (name_hash, key_hash) != (expected.issuer_name_hash, expected.issuer_key_hash):
            return _reply(ocsp.OCSPResponseStatus.UNAUTHORIZED)
        next_update = min(now + RESPONSE_LIFETIME, responder.not_valid_after_utc)
        if not responder.not_valid_before_utc <= now < next_update:
            return _reply(ocsp.OCSPResponseStatus.TRY_LATER)

        row = await get_pool().fetchrow(
            "SELECT certificate_pem, status, revoked_at FROM certificates WHERE serial_number = $1",
            str(serial),
        )
        status, revoked_at = _status(row, issuer)
        builder = (
            ocsp.OCSPResponseBuilder()
            .add_response_by_hash(name_hash, key_hash, serial, algorithm, status,
                                  now, next_update, revoked_at, None)
            .responder_id(ocsp.OCSPResponderEncoding.HASH, responder)
            .certificates([responder])
        )
        if nonce is not None:
            builder = builder.add_extension(nonce, critical=False)
        return _reply(builder.sign(key, hashes.SHA256()))
    except Exception:
        logger.exception("Nie udało się wystawić odpowiedzi OCSP")
        return _reply(ocsp.OCSPResponseStatus.TRY_LATER)
