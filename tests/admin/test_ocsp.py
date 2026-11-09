"""Sprawdzenie formatu OCSP, podpisu i powiązania odpowiedzi z żądaniem."""
import importlib
import shutil
import subprocess
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from fastapi.testclient import TestClient


@pytest.fixture
def service(ca_env, monkeypatch):
    main = importlib.import_module("main")
    route = importlib.import_module("routers.ocsp")
    issued = ca_env.ca.issue_user_certificate("node", "node@example.org")
    cert = x509.load_pem_x509_certificate(issued["certificate_pem"].encode())
    issuer = ca_env.ca.load_ca_certificate()
    row = {"certificate_pem": issued["certificate_pem"], "status": "ACTIVE", "revoked_at": None}

    class Pool:
        async def fetchrow(self, sql, serial):
            return row if serial == str(cert.serial_number) else None

    monkeypatch.setattr(route, "get_pool", Pool)
    monkeypatch.setattr(route, "load_ca", ca_env.ca.load_ca)
    route._responder.cache_clear()
    yield TestClient(main.app), cert, issuer, row
    route._responder.cache_clear()


def _post(client, payload):
    response = client.post("/api/ocsp", content=payload, headers={"Content-Type": "application/ocsp-request"})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/ocsp-response"
    return response.content


def test_ocsp_signed_status_and_nonce(service):
    client, cert, issuer, row = service
    nonce = x509.OCSPNonce(b"n" * 32)
    query = (ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA256())
             .add_extension(nonce, critical=False).build())
    payload = query.public_bytes(serialization.Encoding.DER)
    good = ocsp.load_der_ocsp_response(_post(client, payload))
    assert good.certificate_status == ocsp.OCSPCertStatus.GOOD
    assert good.serial_number == cert.serial_number
    assert good.extensions.get_extension_for_class(x509.OCSPNonce).value == nonce
    signer, = good.certificates
    signer.verify_directly_issued_by(issuer)
    signer.public_key().verify(good.signature, good.tbs_response_bytes, ec.ECDSA(good.signature_hash_algorithm))

    row.update(status="REVOKED", revoked_at=datetime.now(timezone.utc).replace(microsecond=0))
    revoked = ocsp.load_der_ocsp_response(_post(client, payload))
    assert revoked.certificate_status == ocsp.OCSPCertStatus.REVOKED
    assert revoked.revocation_time_utc == row["revoked_at"]


def test_ocsp_unknown_wrong_issuer_and_malformed(service):
    client, cert, issuer, _ = service
    known = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build()
    unknown = ocsp.OCSPRequestBuilder().add_certificate_by_hash(
        known.issuer_name_hash, known.issuer_key_hash, cert.serial_number + 1, hashes.SHA1()
    ).build()
    reply = ocsp.load_der_ocsp_response(_post(client, unknown.public_bytes(serialization.Encoding.DER)))
    assert reply.certificate_status == ocsp.OCSPCertStatus.UNKNOWN

    wrong = ocsp.OCSPRequestBuilder().add_certificate_by_hash(
        known.issuer_name_hash, b"x" * 20, cert.serial_number, hashes.SHA1()
    ).build()
    reply = ocsp.load_der_ocsp_response(_post(client, wrong.public_bytes(serialization.Encoding.DER)))
    assert reply.response_status == ocsp.OCSPResponseStatus.UNAUTHORIZED
    for body in (b"invalid DER", b"x" * 4097):
        reply = ocsp.load_der_ocsp_response(_post(client, body))
        assert reply.response_status == ocsp.OCSPResponseStatus.MALFORMED_REQUEST


def test_openssl_verifies_response(service, tmp_path):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("OpenSSL niedostępny")
    client, cert, issuer, _ = service
    ca_path = tmp_path / "ca.pem"
    leaf_path = tmp_path / "leaf.pem"
    req_path = tmp_path / "request.der"
    resp_path = tmp_path / "response.der"
    ca_path.write_bytes(issuer.public_bytes(serialization.Encoding.PEM))
    leaf_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    subprocess.run([openssl, "ocsp", "-issuer", str(ca_path), "-cert", str(leaf_path),
                    "-reqout", str(req_path)], check=True, capture_output=True)
    resp_path.write_bytes(_post(client, req_path.read_bytes()))
    result = subprocess.run([openssl, "ocsp", "-reqin", str(req_path), "-respin", str(resp_path),
                             "-CAfile", str(ca_path)], check=True, capture_output=True, text=True)
    assert "Response verify OK" in result.stderr
