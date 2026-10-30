"""Portal: kompresja nie zmienia podpisanego obiektu i rozdziela ETag reprezentacji."""
import zlib

from fastapi import Request


def test_portal_crl_compression_and_etags(component_importer):
    component_importer("edge_client")
    from store import pki_object_response
    data = b"DER" * 200
    request = Request({"type": "http", "headers": []})
    args = (request, data, "der", "X509 CRL", "crl", "application/pkix-crl", "crl-1")
    plain = pki_object_response(*args)
    packed = pki_object_response(*args, compression="zlib")
    assert zlib.decompress(packed.body) == plain.body
    assert len(packed.body) < len(plain.body)
    assert packed.headers["etag"] != plain.headers["etag"]
    cached = Request({"type": "http", "headers": [(b"if-none-match", packed.headers["etag"].encode())]})
    response = pki_object_response(cached, *args[1:], compression="zlib")
    assert response.status_code == 304 and response.body == b""
