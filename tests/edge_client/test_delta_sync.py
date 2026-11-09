"""Dobór najmniejszej odpowiedzi, przekazanie hop-by-hop i pamięć ACK."""
import importlib
import json
import zlib
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.pki_factory import TestCA, der

PEER = {"id": "client_2", "kind": "neighbour", "url": "http://peer:8000"}


@pytest.fixture
def node(edge_client_node_env, monkeypatch):
    sync = importlib.import_module("pki_sync")
    monkeypatch.setattr(sync.contact, "announce", lambda *args, **kwargs: None)
    return sync


def test_selects_delta_then_relays_it_and_confirms_after_write(node, monkeypatch, tmp_path):
    from pki.delta import descriptor
    ca = TestCA()
    store = node.certs.get_store()
    store.set_ca(der(ca.cert))
    entries = [SimpleNamespace(serial_number=i) for i in range(1, 201)]
    base = ca.crl(entries, number=1)
    full = ca.crl(entries + [SimpleNamespace(serial_number=201)], number=2)
    delta = ca.crl([SimpleNamespace(serial_number=201)], number=2, delta_base=1)
    store.update_crl(der(base))
    objects = [(descriptor(der(full), "full", 2), der(full)),
               (descriptor(der(delta), "delta", 2, 1), der(delta))]
    calls = []
    def get(url, limit):
        calls.append(url)
        for meta, data in objects:
            if meta["id"] in url:
                body = zlib.compress(data) if "compression=zlib" in url else data
                assert len(body) <= limit
                return node.wire.Fetched(200, body, len(body)+300)
        raise AssertionError(url)
    def ack(url, payload, limit):
        assert store.revocation_number() == 2  # potwierdzenie dopiero po zapisie
        calls.append("ack")
        return node.wire.Fetched(200, b'{"ok":true}', 300)
    monkeypatch.setattr(node.wire, "get", get)
    monkeypatch.setattr(node.wire, "post_json", ack)
    info = {"number": 2, "size": len(der(full)), "updates": [m for m, _ in objects]}
    assert node.sync_crl(PEER, info) == "stored"
    assert objects[1][0]["id"] in calls[0]
    assert calls[-1] == "ack"
    assert store.delta() == delta
    assert node.certs.CertStore(store.root).revocation_number() == 2
    # Węzeł ma tylko bazę+deltę, ale potrafi przekazać oba podpisane obiekty nowemu odbiorcy.
    advertised = store.revocations.objects()
    assert {m["kind"] for m, _ in advertised} == {"bundle", "delta"}
    recipient = node.certs.CertStore(tmp_path / "recipient")
    recipient.set_ca(der(ca.cert))
    bundle = next(data for meta, data in advertised if meta["kind"] == "bundle")
    assert recipient.update_revocation(bundle, "bundle", 2)
    assert recipient.revocation_number() == 2


def test_falls_back_to_full_without_compatible_base(node, monkeypatch):
    from pki.delta import descriptor
    ca = TestCA()
    store = node.certs.get_store()
    store.set_ca(der(ca.cert))
    store.update_crl(der(ca.crl(number=1)))
    full, delta = ca.crl(number=5), ca.crl(number=5, delta_base=3)
    objects = [(descriptor(der(full), "full", 5), der(full)), (descriptor(der(delta), "delta", 5, 3), der(delta))]
    def get(url, limit):
        assert objects[0][0]["id"] in url
        data = zlib.compress(der(full)) if "compression=zlib" in url else der(full)
        return node.wire.Fetched(200, data, len(data)+300)
    monkeypatch.setattr(node.wire, "get", get)
    monkeypatch.setattr(node.wire, "post_json", lambda *args: node.wire.Fetched(200, b"{}", 300))
    assert node.sync_crl(PEER, {"number": 5, "updates": [m for m, _ in objects]}) == "stored"
    assert store.delta() is None and store.revocation_number() == 5


def test_rejected_update_never_acknowledged(node, monkeypatch):
    from pki.delta import descriptor
    ca = TestCA()
    store = node.certs.get_store()
    store.set_ca(der(ca.cert))
    store.update_crl(der(ca.crl(number=1)))
    rogue = der(TestCA().crl(number=2))
    meta = descriptor(rogue, "full", 2)
    def get(url, limit):
        data = zlib.compress(rogue) if "compression=zlib" in url else rogue
        return node.wire.Fetched(200, data, len(data)+300)
    monkeypatch.setattr(node.wire, "get", get)
    monkeypatch.setattr(node.wire, "post_json", lambda *args: pytest.fail("ACK przed weryfikacją"))
    with pytest.raises(node.PkiSyncError):
        node.sync_crl(PEER, {"number": 2, "updates": [meta]})
    assert store.revocation_number() == 1


def test_peer_state_is_persistent_and_detects_data_loss(node):
    import peer_state
    peer_state.pending("client_2", 5)
    peer_state.observe("client_2", 3)
    assert peer_state.read()["client_2"].get("confirmed") is None
    peer_state.confirm("client_2", 5)
    assert peer_state.read()["client_2"]["pending"] is None
    importlib.reload(peer_state)
    assert peer_state.read()["client_2"]["confirmed"] == 5
    peer_state.observe("client_2", None)
    assert peer_state.read()["client_2"]["confirmed"] is None


def test_ack_endpoint_requires_neighbour_and_records_confirmation(node, monkeypatch):
    import neighbours
    import peer_state
    from routers import pki
    monkeypatch.setattr(neighbours, "by_ip", lambda ip: {"id": "client_2"})
    app = FastAPI()
    app.include_router(pki.router)
    client = TestClient(app)
    peer_state.pending("client_2", 4)
    assert client.post("/pki/ack", json={"number": 4}).status_code == 200
    assert peer_state.read()["client_2"]["confirmed"] == 4
    assert peer_state.read()["client_2"]["pending"] is None
    assert client.post("/pki/ack", json={"number": "4"}).status_code == 400
    monkeypatch.setattr(neighbours, "by_ip", lambda ip: None)
    assert client.post("/pki/ack", json={"number": 5}).status_code == 403


def test_empty_summary_clears_stale_confirmation(node):
    import peer_state
    peer_state.confirm("client_2", 10)
    assert node.sync_crl(PEER, None) is None
    assert peer_state.read()["client_2"]["confirmed"] is None


def test_old_ack_does_not_replace_new_confirmation(node):
    import peer_state
    peer_state.confirm("client_2", 10)
    peer_state.confirm("client_2", 9)
    assert peer_state.read()["client_2"]["confirmed"] == 10


def test_full_is_selected_when_compatible_delta_is_larger(node, monkeypatch):
    from pki.delta import descriptor
    ca = TestCA()
    store = node.certs.get_store()
    store.set_ca(der(ca.cert))
    store.update_crl(der(ca.crl(number=1)))
    full = der(ca.crl(number=2))
    delta = der(ca.crl(number=2, delta_base=1))
    meta_full, meta_delta = descriptor(full, "full", 2), descriptor(delta, "delta", 2, 1)
    assert min(meta_full["size"], meta_full["zlib_size"]) < min(meta_delta["size"], meta_delta["zlib_size"])
    def get(url, limit):
        assert meta_full["id"] in url
        data = zlib.compress(full) if "compression=zlib" in url else full
        return node.wire.Fetched(200, data, len(data)+300)
    monkeypatch.setattr(node.wire, "get", get)
    monkeypatch.setattr(node.wire, "post_json", lambda *args: node.wire.Fetched(200, b"{}", 300))
    assert node.sync_crl(PEER, {"number": 2, "updates": [meta_delta, meta_full]}) == "stored"
    assert store.delta() is None


def test_failed_announce_survives_and_retries_on_contact(node, monkeypatch):
    import contact
    import peer_state
    entry = {"id": "client_2", "ip": "192.168.12.20", "port": 8000}
    def fail(*args):
        raise node.wire.WireError("łącze zerwane")
    monkeypatch.setattr(node.wire, "post_json", fail)
    contact._announce_to(entry, "crl-8")
    assert peer_state.read()["client_2"]["pending"] == 8
    importlib.reload(peer_state)
    calls = []
    monkeypatch.setattr(contact, "trigger", lambda peer: {"status": "running"})
    monkeypatch.setattr(contact, "_announce_to", lambda neighbour, reason: calls.append((neighbour["id"], reason)))
    class ImmediateThread:
        def __init__(self, target, args, **kwargs):
            self.target, self.args = target, args
        def start(self):
            self.target(*self.args)
    monkeypatch.setattr(contact.threading, "Thread", ImmediateThread)
    contact.on_neighbour(entry)
    assert calls == [("client_2", "crl-8")]


def test_real_http_delta_chain_and_offline_app(node, monkeypatch, tmp_path):
    from contextlib import contextmanager
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    from urllib.parse import urlsplit
    from pki.delta import descriptor
    from pki.store import PkiStore
    from pki.verifier import verify, Status
    from tests.pki_factory import NOW
    ca = TestCA()
    victim, _ = ca.issue("victim")
    entries = [SimpleNamespace(serial_number=i) for i in range(1, 301)]
    base = ca.crl(entries, number=1)
    full = ca.crl(entries+[victim], number=2)
    delta = ca.crl([victim], number=2, delta_base=1)

    @contextmanager
    def server(objects):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                parsed = urlsplit(self.path)
                for meta, data in objects:
                    if parsed.path == "/pki/updates/"+meta["id"]:
                        body = zlib.compress(data) if parsed.query == "compression=zlib" else data
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                self.send_error(404)
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")
        http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=http.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{http.server_port}"
        finally:
            http.shutdown()
            http.server_close()
            thread.join(timeout=2)

    objects = [(descriptor(der(full), "full", 2), der(full)), (descriptor(der(delta), "delta", 2, 1), der(delta))]
    received = []
    for index in range(3):
        store = node.certs.CertStore(tmp_path / str(index))
        store.set_ca(der(ca.cert))
        if index < 2:
            store.update_crl(der(base))
        monkeypatch.setattr(node.certs, "_store", store)
        with server(objects) as url:
            peer = {"id": f"source_{index}", "kind": "neighbour", "url": url}
            assert node.sync_crl(peer, {"number": 2, "size": len(der(full)), "updates": [m for m, _ in objects]}) == "stored"
        assert store.revocation_number() == 2
        received.append(store)
        objects = store.revocations.objects()
    # Trzeci węzeł bez bazy dostał pakiet dwóch podpisanych obiektów zamiast nieużytecznej delty.
    app = PkiStore(tmp_path / "app")
    app.install_ca(der(ca.cert))
    bundle = next(data for meta, data in objects if meta["kind"] == "bundle")
    assert app.update_revocation(bundle, "bundle", expected=2)
    assert verify(victim, app.ca(), app.crl(), NOW, app.delta()).status == Status.REVOKED
