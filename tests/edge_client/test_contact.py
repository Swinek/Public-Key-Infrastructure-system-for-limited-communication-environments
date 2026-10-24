"""Wyzwalacze kontaktu (edge_client/node/contact.py): WAN do portalu i hello/hello-ack sąsiada, bez timerów."""

from __future__ import annotations

import importlib
import json
import threading
import time

import pytest


@pytest.fixture
def contact(edge_client_node_env, monkeypatch):
    monkeypatch.setenv("NODE_ID", "client_1")
    monkeypatch.setenv("PORTAL_URL", "http://portal:5001/")
    return importlib.import_module("contact")


def test_wan_contact_runs_handlers_with_portal_peer(contact):
    seen = []
    contact.register(seen.append)
    event = contact.trigger(contact.portal_peer(), wait=True)
    assert seen == [{"kind": "wan", "id": "portal", "url": "http://portal:5001"}]
    assert event["status"] == "done" and event["handlers"] == 1
    assert contact.events()[0]["peer"] == "portal"


def test_neighbour_peer_url_from_hello_entry(contact):
    peer = contact.neighbour_peer({"id": "client_2", "name": "Edge client #2", "ip": "192.168.12.20", "port": 8000})
    assert peer["kind"] == "neighbour" and peer["url"] == "http://192.168.12.20:8000"


def test_trigger_for_busy_peer_runs_one_more_round(contact):
    """Wyzwalacz w trakcie wymiany nie ginie (np. announce nowej CRL) – po niej idzie jeszcze jedna runda."""
    release, started, finished = threading.Event(), threading.Event(), threading.Event()
    calls = []

    def slow(peer):
        calls.append(peer["id"])
        started.set()
        release.wait(5)
        if len(calls) == 2:
            finished.set()

    contact.register(slow)
    first = contact.trigger(contact.portal_peer())
    assert started.wait(5)
    second = contact.trigger(contact.portal_peer())
    third = contact.trigger(contact.portal_peer())
    release.set()
    assert finished.wait(5)
    assert first["status"] == "running" and second["status"] == third["status"] == "queued"
    for _ in range(100):  # wpis zdarzenia uzupełnia się po ostatniej rundzie
        if contact.events()[-1]["status"] != "running":
            break
        time.sleep(0.02)
    assert len(calls) == 2  # kilka wyzwoleń w trakcie = jedna dodatkowa runda
    assert contact.events()[-1]["rounds"] == 2


def test_failed_handler_does_not_stop_others_and_frees_peer(contact):
    seen = []

    def broken(peer):
        raise RuntimeError("link lost")

    contact.register(broken)
    contact.register(seen.append)
    event = contact.trigger(contact.portal_peer(), wait=True)
    assert event["status"] == "failed" and "link lost" in event["errors"][0]
    assert len(seen) == 1
    assert contact.trigger(contact.portal_peer(), wait=True)["status"] == "failed"  # not stuck as busy


def test_hello_and_hello_ack_both_trigger_contact(edge_client_node_env, monkeypatch):
    monkeypatch.setenv("NODE_ID", "client_1")
    neighbours = importlib.import_module("neighbours")
    contact = importlib.import_module("contact")
    triggered = []
    monkeypatch.setattr(contact, "on_neighbour", lambda entry: triggered.append(entry["id"]))
    monkeypatch.setattr(neighbours, "_send", lambda *a, **k: None)
    monkeypatch.setattr(neighbours, "p2p_interfaces", lambda: [])

    packets = [(json.dumps({"t": t, "id": "client_2", "port": 8000}).encode(), ("192.168.12.20", 8999))
               for t in ("hello", "hello-ack")]

    class FakeSocket:
        def __init__(self, *a): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def setsockopt(self, *a): pass
        def bind(self, *a): pass
        def recvfrom(self, n):
            if not packets:
                raise StopIteration
            return packets.pop(0)

    monkeypatch.setattr(neighbours.socket, "socket", FakeSocket)
    with pytest.raises(StopIteration):
        neighbours._receive_loop()
    assert triggered == ["client_2", "client_2"]
