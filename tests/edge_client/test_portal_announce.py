"""Impuls z centrum po nowej CRL (edge_client/backend/announce.py): portal budzi węzły, które mają internet."""

from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient


@pytest.fixture
def announce(component_importer):
    component_importer("edge_client")
    import announce as module
    module._ONLINE.clear()
    return module


def test_edge_client_requests_register_the_node(announce):
    app = FastAPI()

    @app.get("/pki/summary")
    def summary(request: Request):
        return {"node": announce.remember(request)}

    client = TestClient(app)
    assert client.get("/pki/summary", headers={"User-Agent": "EdgeClient/client_1"}).json() == {"node": "client_1"}
    assert client.get("/pki/summary", headers={"User-Agent": "curl/8"}).json() == {"node": None}
    assert announce.online() == {"client_1": "testclient"}


def test_notify_wakes_online_nodes_and_drops_unreachable(announce, monkeypatch):
    announce._ONLINE.update({"client_1": "172.30.0.5", "client_2": "172.30.0.6"})
    called = []

    def fake_post(url):
        called.append(url)
        if "172.30.0.6" in url:
            raise OSError("no route to host")  # client_2 po `internet off`
        return 200

    monkeypatch.setattr(announce, "_post", fake_post)
    outcome = asyncio.run(announce.notify_nodes("crl-54"))
    assert outcome["client_1"] == "ok" and "no route" in outcome["client_2"]
    assert "http://172.30.0.5:8000/api/contact/wan" in called
    assert announce.online() == {"client_1": "172.30.0.5"}  # wróci przy następnym kontakcie WAN
