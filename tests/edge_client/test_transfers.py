"""Rejestr przesłanych danych (edge_client/node/transfers.py, routers/stats.py) i limit rozmiaru w wire.py."""

from __future__ import annotations

import csv
import importlib
import io

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def transfers(edge_client_node_env, monkeypatch):
    monkeypatch.setenv("NODE_ID", "client_1")
    return importlib.import_module("transfers")


def test_records_are_summed_by_kind_peer_and_direction(transfers):
    transfers.record("crl_full", "in", "client_2", 400, 650, encoding="DER", number=5)
    transfers.record("crl_full", "in", "client_2", status="skipped", saved_bytes=400, number=5)
    transfers.record("summary", "out", "client_3", 200, 450)
    s = transfers.summary()
    assert s["records"] == 3
    assert s["total"]["wire_bytes"] == 1100 and s["total"]["saved_bytes"] == 400
    assert s["by_kind"]["crl_full"]["count"] == 2 and s["by_kind"]["crl_full"]["status_skipped"] == 1
    assert s["by_peer"]["client_2"]["payload_bytes"] == 400
    assert s["by_direction"]["out"]["wire_bytes"] == 450


def test_unknown_kind_is_refused(transfers):
    with pytest.raises(ValueError):
        transfers.record("cookie", "in", "x")


def test_stats_endpoint_csv_and_reset(transfers):
    app = FastAPI()
    app.include_router(importlib.import_module("routers.stats").router)
    client = TestClient(app)
    transfers.record("msg", "out", "client_2", 5, 300, number="ab")

    assert client.get("/api/stats/transfers").json()["total"]["count"] == 1
    rows = list(csv.DictReader(io.StringIO(client.get("/api/stats/transfers?format=csv").text)))
    assert rows[0]["node_id"] == "client_1" and rows[0]["kind"] == "msg" and rows[0]["wire_bytes"] == "300"
    assert client.delete("/api/stats/transfers").json()["removed"] == 1
    assert client.get("/api/stats/transfers").json()["records"] == 0


def test_download_is_aborted_above_the_limit(transfers):
    wire = importlib.import_module("wire")

    class Resp:
        def iter_content(self, chunk_size):
            yield b"x" * 4096
            yield b"x" * 4096

        def close(self):
            self.closed = True

    with pytest.raises(wire.WireError, match="limit"):
        wire._read_limited(Resp(), 5000)
    assert wire._read_limited(Resp(), 8192) == b"x" * 8192
