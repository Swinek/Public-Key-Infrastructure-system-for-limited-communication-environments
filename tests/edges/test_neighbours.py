"""Wykrywanie sąsiadów beaconem (edges/neighbours.py) i dostarczanie tylko do węzłów w zasięgu (routing.py)."""

from __future__ import annotations

import importlib
import json

import pytest

IP_ADDR_OUTPUT = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 192.168.201.10/24 brd 192.168.201.255 scope global eth0\\       valid_lft forever
3: eth1    inet 192.168.12.10/24 brd 192.168.12.255 scope global eth1\\       valid_lft forever
4: eth2    inet 192.168.13.10/24 brd 192.168.13.255 scope global eth2\\       valid_lft forever
5: eth3    inet 172.20.0.5/16 brd 172.20.255.255 scope global eth3\\       valid_lft forever
"""


@pytest.fixture
def mods(edges_env, monkeypatch):
    monkeypatch.setenv("NODE_ID", "client_1")
    monkeypatch.setenv("NEIGHBOUR_TIMEOUT", "7")
    neighbours = importlib.import_module("neighbours")
    routing = importlib.import_module("routing")
    return neighbours, routing


def _beacon(node_id: str, name: str = "", port: int = 8000) -> bytes:
    return json.dumps({"v": 1, "id": node_id, "name": name or node_id, "port": port}).encode()


def test_parse_ip_addr_keeps_only_radio_links(mods):
    neighbours, _ = mods
    ifaces = neighbours.parse_ip_addr(IP_ADDR_OUTPUT)
    # mgmt (192.168.201.x), internet_net (172.x) i loopback nie są łączami radiowymi.
    assert [i["ip"] for i in ifaces] == ["192.168.12.10", "192.168.13.10"]
    assert ifaces[1]["broadcast"] == "192.168.13.255"


def test_beacon_registers_neighbour(mods):
    neighbours, _ = mods
    entry = neighbours.handle_beacon(_beacon("client_2", "Edge App #2"), "192.168.12.20", now=100.0)
    assert entry["id"] == "client_2" and entry["ip"] == "192.168.12.20" and entry["port"] == 8000
    current = neighbours.current(now=101.0)
    assert [n["id"] for n in current] == ["client_2"]
    assert current[0]["name"] == "Edge App #2"
    assert current[0]["last_seen_ago_s"] == 1.0


@pytest.mark.parametrize("data, src", [
    (_beacon("client_1"), "192.168.12.20"),          # własny beacon
    (_beacon("client_2"), "192.168.201.20"),         # spoza łączy radiowych
    (b"not json", "192.168.12.20"),                  # uszkodzony
    (json.dumps({"name": "x"}).encode(), "192.168.12.20"),  # brak id
])
def test_ignored_beacons(mods, data, src):
    neighbours, _ = mods
    assert neighbours.handle_beacon(data, src, now=100.0) is None
    assert neighbours.current(now=100.0) == []


def test_neighbour_expires_after_timeout(mods):
    neighbours, _ = mods
    neighbours.handle_beacon(_beacon("client_2"), "192.168.12.20", now=100.0)
    assert neighbours.current(now=106.9)
    assert neighbours.current(now=107.1) == []  # nie słychać go dłużej niż NEIGHBOUR_TIMEOUT (link down)


def test_routing_only_to_neighbours_in_range(mods, monkeypatch):
    neighbours, routing = mods
    neighbours.handle_beacon(_beacon("client_2"), "192.168.12.20", now=1000.0)
    monkeypatch.setattr(neighbours.time, "time", lambda: 1001.0)

    assert routing.resolve_next_hop("client_2")["ip"] == "192.168.12.20"
    assert routing.peer_url(routing.resolve_next_hop("client_2"), "/x") == "http://192.168.12.20:8000/x"
    # client_3 nie jest w zasięgu – brak tras statycznych, więc nie ma jak do niego dostarczyć.
    with pytest.raises(routing.NoRouteError):
        routing.resolve_next_hop("client_3")
    assert routing.known_destinations() == [{"id": "client_2", "name": "client_2", "direct": True}]


def test_default_recipient_requires_single_neighbour(mods, monkeypatch):
    neighbours, routing = mods
    monkeypatch.setattr(neighbours.time, "time", lambda: 1001.0)
    with pytest.raises(routing.NoRouteError):
        routing.resolve_destination(None)  # brak sąsiadów
    neighbours.handle_beacon(_beacon("client_2"), "192.168.12.20", now=1000.0)
    assert routing.resolve_destination(None) == "client_2"
    neighbours.handle_beacon(_beacon("client_3"), "192.168.13.30", now=1000.0)
    with pytest.raises(routing.NoRouteError):
        routing.resolve_destination(None)  # dwóch sąsiadów – trzeba podać odbiorcę
    assert routing.resolve_destination("client_3") == "client_3"
