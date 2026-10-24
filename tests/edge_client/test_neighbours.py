"""Sąsiedzi poznawani jednorazowym hello przy zestawieniu łącza (edge_client/node/neighbours.py)
i dostarczanie tylko do węzłów w zasięgu (edge_client/node/routing.py)."""

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
def mods(edge_client_node_env, monkeypatch):
    monkeypatch.setenv("NODE_ID", "client_1")
    neighbours = importlib.import_module("neighbours")
    routing = importlib.import_module("routing")
    # Łącza węzła 1 jak w IP_ADDR_OUTPUT: p2p_12 i p2p_13.
    monkeypatch.setattr(neighbours, "p2p_interfaces", lambda: neighbours.parse_ip_addr(IP_ADDR_OUTPUT))
    return neighbours, routing


def _pkt(kind: str, node_id: str, name: str = "", port: int = 8000) -> bytes:
    return json.dumps({"t": kind, "id": node_id, "name": name or node_id, "port": port}).encode()


def test_parse_ip_addr_keeps_only_radio_links(mods):
    neighbours, _ = mods
    ifaces = neighbours.parse_ip_addr(IP_ADDR_OUTPUT)
    # mgmt (192.168.201.x), internet_net (172.x) i loopback nie są łączami radiowymi.
    assert [i["ip"] for i in ifaces] == ["192.168.12.10", "192.168.13.10"]
    assert ifaces[1]["network"] == "192.168.13.0/24"
    assert ifaces[1]["broadcast"] == "192.168.13.255"


def test_hello_registers_and_requests_reply(mods):
    neighbours, _ = mods
    entry = neighbours.handle_packet(_pkt("hello", "client_2", "Edge App #2"), "192.168.12.20", now=100.0)
    assert entry["reply"] is True  # na hello odpowiada się jednym hello-ack
    current = neighbours.current()
    assert [(n["id"], n["ip"], n["name"]) for n in current] == [("client_2", "192.168.12.20", "Edge App #2")]
    assert current[0]["connected_since"] == 100.0


def test_hello_ack_registers_without_reply(mods):
    neighbours, _ = mods
    entry = neighbours.handle_packet(_pkt("hello-ack", "client_3"), "192.168.13.30", now=100.0)
    assert entry["reply"] is False  # na ack nikt nie odpowiada – dwa pakiety na łącze i koniec
    assert [n["id"] for n in neighbours.current()] == ["client_3"]


@pytest.mark.parametrize("data, src", [
    (_pkt("hello", "client_1"), "192.168.12.20"),          # własny pakiet
    (_pkt("hello", "client_2"), "192.168.201.20"),         # spoza łączy radiowych
    (_pkt("ping", "client_2"), "192.168.12.20"),           # nieznany typ
    (b"not json", "192.168.12.20"),                        # uszkodzony
    (json.dumps({"t": "hello"}).encode(), "192.168.12.20"),  # brak id
])
def test_ignored_packets(mods, data, src):
    neighbours, _ = mods
    assert neighbours.handle_packet(data, src) is None
    assert neighbours.current() == []


def test_neighbour_disappears_with_its_link(mods):
    neighbours, _ = mods
    neighbours.handle_packet(_pkt("hello", "client_2"), "192.168.12.20")
    neighbours.handle_packet(_pkt("hello", "client_3"), "192.168.13.30")
    # link down 1 2: interfejs p2p_12 znika -> client_2 przestaje być sąsiadem (bez żadnego ruchu radiowego).
    only_13 = [i for i in neighbours.parse_ip_addr(IP_ADDR_OUTPUT) if i["ip"] == "192.168.13.10"]
    assert [n["id"] for n in neighbours.current(only_13)] == ["client_3"]
    # Wpis jest usunięty na stałe: po ponownym link up potrzebne jest nowe hello.
    assert [n["id"] for n in neighbours.current()] == ["client_3"]


def test_routing_only_to_neighbours_in_range(mods):
    neighbours, routing = mods
    neighbours.handle_packet(_pkt("hello", "client_2"), "192.168.12.20")

    assert routing.peer_url(routing.resolve_next_hop("client_2"), "/x") == "http://192.168.12.20:8000/x"
    # client_3 nie odpowiedział na hello – brak tras statycznych, więc nie ma jak do niego dostarczyć.
    with pytest.raises(routing.NoRouteError):
        routing.resolve_next_hop("client_3")
    assert routing.known_destinations() == [{"id": "client_2", "name": "client_2", "direct": True}]


def test_default_recipient_requires_single_neighbour(mods):
    neighbours, routing = mods
    with pytest.raises(routing.NoRouteError):
        routing.resolve_destination(None)  # brak sąsiadów
    neighbours.handle_packet(_pkt("hello", "client_2"), "192.168.12.20")
    assert routing.resolve_destination(None) == "client_2"
    neighbours.handle_packet(_pkt("hello-ack", "client_3"), "192.168.13.30")
    with pytest.raises(routing.NoRouteError):
        routing.resolve_destination(None)  # dwóch sąsiadów – trzeba podać odbiorcę
    assert routing.resolve_destination("client_3") == "client_3"
