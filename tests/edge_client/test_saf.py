"""Store-and-forward (edge_client/node/saf.py, routers/saf.py, routers/p2p.py): kolejka dla węzłów poza zasięgiem,
wymiana listy znanych msg_id, TTL, limit skoków, doręczenie u adresata."""

from __future__ import annotations

import hashlib
import importlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

NEIGHBOUR = {"kind": "neighbour", "id": "client_1", "url": "http://192.168.12.10:8000"}


@pytest.fixture
def node(edge_client_node_env, monkeypatch):
    """Węzeł client_2 bez sąsiadów w zasięgu; announce tylko zapisywany."""
    monkeypatch.setenv("NODE_ID", "client_2")
    saf = importlib.import_module("saf")
    contact = importlib.import_module("contact")
    neighbours = importlib.import_module("neighbours")
    monkeypatch.setattr(neighbours, "p2p_interfaces", lambda: [])
    announced = []
    monkeypatch.setattr(contact, "announce", lambda reason, exclude=None, wait=False: announced.append(exclude) or [])
    saf.announced = announced
    return saf


@pytest.fixture
def client(node):
    app = FastAPI()
    for name in ("routers.p2p", "routers.saf"):
        app.include_router(importlib.import_module(name).router)
    return TestClient(app)


def _item(msg_id="a" * 32, destination="client_3", hops=("client_1",), message="hello", **extra):
    now = datetime.now(timezone.utc)
    return {"msg_id": msg_id, "type": "msg", "origin_id": hops[0], "origin_name": hops[0],
            "destination_id": destination, "hops": list(hops), "created_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(), "message": message, **extra}


def _offer_from(node, monkeypatch, items, files=None):
    """Sąsiad client_1 oferuje `items`; zwraca listę wysłanych zapytań."""
    wire = importlib.import_module("wire")
    sent = []

    def post_json(url, payload, limit):
        sent.append(payload)
        body = json.dumps({"items": [i for i in items if i["msg_id"][:16] not in payload["known"]]}).encode()
        return wire.Fetched(200, body, len(body) + 200)

    def get(url, limit):
        data = (files or {})[url.rsplit("/", 2)[-2]]
        if len(data) > limit:
            raise wire.WireError("limit")
        return wire.Fetched(200, data, len(data) + 200)

    monkeypatch.setattr(wire, "post_json", post_json)
    monkeypatch.setattr(wire, "get", get)
    return sent


def test_message_for_node_out_of_range_is_queued(client, node):
    resp = client.post("/api/p2p/send-message", json={"message": "do client_3", "to": "client_3"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "QUEUED" and body["recipient"] == "client_3"
    queued = node.queue()
    assert len(queued) == 1 and queued[0]["hops"] == ["client_2"] and queued[0]["message"] == "do client_3"
    assert node.announced == [None]


def test_carried_item_is_queued_and_passed_on(node, monkeypatch):
    sent = _offer_from(node, monkeypatch, [_item()])
    assert node.exchange(NEIGHBOUR) == {"delivered": 0, "queued": 1, "duplicate": 0, "rejected": 0, "pages": 1}
    assert node.queue()[0]["hops"] == ["client_1", "client_2"]
    assert node.announced == ["client_1"]  # dalej, ale nie do źródła

    # druga wymiana: client_2 zna już ten msg_id, więc sąsiad nic nie wysyła
    assert node.exchange(NEIGHBOUR)["queued"] == 0
    assert "a" * 16 in sent[1]["known"]


def test_item_for_this_node_is_delivered_to_inbox(node, monkeypatch):
    _offer_from(node, monkeypatch, [_item(destination="client_2", message="dla mnie")])
    assert node.exchange(NEIGHBOUR)["delivered"] == 1
    inbox = importlib.import_module("state").inbox_snapshot()
    assert inbox[-1]["message"] == "dla mnie" and inbox[-1]["route"] == ["client_1", "client_2"]
    assert node.queue() == [] and node.announced == []
    assert node.exchange(NEIGHBOUR)["delivered"] == 0  # nie wraca po doręczeniu


@pytest.mark.parametrize("bad", [
    {"hops": ["client_1", "client_2"]},                      # pętla
    {"expires_at": "2000-01-01T00:00:00+00:00"},             # wygasł
    {"hops": [f"n{i}" for i in range(16)]},                  # limit skoków
    {"msg_id": "../../etc/passwd"},                          # niepoprawny id
])
def test_invalid_items_are_rejected(node, monkeypatch, bad):
    _offer_from(node, monkeypatch, [_item(**bad)])
    assert node.exchange(NEIGHBOUR)["rejected"] == 1
    assert node.queue() == []


def test_file_is_carried_with_checked_content(node, monkeypatch):
    data = b"plik testowy" * 10
    item = _item(msg_id="b" * 32, type="file", filename="raport.txt", size=len(data),
                 sha256=hashlib.sha256(data).hexdigest())
    item.pop("message")
    _offer_from(node, monkeypatch, [item], files={"b" * 32: data})
    assert node.exchange(NEIGHBOUR)["queued"] == 1
    assert node.content("b" * 32) == data


def test_file_with_wrong_content_is_rejected(node, monkeypatch):
    data = b"oryginal"
    item = _item(msg_id="c" * 32, type="file", filename="x.bin", size=len(data),
                 sha256=hashlib.sha256(b"inna tresc").hexdigest())
    item.pop("message")
    _offer_from(node, monkeypatch, [item], files={"c" * 32: data})
    assert node.exchange(NEIGHBOUR)["rejected"] == 1
    assert node.queue() == [] and node.content("c" * 32) is None


def test_ttl_cannot_be_extended_by_a_carrier(node):
    item = _item()
    item["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    node.accept(item)
    expires = datetime.fromisoformat(node.queue()[0]["expires_at"])
    assert expires <= datetime.fromisoformat(item["created_at"]) + timedelta(hours=168, seconds=1)


def test_offer_endpoint_sends_only_unknown_items(client, node):
    node.accept(_item(msg_id="d" * 32))
    node.accept(_item(msg_id="e" * 32))
    resp = client.post("/api/saf/offer", json={"node_id": "client_3", "known": ["d" * 16]})
    assert [i["msg_id"] for i in resp.json()["items"]] == ["e" * 32]
    # sąsiad, który już był na trasie (client_1), nie dostaje kopii
    assert client.post("/api/saf/offer", json={"node_id": "client_1", "known": []}).json()["items"] == []
    offers = [e for e in importlib.import_module("transfers").entries() if e["kind"] == "saf_offer"]
    assert offers[0]["direction"] == "out" and offers[0]["saved_bytes"] == len("hello")


def test_transit_message_received_directly_is_kept_for_store_and_forward(client, node):
    msg = {"msg_id": "f" * 32, "sender_id": "client_1", "sender_name": "#1", "origin_id": "client_1",
           "destination_id": "client_3", "hops": ["client_1"], "message": "przez 2", "sent_at": datetime.now(timezone.utc).isoformat()}
    body = client.post("/api/p2p/receive-message", json=msg).json()
    assert body["status"] == "QUEUED" and node.queue()[0]["hops"] == ["client_1", "client_2"]
    assert client.post("/api/p2p/receive-message", json=msg).json()["status"] == "DUPLICATE"


def _csr_item(msg_id="f" * 64, hops=("client_3",)):
    return {**_item(msg_id=msg_id, destination="portal", hops=hops), "type": "csr", "size": 300, "sha256": msg_id}


def _neighbours_in_range(monkeypatch, wan_of_1: bool):
    """client_2 ma łącza p2p_12 (client_1) i p2p_23 (client_3); client_1 zgłasza w hello flagę WAN."""
    neighbours = importlib.import_module("neighbours")
    ifaces = [{"ifname": "eth1", "ip": "192.168.12.20", "network": "192.168.12.0/24", "broadcast": "192.168.12.255"},
              {"ifname": "eth2", "ip": "192.168.23.20", "network": "192.168.23.0/24", "broadcast": "192.168.23.255"}]
    monkeypatch.setattr(neighbours, "p2p_interfaces", lambda: ifaces)
    for node_id, ip, wan in (("client_1", "192.168.12.10", wan_of_1), ("client_4", "192.168.23.40", False)):
        pkt = json.dumps({"t": "hello", "id": node_id, "name": node_id, "port": 8000, "wan": wan}).encode()
        neighbours.handle_packet(pkt, ip)


def test_request_goes_first_only_to_neighbour_with_wan(node, monkeypatch):
    node.accept(_csr_item(), b"x" * 300)
    node.accept(_item(msg_id="1" * 32, hops=("client_3",)))
    _neighbours_in_range(monkeypatch, wan_of_1=True)
    # Sąsiad bez WAN dostaje wiadomość, ale nie wniosek – ten czeka na client_1 z łączem WAN.
    items, saved = node.offer([], "client_4")
    assert [i["type"] for i in items] == ["msg"] and saved == 300
    # Sąsiad z WAN dostaje wniosek.
    assert sorted(i["type"] for i in node.offer([], "client_1")[0]) == ["csr", "msg"]


def test_request_goes_to_all_when_no_neighbour_has_wan(node, monkeypatch):
    node.accept(_csr_item(), b"x" * 300)
    _neighbours_in_range(monkeypatch, wan_of_1=False)
    assert [i["type"] for i in node.offer([], "client_4")[0]] == ["csr"]
    assert node.carries_requests() is True


def test_known_list_holds_only_items_that_have_not_expired(node, monkeypatch):
    # Element odebrany i przekazany dalej (wniosek oddany do portalu): jego id jest znane do wygaśnięcia.
    node.accept(_item(msg_id="2" * 32, hops=("client_3",)))
    assert node.drop("2" * 32) is True
    assert "2" * 16 in node.known_prefixes()
    # Kopia od innego sąsiada nie wraca, dopóki element żyje.
    assert node.accept(_item(msg_id="2" * 32, hops=("client_4",)))[0] == "duplicate"

    # Po wygaśnięciu (TTL 1 h w _item) id znika z listy wysyłanej przy każdym kontakcie i z seen.json.
    later = datetime.now(timezone.utc) + timedelta(hours=2)
    monkeypatch.setattr(node, "_now", lambda: later)
    assert node.known_prefixes() == []
    assert node.seen() == set()
    node.mark_seen("3" * 32)  # zapis czyści wygasłe wpisy z pliku
    saved = json.loads((node._dir() / "seen.json").read_text(encoding="utf-8"))
    assert list(saved) == ["3" * 32]


def test_old_seen_list_is_kept_for_one_ttl(node, monkeypatch):
    # Stary format seen.json (same id, bez czasu wygaśnięcia): id pamiętane przez jeden pełny TTL od teraz.
    node._save("seen.json", ["4" * 32])
    assert node.known_prefixes() == ["4" * 16]
    later = datetime.now(timezone.utc) + timedelta(hours=node.config.SAF_TTL_HOURS + 1)
    monkeypatch.setattr(node, "_now", lambda: later)
    assert node.known_prefixes() == []


def test_offer_is_split_into_pages(node):
    items = [_item(msg_id=str(d) * 32, message="x" * 100) for d in range(5, 9)]
    size = len(json.dumps(items[0], separators=(",", ":"), ensure_ascii=False).encode())
    first, more = node.page(items, limit=2 * size)
    assert [i["msg_id"] for i in first] == [items[0]["msg_id"], items[1]["msg_id"]] and more is True
    assert node.page(items[2:], limit=2 * size) == (items[2:], False)
    # Element większy niż limit idzie sam - porcja zawsze posuwa wymianę naprzód.
    assert node.page(items, limit=1) == ([items[0]], True)


def _paged_neighbour(node, monkeypatch, items, limit):
    """Sąsiad, który odsyła brakujące elementy porcjami po `limit` bajtów (jak routers/saf.py)."""
    wire = importlib.import_module("wire")
    calls = []

    def post_json(url, payload, max_bytes):
        calls.append(payload)
        missing = [i for i in items if i["msg_id"][:16] not in payload["known"]]
        page, more = node.page(missing, limit=limit)
        body = json.dumps({"items": page, "more": more}).encode()
        assert len(body) <= max_bytes
        return wire.Fetched(200, body, len(body) + 200)

    monkeypatch.setattr(wire, "post_json", post_json)
    return calls


def test_long_queue_is_taken_page_by_page_in_one_contact(node, monkeypatch):
    items = [_item(msg_id=f"{d:x}" * 32, message="x" * 100) for d in range(1, 8)]
    size = len(json.dumps(items[0], separators=(",", ":"), ensure_ascii=False).encode())
    calls = _paged_neighbour(node, monkeypatch, items, limit=3 * size)
    counts = node.exchange(NEIGHBOUR)
    assert counts["queued"] == 7 and counts["pages"] == 3
    # Każda kolejna prośba zawiera już elementy z poprzedniej porcji.
    assert [len(c["known"]) for c in calls] == [0, 3, 6]


def test_rejected_item_is_not_offered_again_in_the_next_page(node, monkeypatch):
    expired = _item(msg_id="9" * 32)
    expired["expires_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    items = [expired] + [_item(msg_id=f"{d:x}" * 32) for d in range(1, 4)]
    size = len(json.dumps(items[1], separators=(",", ":"), ensure_ascii=False).encode())
    calls = _paged_neighbour(node, monkeypatch, items, limit=size)
    counts = node.exchange(NEIGHBOUR)
    assert counts["rejected"] == 1 and counts["queued"] == 3 and counts["pages"] == 4
    assert "9" * 16 in calls[1]["known"]  # odrzucony nie wraca w kolejnej porcji


def test_pki_items_are_offered_before_messages_and_files(node):
    data = b"plik"
    node.accept({**_item(msg_id="a1" * 16, hops=("client_3",)), "type": "file", "filename": "f.txt",
                 "content_type": "text/plain", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}, data)
    node.accept(_item(msg_id="b2" * 16, hops=("client_3",)))
    node.accept(_csr_item(msg_id="c3" * 32))
    node.accept(_item(msg_id="d4" * 16, hops=("client_3",)))
    items, _ = node.offer([], "client_4")
    # Wniosek idzie pierwszy, potem wiadomości w kolejności przyjęcia, plik na końcu.
    assert [(i["type"], i["msg_id"][:2]) for i in items] == [("csr", "c3"), ("msg", "b2"), ("msg", "d4"), ("file", "a1")]
