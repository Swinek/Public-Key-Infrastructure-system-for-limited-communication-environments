"""Static next-hop routing over the physical P2P topology.

Rule: destination is a direct neighbour (PEERS) -> send directly;
destination is in ROUTES -> send to its next hop; otherwise -> no route.

Forwarding is synchronous for now. Stage 3 (store-and-forward) can plug a queue in
behind resolve_next_hop() without changing the message format (msg_id, hops).
"""
from typing import Dict, List, Optional

import config


class NoRouteError(Exception):
    pass


def get_peer(peer_id: str) -> Optional[Dict[str, str]]:
    for peer in config.PEERS:
        if peer["id"] == peer_id:
            return peer
    return None


def peer_url(peer: Dict[str, str], path: str) -> str:
    return f"http://{peer['ip']}:{config.PORT}{path}"


def resolve_next_hop(destination_id: str) -> Dict[str, str]:
    peer = get_peer(destination_id)
    if peer:
        return peer
    next_hop_id = config.ROUTES.get(destination_id)
    if next_hop_id:
        peer = get_peer(next_hop_id)
        if peer:
            return peer
    raise NoRouteError(f"No route from {config.NODE_ID} to '{destination_id}'.")


def known_destinations() -> List[Dict[str, Optional[str]]]:
    """Destinations reachable from this node (neighbours + ROUTES keys), for UI/CLI."""
    result = [
        {"id": p["id"], "name": p["name"], "direct": True, "via": None, "via_name": None}
        for p in config.PEERS
    ]
    for dest, hop in config.ROUTES.items():
        if dest == config.NODE_ID or get_peer(dest):
            continue
        hop_peer = get_peer(hop)
        result.append({
            "id": dest,
            "name": config.ROUTE_NAMES.get(dest, dest),
            "direct": False,
            "via": hop,
            "via_name": hop_peer["name"] if hop_peer else hop,
        })
    return result


def resolve_destination(to: Optional[str]) -> str:
    """Default recipient when 'to' is omitted: the only neighbour (backward compatible single-peer API)."""
    if to:
        return to
    if len(config.PEERS) == 1 and not config.ROUTES:
        return config.PEERS[0]["id"]
    raise NoRouteError("Recipient ('to') is required when the node has more than one destination.")
