"""Delivery over the radio links: only to neighbours that are in range right now.

The node has no routing table and no knowledge of the topology - its neighbours are the nodes
that answered its hello on a link that still exists (neighbours.py). Anyone else gets NoRouteError.

A destination out of range is not an error for messages and files: routers/p2p.py hands them to the
store-and-forward queue (saf.py), which carries them hop by hop on later contacts.
"""
from typing import Any, Dict, List, Optional

import config
import neighbours


class NoRouteError(Exception):
    pass


def peer_url(peer: Dict[str, Any], path: str) -> str:
    return f"http://{peer['ip']}:{peer.get('port', config.PORT)}{path}"


def resolve_next_hop(destination_id: str) -> Dict[str, Any]:
    peer = neighbours.get(destination_id)
    if peer:
        return peer
    raise NoRouteError(
        f"'{destination_id}' is not in radio range of {config.NODE_ID} (no radio link)."
    )


def known_destinations() -> List[Dict[str, Any]]:
    """Destinations reachable right now (= current neighbours), for UI/CLI."""
    return [{"id": n["id"], "name": n["name"], "direct": True} for n in neighbours.current()]


def resolve_destination(to: Optional[str]) -> str:
    """Default recipient when 'to' is omitted: the only neighbour in range."""
    if to:
        return to
    current = neighbours.current()
    if len(current) == 1:
        return current[0]["id"]
    raise NoRouteError(
        f"Recipient ('to') is required: {len(current)} neighbours in range of {config.NODE_ID}."
    )
