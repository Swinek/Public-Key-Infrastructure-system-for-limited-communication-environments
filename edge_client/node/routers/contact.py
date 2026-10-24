"""Contact events: WAN link to the portal established (Łączność), new data announced by a neighbour.

Radio contacts on link establishment come from neighbours.py (hello / hello-ack).
"""
from fastapi import APIRouter, HTTPException, Request

import config
import contact
import neighbours

router = APIRouter(prefix="/api/contact", tags=["Contact triggers"])


@router.post("/wan", summary="WAN link to the portal is up (called by `client.sh internet on`)")
def wan_contact():
    return {"node_id": config.NODE_ID, "event": contact.on_wan()}


@router.post("/announce", summary="A neighbour has new data (CRL, store-and-forward item): pull from it now")
def announced(request: Request):
    host = request.client.host if request.client else None
    entry = neighbours.by_ip(host)
    if entry is None or neighbours.get(entry["id"]) is None:
        raise HTTPException(status_code=404, detail=f"{host} is not a neighbour in radio range of {config.NODE_ID}.")
    return {"status": contact.on_neighbour(entry)["status"]}  # short: the answer goes over the radio link


@router.get("/events", summary="Latest contacts (WAN / radio neighbour) and the result of their exchanges")
def contact_events(limit: int = 50):
    return {"node_id": config.NODE_ID, "events": contact.events(limit)}
