"""Store-and-forward over the radio links (saf.py): a neighbour pulls the items it does not know yet."""
from typing import List

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import config
import saf
import transfers
import wire
from routers.pki import peer_id

router = APIRouter(prefix="/api/saf", tags=["Store-and-forward"])


class OfferRequest(BaseModel):
    node_id: str = Field(..., description="Node asking for items")
    known: List[str] = Field(default_factory=list, max_length=100_000,
                             description="Prefixes (16 hex) of msg_id the node already has")


def _wire(request: Request, response: Response, request_body: int) -> int:
    return wire.server_wire_bytes(request.method, request.url.path, request.headers, request_body,
                                  response.status_code, response.raw_headers, len(response.body))


@router.post("/offer", summary="Items this node carries that the asking neighbour does not know yet")
async def offer(request: Request, body: OfferRequest):
    peer = peer_id(request, body.node_id)
    items, saved = saf.offer(body.known, peer)
    response = JSONResponse({"items": items})
    inline = sum(wire.json_payload_size(i) for i in items)
    request_body = int(request.headers.get("content-length") or 0)
    transfers.record("saf_offer", "out", peer, request_body + len(response.body) - inline,
                     _wire(request, response, request_body) - inline, saved_bytes=saved, encoding="JSON",
                     note=f"{len(items)} item(s) offered")
    for item in items:
        if item["type"] == "msg":  # file / csr / cert content is recorded when it is downloaded
            transfers.record("msg", "out", peer, len(item["message"].encode()), wire.json_payload_size(item),
                             number=item["msg_id"], note=f"for {item['destination_id']}")
        elif item["type"] == "csr_result":
            transfers.record("csr", "out", peer, wire.json_payload_size(item["result"]),
                             wire.json_payload_size(item), number=item["msg_id"],
                             note=f"result for {item['destination_id']}")
    return response


@router.get("/items/{msg_id}/content", summary="Content of a file / csr / cert item (raw bytes)")
def item_content(request: Request, msg_id: str):
    data = saf.content(msg_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Item not carried by this node.")
    response = Response(content=data, media_type="application/octet-stream")
    kind = saf.transfer_kind(saf.carried(msg_id) or {"type": "file"})
    transfers.record(kind, "out", peer_id(request), len(data), _wire(request, response, 0),
                     encoding="DER" if kind in ("csr", "cert") else None, number=msg_id)
    return response


@router.get("/queue", summary="Items carried for nodes out of range, and how many ids this node knows")
def get_queue():
    items = saf.queue()
    return {"node_id": config.NODE_ID, "count": len(items), "items": items, "known_ids": len(saf.seen())}
