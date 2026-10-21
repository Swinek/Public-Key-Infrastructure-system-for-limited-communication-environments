import uuid
from typing import List, Optional

from pydantic import BaseModel, Field


class MessagePayload(BaseModel):
    message: str = Field(..., description="P2P message text")
    to: Optional[str] = Field(None, description="Destination node id (e.g. client_3). Optional only if the node has a single neighbour.")


class IncomingMessage(BaseModel):
    msg_id: str = Field(default_factory=lambda: uuid.uuid4().hex, description="Unique message id (end-to-end)")
    sender_id: str = Field(..., description="Previous hop that delivered this message")
    sender_name: str
    origin_id: Optional[str] = Field(None, description="Original author node id (defaults to sender_id)")
    origin_name: Optional[str] = None
    destination_id: Optional[str] = Field(None, description="Final destination node id (defaults to the receiver)")
    hops: List[str] = Field(default_factory=list, description="Nodes traversed so far, starting with the origin")
    message: str
    sent_at: str
