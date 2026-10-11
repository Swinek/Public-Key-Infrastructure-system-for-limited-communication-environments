from pydantic import BaseModel, Field

class MessagePayload(BaseModel):
    message: str = Field(..., description="P2P message text")

class IncomingMessage(BaseModel):
    sender_id: str
    sender_name: str
    message: str
    sent_at: str
