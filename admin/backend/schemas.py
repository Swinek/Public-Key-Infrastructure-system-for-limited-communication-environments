from typing import Optional
from pydantic import BaseModel


class UserCreate(BaseModel):
    username: str
    email: str
    role: Optional[str] = "user"


class CsrDecision(BaseModel):
    reason: Optional[str] = None


class CertificateRevoke(BaseModel):
    certId: int
    reason: Optional[str] = None
