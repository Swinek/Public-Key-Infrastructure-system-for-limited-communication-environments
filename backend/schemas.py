from typing import Optional
from pydantic import BaseModel


class UserCreate(BaseModel):
    username: str
    email: str
    role: Optional[str] = "user"


class CertificateCreate(BaseModel):
    userId: int


class CertificateRevoke(BaseModel):
    certId: int
    reason: Optional[str] = None
