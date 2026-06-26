from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional

class APIKeyBase(BaseModel):
    label: str = Field(..., min_length=1, max_length=100)
    service: str = Field(..., min_length=1, max_length=50)
    expires_at: Optional[datetime] = None

class APIKeyCreate(APIKeyBase):
    value: str = Field(..., min_length=8)

class APIKeyUpdate(BaseModel):
    label: Optional[str] = Field(None, min_length=1, max_length=100)
    service: Optional[str] = Field(None, min_length=1, max_length=50)
    expires_at: Optional[datetime] = None

class APIKeyResponse(APIKeyBase):
    id: int
    key_prefix: str
    status: str
    created_at: datetime
    last_rotated_at: Optional[datetime] = None
    last_scanned_at: Optional[datetime] = None

    class Config:
        from_attributes = True
