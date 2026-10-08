import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    seq: int
    action: str
    actor_user_id: uuid.UUID | None
    target_type: str | None
    target_id: str | None
    ip: str | None
    details: dict[str, Any]
    created_at: datetime
    hash: str


class ChainStatusOut(BaseModel):
    intact: bool
    entries: int
    broken_at_seq: int | None = None
