import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

SLUG_PATTERN = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"


class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    # Optional: generated from the name when omitted
    slug: str | None = Field(default=None, min_length=3, max_length=63, pattern=SLUG_PATTERN)


class TenantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    created_at: datetime


class SwitchTenantRequest(BaseModel):
    """Switching rotates the session, so the client sends its refresh token."""

    refresh_token: str = Field(min_length=1, max_length=512)


class InviteCreate(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().lower()


class InviteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    expires_at: datetime
    # Returned once, at creation. A real deployment emails this instead of
    # returning it; the raw token is never stored and can't be shown again.
    token: str


class InviteAccept(BaseModel):
    token: str = Field(min_length=1, max_length=512)


class MemberOut(BaseModel):
    user_id: uuid.UUID
    email: EmailStr
    joined_at: datetime
