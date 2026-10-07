import uuid

from pydantic import BaseModel, ConfigDict, Field

ROLE_NAME_PATTERN = r"^[a-zA-Z0-9][a-zA-Z0-9 _-]*$"


class PermissionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    code: str
    description: str


class RoleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=64, pattern=ROLE_NAME_PATTERN)
    permissions: list[str] = Field(default_factory=list)


class RoleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=64, pattern=ROLE_NAME_PATTERN)
    permissions: list[str] | None = None


class RoleOut(BaseModel):
    id: uuid.UUID
    name: str
    is_system: bool
    permissions: list[str]


class AssignRolesRequest(BaseModel):
    """Replaces the user's roles in this tenant with exactly these."""

    role_ids: list[uuid.UUID]
