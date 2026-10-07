"""Roles, permissions and role assignment, all scoped to the current tenant."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_tenant, get_current_user, require_permission
from app.core import permissions as perms
from app.core.redis import get_redis
from app.db.session import get_db
from app.models import Tenant, User
from app.schemas.rbac import AssignRolesRequest, PermissionOut, RoleCreate, RoleOut, RoleUpdate
from app.services import rbac_service, tenant_service

router = APIRouter(tags=["rbac"])


@router.get("/permissions", response_model=list[PermissionOut])
async def list_permission_catalogue(_: User = Depends(get_current_user)) -> list[PermissionOut]:
    return [
        PermissionOut(code=code, description=description)
        for code, description in perms.CATALOGUE.items()
    ]


@router.get("/tenants/current/permissions", response_model=list[str])
async def my_permissions(
    tenant: Tenant = Depends(get_current_tenant),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> list[str]:
    """What the caller may do here — handy for hiding buttons in a UI."""
    return sorted(await rbac_service.get_user_permissions(db, redis, tenant.id, user.id))


@router.get("/tenants/current/roles", response_model=list[RoleOut])
async def list_roles(
    tenant: Tenant = Depends(get_current_tenant),
    _: User = Depends(require_permission(perms.ROLES_READ)),
    db: AsyncSession = Depends(get_db),
) -> list[RoleOut]:
    return await rbac_service.list_roles(db, tenant.id)


@router.post("/tenants/current/roles", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
async def create_role(
    body: RoleCreate,
    tenant: Tenant = Depends(get_current_tenant),
    _: User = Depends(require_permission(perms.ROLES_CREATE)),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> RoleOut:
    try:
        return await rbac_service.create_role(db, redis, tenant.id, body.name, body.permissions)
    except rbac_service.RoleNameTaken as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "A role with that name exists") from exc
    except rbac_service.UnknownPermission as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown permissions: {exc}") from exc


@router.put("/tenants/current/roles/{role_id}", response_model=RoleOut)
async def update_role(
    role_id: uuid.UUID,
    body: RoleUpdate,
    tenant: Tenant = Depends(get_current_tenant),
    _: User = Depends(require_permission(perms.ROLES_UPDATE)),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> RoleOut:
    try:
        return await rbac_service.update_role(
            db, redis, tenant.id, role_id, body.name, body.permissions
        )
    except rbac_service.RoleNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Role not found") from exc
    except rbac_service.SystemRoleImmutable as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Built-in roles cannot be changed") from exc
    except rbac_service.RoleNameTaken as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "A role with that name exists") from exc
    except rbac_service.UnknownPermission as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown permissions: {exc}") from exc


@router.delete("/tenants/current/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    role_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    _: User = Depends(require_permission(perms.ROLES_DELETE)),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> None:
    try:
        await rbac_service.delete_role(db, redis, tenant.id, role_id)
    except rbac_service.RoleNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Role not found") from exc
    except rbac_service.SystemRoleImmutable as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Built-in roles cannot be deleted") from exc


@router.get("/tenants/current/users/{user_id}/roles", response_model=list[RoleOut])
async def list_user_roles(
    user_id: uuid.UUID,
    tenant: Tenant = Depends(get_current_tenant),
    _: User = Depends(require_permission(perms.ROLES_READ)),
    db: AsyncSession = Depends(get_db),
) -> list[RoleOut]:
    return await rbac_service.list_user_roles(db, tenant.id, user_id)


@router.put("/tenants/current/users/{user_id}/roles", response_model=list[RoleOut])
async def assign_user_roles(
    user_id: uuid.UUID,
    body: AssignRolesRequest,
    tenant: Tenant = Depends(get_current_tenant),
    _: User = Depends(require_permission(perms.ROLES_ASSIGN)),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),
) -> list[RoleOut]:
    try:
        return await rbac_service.assign_roles(db, redis, tenant.id, user_id, body.role_ids)
    except tenant_service.NotAMember as exc:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "That user is not a member of this tenant"
        ) from exc
    except rbac_service.RoleNotFound as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown roles: {exc}") from exc
