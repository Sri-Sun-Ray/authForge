"""Roles, permissions and the per-user permission cache."""

import json
import logging
import uuid

from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import permissions as perms
from app.models import Permission, Role, RolePermission, UserRole
from app.schemas.rbac import RoleOut
from app.services.auth_service import AuthError
from app.services.tenant_service import NotAMember, get_membership

logger = logging.getLogger(__name__)

PERMISSION_CACHE_TTL_SECONDS = 300


class RbacError(AuthError):
    pass


class RoleNameTaken(RbacError):
    pass


class UnknownPermission(RbacError):
    pass


class RoleNotFound(RbacError):
    pass


class SystemRoleImmutable(RbacError):
    pass


# --- Permission lookup ------------------------------------------------------


def _generation_key(tenant_id: uuid.UUID) -> str:
    return f"permsgen:{tenant_id}"


def _cache_key(tenant_id: uuid.UUID, generation: str, user_id: uuid.UUID) -> str:
    return f"perms:{tenant_id}:{generation}:{user_id}"


async def invalidate_tenant_permissions(redis: Redis, tenant_id: uuid.UUID) -> None:
    """Drop every cached permission set for this tenant.

    Bumping a counter that is part of the cache key is atomic and O(1); deleting keys
    by pattern would mean scanning the whole keyspace.
    """
    try:
        await redis.incr(_generation_key(tenant_id))
    except RedisError:
        logger.warning("Could not bump permission cache generation", exc_info=True)


async def get_user_permissions(
    db: AsyncSession, redis: Redis, tenant_id: uuid.UUID, user_id: uuid.UUID
) -> set[str]:
    generation = "0"
    cache_key = None
    try:
        generation = await redis.get(_generation_key(tenant_id)) or "0"
        cache_key = _cache_key(tenant_id, generation, user_id)
        cached = await redis.get(cache_key)
        if cached is not None:
            return set(json.loads(cached))
    except RedisError:
        # The cache is an optimisation, never a dependency: fall back to Postgres
        logger.warning("Permission cache unavailable, falling back to the database")
        cache_key = None

    codes = set(
        await db.scalars(
            select(Permission.code)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .join(UserRole, UserRole.role_id == RolePermission.role_id)
            .where(UserRole.user_id == user_id, UserRole.tenant_id == tenant_id)
        )
    )

    if cache_key is not None:
        try:
            await redis.set(cache_key, json.dumps(sorted(codes)), ex=PERMISSION_CACHE_TTL_SECONDS)
        except RedisError:
            logger.warning("Could not cache permissions", exc_info=True)
    return codes


# --- Roles ------------------------------------------------------------------


async def _permission_ids(db: AsyncSession, codes: list[str]) -> list[uuid.UUID]:
    rows = (
        await db.execute(select(Permission.id, Permission.code).where(Permission.code.in_(codes)))
    ).all()
    found = {code: permission_id for permission_id, code in rows}
    unknown = sorted(set(codes) - found.keys())
    if unknown:
        raise UnknownPermission(", ".join(unknown))
    return list(found.values())


async def _role_permission_codes(db: AsyncSession, role_ids: list[uuid.UUID]) -> dict:
    rows = (
        await db.execute(
            select(RolePermission.role_id, Permission.code).join(
                Permission, Permission.id == RolePermission.permission_id
            )
        )
    ).all()
    codes: dict[uuid.UUID, list[str]] = {role_id: [] for role_id in role_ids}
    for role_id, code in rows:
        if role_id in codes:
            codes[role_id].append(code)
    return {role_id: sorted(values) for role_id, values in codes.items()}


async def list_roles(db: AsyncSession, tenant_id: uuid.UUID) -> list[RoleOut]:
    """Built-in roles plus this tenant's own."""
    roles = list(
        await db.scalars(
            select(Role)
            .where((Role.tenant_id == tenant_id) | (Role.tenant_id.is_(None)))
            .order_by(Role.tenant_id.is_not(None), Role.name)
        )
    )
    codes = await _role_permission_codes(db, [role.id for role in roles])
    return [
        RoleOut(
            id=role.id,
            name=role.name,
            is_system=role.is_system,
            permissions=codes.get(role.id, []),
        )
        for role in roles
    ]


async def get_system_role(db: AsyncSession, name: str) -> Role:
    role = await db.scalar(select(Role).where(Role.tenant_id.is_(None), Role.name == name))
    if role is None:  # pragma: no cover - seeded by migration
        raise RoleNotFound(name)
    return role


async def create_role(
    db: AsyncSession, redis: Redis, tenant_id: uuid.UUID, name: str, codes: list[str]
) -> RoleOut:
    permission_ids = await _permission_ids(db, codes)
    role = Role(tenant_id=tenant_id, name=name)
    db.add(role)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise RoleNameTaken from exc

    db.add_all(RolePermission(role_id=role.id, permission_id=pid) for pid in permission_ids)
    await db.commit()
    await invalidate_tenant_permissions(redis, tenant_id)
    return RoleOut(id=role.id, name=name, is_system=False, permissions=sorted(codes))


async def _get_tenant_role(db: AsyncSession, tenant_id: uuid.UUID, role_id: uuid.UUID) -> Role:
    role = await db.get(Role, role_id)
    if role is None or (role.tenant_id is not None and role.tenant_id != tenant_id):
        raise RoleNotFound(str(role_id))
    if role.is_system:
        raise SystemRoleImmutable(role.name)
    return role


async def update_role(
    db: AsyncSession,
    redis: Redis,
    tenant_id: uuid.UUID,
    role_id: uuid.UUID,
    name: str | None,
    codes: list[str] | None,
) -> RoleOut:
    role = await _get_tenant_role(db, tenant_id, role_id)
    if name is not None:
        role.name = name
    if codes is not None:
        permission_ids = await _permission_ids(db, codes)
        await db.execute(delete(RolePermission).where(RolePermission.role_id == role.id))
        db.add_all(RolePermission(role_id=role.id, permission_id=pid) for pid in permission_ids)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise RoleNameTaken from exc

    # Permissions changed, so every cached set in this tenant is now stale
    await invalidate_tenant_permissions(redis, tenant_id)
    current = await _role_permission_codes(db, [role.id])
    return RoleOut(
        id=role.id, name=role.name, is_system=False, permissions=current.get(role.id, [])
    )


async def delete_role(
    db: AsyncSession, redis: Redis, tenant_id: uuid.UUID, role_id: uuid.UUID
) -> None:
    role = await _get_tenant_role(db, tenant_id, role_id)
    await db.delete(role)  # user_roles and role_permissions cascade
    await db.commit()
    await invalidate_tenant_permissions(redis, tenant_id)


# --- Assignments ------------------------------------------------------------


async def list_user_roles(
    db: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID
) -> list[RoleOut]:
    roles = list(
        await db.scalars(
            select(Role)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.tenant_id == tenant_id, UserRole.user_id == user_id)
            .order_by(Role.name)
        )
    )
    codes = await _role_permission_codes(db, [role.id for role in roles])
    return [
        RoleOut(
            id=role.id,
            name=role.name,
            is_system=role.is_system,
            permissions=codes.get(role.id, []),
        )
        for role in roles
    ]


async def assign_roles(
    db: AsyncSession,
    redis: Redis,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    role_ids: list[uuid.UUID],
) -> list[RoleOut]:
    """Replace the user's roles in this tenant."""
    if await get_membership(db, user_id, tenant_id) is None:
        raise NotAMember

    if role_ids:
        valid = set(
            await db.scalars(
                select(Role.id).where(
                    Role.id.in_(role_ids),
                    (Role.tenant_id == tenant_id) | (Role.tenant_id.is_(None)),
                )
            )
        )
        # A role from another tenant must never be grantable here
        if missing := set(role_ids) - valid:
            raise RoleNotFound(", ".join(str(role_id) for role_id in sorted(missing)))

    await db.execute(
        delete(UserRole).where(UserRole.tenant_id == tenant_id, UserRole.user_id == user_id)
    )
    db.add_all(
        UserRole(tenant_id=tenant_id, user_id=user_id, role_id=role_id)
        for role_id in dict.fromkeys(role_ids)
    )
    await db.commit()
    await invalidate_tenant_permissions(redis, tenant_id)
    return await list_user_roles(db, tenant_id, user_id)


async def grant_system_role(
    db: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID, name: str
) -> None:
    """Grant a built-in role. Caller commits."""
    role = await get_system_role(db, name)
    exists = await db.scalar(
        select(UserRole.id).where(
            UserRole.tenant_id == tenant_id,
            UserRole.user_id == user_id,
            UserRole.role_id == role.id,
        )
    )
    if exists is None:
        db.add(UserRole(tenant_id=tenant_id, user_id=user_id, role_id=role.id))


async def grant_owner_role(db: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID) -> None:
    """Called when a tenant is created: its creator owns it."""
    await grant_system_role(db, tenant_id, user_id, perms.OWNER)
