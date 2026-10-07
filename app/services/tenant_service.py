"""Tenants, memberships, invites and tenant switching."""

import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import hash_refresh_token
from app.models import Invite, Membership, RefreshToken, Tenant, User
from app.schemas.auth import TokenPair
from app.services import auth_service
from app.services.auth_service import AuthError, ClientInfo


class TenantError(AuthError):
    pass


class SlugTaken(TenantError):
    pass


class NotAMember(TenantError):
    pass


class InvalidInvite(TenantError):
    pass


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:48]
    # Random suffix keeps slugs unique without a retry loop
    return f"{slug or 'tenant'}-{secrets.token_hex(3)}"


# --- Tenants ----------------------------------------------------------------


async def create_tenant(db: AsyncSession, owner: User, name: str, slug: str | None) -> Tenant:
    tenant = Tenant(name=name, slug=slug or slugify(name))
    db.add(tenant)
    try:
        await db.flush()
    except IntegrityError as exc:
        await db.rollback()
        raise SlugTaken from exc

    # The creator is automatically a member (their role comes in Milestone 3)
    db.add(Membership(tenant_id=tenant.id, user_id=owner.id))
    await db.commit()
    await db.refresh(tenant)
    return tenant


async def list_tenants_for_user(db: AsyncSession, user: User) -> list[Tenant]:
    result = await db.scalars(
        select(Tenant)
        .join(Membership, Membership.tenant_id == Tenant.id)
        .where(Membership.user_id == user.id)
        .order_by(Tenant.created_at)
    )
    return list(result)


async def get_membership(
    db: AsyncSession, user_id: uuid.UUID, tenant_id: uuid.UUID
) -> Membership | None:
    return await db.scalar(
        select(Membership).where(Membership.user_id == user_id, Membership.tenant_id == tenant_id)
    )


async def list_members(db: AsyncSession, tenant_id: uuid.UUID) -> list[tuple[User, Membership]]:
    result = await db.execute(
        select(User, Membership)
        .join(Membership, Membership.user_id == User.id)
        .where(Membership.tenant_id == tenant_id)
        .order_by(Membership.created_at)
    )
    return [(user, membership) for user, membership in result]


async def switch_tenant(
    db: AsyncSession, raw_refresh_token: str, tenant_id: uuid.UUID, client: ClientInfo
) -> TokenPair:
    """Re-issue the session's tokens scoped to another tenant the user belongs to."""
    token = await db.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(raw_refresh_token))
    )
    if token is None:
        raise auth_service.InvalidRefreshToken
    if await get_membership(db, token.user_id, tenant_id) is None:
        raise NotAMember
    # Rotating here too means a switch leaves the old token unusable, like any refresh
    return await auth_service.rotate_refresh_token(
        db, raw_refresh_token, client, tenant_id=tenant_id
    )


# --- Invites ----------------------------------------------------------------


async def create_invite(
    db: AsyncSession, tenant_id: uuid.UUID, email: str, invited_by: User
) -> tuple[Invite, str]:
    """Return (invite, raw_token). Only the token's hash is stored."""
    raw_token = secrets.token_urlsafe(32)
    invite = Invite(
        tenant_id=tenant_id,
        email=email.strip().lower(),
        token_hash=hash_refresh_token(raw_token),
        expires_at=datetime.now(UTC) + timedelta(days=get_settings().invite_ttl_days),
        invited_by_user_id=invited_by.id,
    )
    db.add(invite)
    await db.commit()
    await db.refresh(invite)
    return invite, raw_token


async def accept_invite(db: AsyncSession, user: User, raw_token: str) -> Tenant:
    now = datetime.now(UTC)
    invite = await db.scalar(
        select(Invite).where(Invite.token_hash == hash_refresh_token(raw_token)).with_for_update()
    )
    if invite is None or invite.accepted_at is not None or invite.expires_at <= now:
        raise InvalidInvite
    # An invite is for one specific address, so it can't be forwarded to someone else
    if invite.email != user.email:
        raise InvalidInvite

    if await get_membership(db, user.id, invite.tenant_id) is None:
        db.add(Membership(tenant_id=invite.tenant_id, user_id=user.id))
    invite.accepted_at = now
    await db.commit()

    tenant = await db.get(Tenant, invite.tenant_id)
    if tenant is None:  # pragma: no cover - tenant deletion cascades the invite away
        raise InvalidInvite
    return tenant
