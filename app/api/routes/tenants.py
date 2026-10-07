"""Tenant endpoints: create, list, switch, invite and list members."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_tenant, get_current_user
from app.api.routes.auth import client_info
from app.db.session import get_db
from app.models import Tenant, User
from app.schemas.auth import TokenPair
from app.schemas.tenant import (
    InviteAccept,
    InviteCreate,
    InviteOut,
    MemberOut,
    SwitchTenantRequest,
    TenantCreate,
    TenantOut,
)
from app.services import auth_service, tenant_service

router = APIRouter(prefix="/tenants", tags=["tenants"])
invites_router = APIRouter(prefix="/invites", tags=["tenants"])


@router.post("", response_model=TenantOut, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    body: TenantCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Tenant:
    try:
        return await tenant_service.create_tenant(db, user, body.name, body.slug)
    except tenant_service.SlugTaken as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "Slug is already taken") from exc


@router.get("", response_model=list[TenantOut])
async def list_my_tenants(
    user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
) -> list[Tenant]:
    return await tenant_service.list_tenants_for_user(db, user)


@router.post("/{tenant_id}/switch", response_model=TokenPair)
async def switch_tenant(
    tenant_id: uuid.UUID,
    body: SwitchTenantRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenPair:
    """Swap the session into another tenant, rotating its tokens."""
    try:
        return await tenant_service.switch_tenant(
            db, body.refresh_token, tenant_id, client_info(request)
        )
    except tenant_service.NotAMember as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not a member of this tenant") from exc
    except auth_service.InvalidRefreshToken as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.get("/current", response_model=TenantOut)
async def current_tenant(tenant: Tenant = Depends(get_current_tenant)) -> Tenant:
    return tenant


@router.get("/current/members", response_model=list[MemberOut])
async def list_members(
    tenant: Tenant = Depends(get_current_tenant), db: AsyncSession = Depends(get_db)
) -> list[MemberOut]:
    members = await tenant_service.list_members(db, tenant.id)
    return [
        MemberOut(user_id=user.id, email=user.email, joined_at=membership.created_at)
        for user, membership in members
    ]


@router.post("/current/invites", response_model=InviteOut, status_code=status.HTTP_201_CREATED)
async def invite_member(
    body: InviteCreate,
    tenant: Tenant = Depends(get_current_tenant),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> InviteOut:
    # Milestone 3 will restrict this to Depends(require_permission("users:invite"))
    invite, raw_token = await tenant_service.create_invite(db, tenant.id, body.email, user)
    return InviteOut(
        id=invite.id, email=invite.email, expires_at=invite.expires_at, token=raw_token
    )


@invites_router.post("/accept", response_model=TenantOut)
async def accept_invite(
    body: InviteAccept,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Tenant:
    try:
        return await tenant_service.accept_invite(db, user, body.token)
    except tenant_service.InvalidInvite as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired invite") from exc
