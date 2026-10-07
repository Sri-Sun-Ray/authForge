"""Shared FastAPI dependencies.

Still to implement:
- require_permission("users:invite") (Milestone 3): check the user's permissions
  for the current tenant, cached in Redis
"""

import uuid
from collections.abc import Callable
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TokenError, decode_access_token
from app.db.session import get_db
from app.models import Tenant, User
from app.services import tenant_service

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def unauthorized(detail: str = "Could not validate credentials") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_token_claims(token: str = Depends(oauth2_scheme)) -> dict[str, Any]:
    try:
        return decode_access_token(token)
    except TokenError as exc:
        raise unauthorized() from exc


async def get_current_user(
    claims: dict[str, Any] = Depends(get_token_claims), db: AsyncSession = Depends(get_db)
) -> User:
    try:
        user_id = uuid.UUID(claims["sub"])
    except (KeyError, ValueError) as exc:
        raise unauthorized() from exc

    # Checked on every request so a deactivated user loses access immediately,
    # not only when their access token expires
    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise unauthorized()
    return user


async def get_current_tenant(
    claims: dict[str, Any] = Depends(get_token_claims),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Tenant:
    """The tenant this request works in, taken from the access token.

    Membership is re-checked here, so removing someone from a tenant takes effect at
    once rather than when their token expires.
    """
    raw_tenant_id = claims.get("tenant_id")
    if not raw_tenant_id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "No tenant selected. Call POST /tenants/{tenant_id}/switch first.",
        )
    try:
        tenant_id = uuid.UUID(raw_tenant_id)
    except ValueError as exc:
        raise unauthorized() from exc

    if await tenant_service.get_membership(db, user.id, tenant_id) is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not a member of this tenant")

    # Hand the tenant to Postgres for the rest of this transaction. Row-level security
    # policies read it, so a missing WHERE tenant_id = ... can no longer leak data.
    await db.execute(
        text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
        {"tenant_id": str(tenant_id)},
    )

    tenant = await db.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not a member of this tenant")
    return tenant


def require_permission(permission: str) -> Callable:
    async def checker():
        raise NotImplementedError

    return checker
