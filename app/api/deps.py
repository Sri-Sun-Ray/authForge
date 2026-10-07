"""Shared FastAPI dependencies.

Still to implement:
- get_current_tenant (Milestone 2): tenant_id from the token; also set
  `SET LOCAL app.tenant_id = ...` on the DB session so Postgres RLS applies
- require_permission("users:invite") (Milestone 3): check the user's permissions
  for the current tenant, cached in Redis
"""

import uuid
from collections.abc import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import TokenError, decode_access_token
from app.db.session import get_db
from app.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def unauthorized(detail: str = "Could not validate credentials") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)
) -> User:
    try:
        claims = decode_access_token(token)
        user_id = uuid.UUID(claims["sub"])
    except (TokenError, ValueError) as exc:
        raise unauthorized() from exc

    # Checked on every request so a deactivated user loses access immediately,
    # not only when their access token expires
    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise unauthorized()
    return user


async def get_current_tenant():
    raise NotImplementedError


def require_permission(permission: str) -> Callable:
    async def checker():
        raise NotImplementedError

    return checker
