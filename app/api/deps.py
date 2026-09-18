"""Shared FastAPI dependencies.

Implement as you go:
- get_current_user (Milestone 1): read the Bearer token, decode it, load the user
- get_current_tenant (Milestone 2): tenant_id from the token; also set
  `SET LOCAL app.tenant_id = ...` on the DB session so Postgres RLS applies
- require_permission("users:invite") (Milestone 3): check the user's permissions
  for the current tenant, cached in Redis
"""

from collections.abc import Callable

from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


async def get_current_user():
    raise NotImplementedError


async def get_current_tenant():
    raise NotImplementedError


def require_permission(permission: str) -> Callable:
    async def checker():
        raise NotImplementedError

    return checker
