"""Audit log endpoints, scoped to the current tenant."""

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_tenant, require_permission
from app.core import permissions as perms
from app.db.session import get_db
from app.models import AuditLog, Tenant, User
from app.schemas.audit import AuditLogOut, ChainStatusOut
from app.services import audit_service

router = APIRouter(prefix="/audit-logs", tags=["audit"])


@router.get("", response_model=list[AuditLogOut])
async def list_audit_logs(
    action: str | None = None,
    actor_user_id: uuid.UUID | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    tenant: Tenant = Depends(get_current_tenant),
    _: User = Depends(require_permission(perms.AUDIT_READ)),
    db: AsyncSession = Depends(get_db),
) -> list[AuditLog]:
    return await audit_service.list_entries(
        db, tenant.id, action=action, actor_user_id=actor_user_id, limit=limit, offset=offset
    )


@router.get("/verify", response_model=ChainStatusOut)
async def verify_audit_chain(
    tenant: Tenant = Depends(get_current_tenant),
    _: User = Depends(require_permission(perms.AUDIT_READ)),
    db: AsyncSession = Depends(get_db),
) -> ChainStatusOut:
    """Re-hash the tenant's entries to prove none were edited or removed."""
    status = await audit_service.verify_chain(db, tenant.id)
    return ChainStatusOut(
        intact=status.intact, entries=status.entries, broken_at_seq=status.broken_at_seq
    )
