"""Append-only, hash-chained audit logging."""

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog

if TYPE_CHECKING:  # auth_service records events, so the import only goes one way
    from app.services.auth_service import ClientInfo

# Account-level events (no tenant)
LOGIN_SUCCEEDED = "auth.login.succeeded"
LOGIN_FAILED = "auth.login.failed"
ACCOUNT_LOCKED = "auth.account.locked"  # noqa: S105 (an action name, not a secret)
LOGOUT = "auth.logout"
PASSWORD_RESET_REQUESTED = "auth.password_reset.requested"  # noqa: S105
PASSWORD_RESET_COMPLETED = "auth.password_reset.completed"  # noqa: S105
EMAIL_VERIFIED = "auth.email.verified"

# Tenant events
TENANT_CREATED = "tenant.created"
INVITE_CREATED = "tenant.invite.created"
INVITE_ACCEPTED = "tenant.invite.accepted"
ROLE_CREATED = "rbac.role.created"
ROLE_UPDATED = "rbac.role.updated"
ROLE_DELETED = "rbac.role.deleted"
ROLES_ASSIGNED = "rbac.roles.assigned"


@dataclass(frozen=True)
class ChainStatus:
    intact: bool
    entries: int
    broken_at_seq: int | None = None


def _chain_lock_key(tenant_id: uuid.UUID | None) -> int:
    """A per-chain advisory lock id. Without it, two concurrent writes could read the
    same previous row and both claim to follow it, breaking the chain."""
    digest = hashlib.sha256(str(tenant_id).encode()).digest()[:8]
    return int.from_bytes(digest, "big", signed=True)


def compute_hash(entry: AuditLog) -> str:
    payload = {
        "previous_hash": entry.previous_hash,
        "tenant_id": str(entry.tenant_id) if entry.tenant_id else None,
        "actor_user_id": str(entry.actor_user_id) if entry.actor_user_id else None,
        "action": entry.action,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "ip": entry.ip,
        "user_agent": entry.user_agent,
        "details": entry.details,
        "created_at": entry.created_at.isoformat(),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


async def record(
    db: AsyncSession,
    action: str,
    *,
    tenant_id: uuid.UUID | None = None,
    actor_user_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    client: "ClientInfo | None" = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Append an entry. The caller commits, so the event and its audit row land together."""
    await db.execute(
        text("SELECT pg_advisory_xact_lock(:key)"), {"key": _chain_lock_key(tenant_id)}
    )

    previous_hash = await db.scalar(
        select(AuditLog.hash)
        .where(AuditLog.tenant_id == tenant_id if tenant_id else AuditLog.tenant_id.is_(None))
        .order_by(AuditLog.seq.desc())
        .limit(1)
    )

    entry = AuditLog(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        ip=client.ip if client else None,
        user_agent=client.user_agent[:512] if client and client.user_agent else None,
        details=details or {},
        created_at=datetime.now(UTC),
        previous_hash=previous_hash,
    )
    entry.hash = compute_hash(entry)
    db.add(entry)
    await db.flush()
    return entry


async def list_entries(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    action: str | None = None,
    actor_user_id: uuid.UUID | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[AuditLog]:
    query = select(AuditLog).where(AuditLog.tenant_id == tenant_id)
    if action:
        query = query.where(AuditLog.action == action)
    if actor_user_id:
        query = query.where(AuditLog.actor_user_id == actor_user_id)
    result = await db.scalars(query.order_by(AuditLog.seq.desc()).limit(limit).offset(offset))
    return list(result)


async def verify_chain(db: AsyncSession, tenant_id: uuid.UUID) -> ChainStatus:
    """Re-hash every entry in order and check it still matches, including its link to
    the entry before it. Catches an edited row, and a deleted one."""
    entries = list(
        await db.scalars(
            select(AuditLog).where(AuditLog.tenant_id == tenant_id).order_by(AuditLog.seq)
        )
    )
    expected_previous: str | None = None
    for entry in entries:
        if entry.previous_hash != expected_previous or entry.hash != compute_hash(entry):
            return ChainStatus(intact=False, entries=len(entries), broken_at_seq=entry.seq)
        expected_previous = entry.hash
    return ChainStatus(intact=True, entries=len(entries))
