import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Identity, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UUIDPrimaryKeyMixin


class AuditLog(UUIDPrimaryKeyMixin, Base):
    """An append-only record of something that happened.

    Rows are chained: each one stores the hash of the previous row for the same tenant,
    so deleting or editing history breaks the chain and /audit-logs/verify will say so.
    The app's database role is granted SELECT and INSERT only, so the database itself
    refuses updates and deletes.

    No TimestampMixin: an audit row is never updated, and created_at is set in Python
    because it is part of the hashed payload.
    """

    __tablename__ = "audit_logs"

    # Strictly increasing, which gives the chain an unambiguous order even when two
    # rows share a timestamp
    seq: Mapped[int] = mapped_column(BigInteger, Identity(), unique=True)

    # Null for account-level events that belong to no tenant, such as a password reset
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(64))

    ip: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))

    def __repr__(self) -> str:
        return f"<AuditLog {self.seq} {self.action}>"
