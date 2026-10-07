import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Tenant(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An organization. Every tenant-scoped row points at one of these."""

    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(120))
    slug: Mapped[str] = mapped_column(String(63), unique=True)

    def __repr__(self) -> str:
        return f"<Tenant {self.id} {self.slug}>"


class Membership(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Links a user to a tenant. A user can belong to many tenants."""

    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id", name="tenant_user"),)

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )

    def __repr__(self) -> str:
        return f"<Membership tenant={self.tenant_id} user={self.user_id}>"


class Invite(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A pending invitation to join a tenant, redeemed with a one-time token."""

    __tablename__ = "invites"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    email: Mapped[str] = mapped_column(String(320), index=True)
    # Only the hash is stored, exactly like refresh tokens
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    invited_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    def __repr__(self) -> str:
        return f"<Invite {self.id} tenant={self.tenant_id} {self.email}>"
