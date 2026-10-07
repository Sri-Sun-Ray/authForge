import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class RefreshToken(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One row per issued refresh token.

    Rotation: every /auth/refresh revokes the presented token and issues a new one in
    the same family (replaced_by_id links old -> new). If a token that was already
    revoked is presented again, it was stolen or replayed, so the whole family is revoked.
    """

    __tablename__ = "refresh_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    # SHA-256 hex digest of the raw token; the raw token is never stored
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    # All tokens descended from a single login share a family_id
    family_id: Mapped[uuid.UUID] = mapped_column(index=True)
    # Which tenant this session is working in; null until the user picks one.
    # Stored so that refreshing keeps the tenant instead of silently dropping it.
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE")
    )

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    replaced_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("refresh_tokens.id", ondelete="SET NULL")
    )

    # Session metadata, useful for a "your active sessions" page and audit logs
    created_ip: Mapped[str | None] = mapped_column(String(45))  # 45 fits IPv6
    user_agent: Mapped[str | None] = mapped_column(String(512))

    def is_usable(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        return self.revoked_at is None and self.expires_at > now

    def __repr__(self) -> str:
        return f"<RefreshToken {self.id} user={self.user_id} family={self.family_id}>"


class OneTimeToken(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A single-use token emailed to a user: verify this address, or reset this password.

    Stored as a hash like every other token, so a database leak reveals nothing usable.
    """

    __tablename__ = "one_time_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    purpose: Mapped[str] = mapped_column(String(32), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def is_usable(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        return self.used_at is None and self.expires_at > now

    def __repr__(self) -> str:
        return f"<OneTimeToken {self.purpose} user={self.user_id}>"
