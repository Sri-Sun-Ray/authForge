from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, Integer, String, false, text, true
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        # Emails are normalized to lowercase before saving; the database enforces it
        # so "A@x.com" and "a@x.com" can never become two accounts.
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        CheckConstraint("failed_login_count >= 0", name="failed_login_count_non_negative"),
    )

    # 320 = maximum length of an email address (RFC 3696)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    # Null for accounts that only sign in with Google (Milestone 4)
    password_hash: Mapped[str | None] = mapped_column(String(255))

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    is_email_verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())

    # Account lockout after repeated failed logins (Milestone 4)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:
        return f"<User {self.id} {self.email}>"
