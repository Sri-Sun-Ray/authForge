import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError

from app.db.session import SessionLocal
from app.models import RefreshToken, User

integration = pytest.mark.skipif(
    not os.getenv("INTEGRATION"), reason="needs Postgres (set INTEGRATION=1)"
)


def make_user(email: str | None = None) -> User:
    return User(email=email or f"user-{uuid.uuid4().hex[:8]}@example.com", password_hash="x")


def make_token(user: User, **overrides) -> RefreshToken:
    fields = {
        "user_id": user.id,
        "token_hash": uuid.uuid4().hex + uuid.uuid4().hex,
        "family_id": uuid.uuid4(),
        "expires_at": datetime.now(UTC) + timedelta(days=7),
    }
    return RefreshToken(**(fields | overrides))


@integration
async def test_user_defaults() -> None:
    async with SessionLocal() as session:
        user = make_user()
        session.add(user)
        await session.flush()
        await session.refresh(user)

        assert user.is_active is True
        assert user.is_email_verified is False
        assert user.failed_login_count == 0
        assert user.created_at is not None
        await session.rollback()


@integration
async def test_email_must_be_unique() -> None:
    async with SessionLocal() as session:
        session.add(make_user("dup@example.com"))
        await session.flush()
        session.add(make_user("dup@example.com"))
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


@integration
async def test_email_must_be_lowercase() -> None:
    async with SessionLocal() as session:
        session.add(make_user("Mixed@Example.com"))
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()


@integration
async def test_deleting_user_deletes_their_refresh_tokens() -> None:
    async with SessionLocal() as session:
        user = make_user()
        session.add(user)
        await session.flush()
        session.add_all([make_token(user), make_token(user)])
        await session.flush()

        await session.execute(delete(User).where(User.id == user.id))
        count = await session.scalar(
            select(func.count()).select_from(RefreshToken).where(RefreshToken.user_id == user.id)
        )
        assert count == 0
        await session.rollback()


def test_refresh_token_is_usable() -> None:
    now = datetime.now(UTC)
    user = User(id=uuid.uuid4(), email="a@example.com")

    assert make_token(user, expires_at=now + timedelta(minutes=1)).is_usable(now)
    assert not make_token(user, expires_at=now - timedelta(minutes=1)).is_usable(now)
    assert not make_token(user, revoked_at=now).is_usable(now)
