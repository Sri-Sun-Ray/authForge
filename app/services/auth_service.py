"""Registration, login, refresh-token rotation and logout."""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import (
    create_access_token,
    dummy_password_hash,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    password_needs_rehash,
    verify_password,
)
from app.models import OneTimeToken, RefreshToken, User
from app.schemas.auth import TokenPair
from app.services import mailer

PURPOSE_VERIFY_EMAIL = "verify_email"
PURPOSE_RESET_PASSWORD = "reset_password"  # noqa: S105 (a label, not a secret)


class AuthError(Exception):
    """Base class for errors the API turns into 4xx responses."""


class EmailAlreadyRegistered(AuthError):
    pass


class InvalidCredentials(AuthError):
    pass


class AccountLocked(AuthError):
    """Too many failed logins. Carries the seconds left on the lock."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("Account temporarily locked")
        self.retry_after_seconds = retry_after_seconds


class InvalidRefreshToken(AuthError):
    pass


class InvalidOneTimeToken(AuthError):
    pass


class RefreshTokenReused(InvalidRefreshToken):
    """A revoked token was presented again: it was probably stolen."""


# Sentinel: "keep whatever tenant this session is already in"
KEEP_TENANT = object()


@dataclass(frozen=True)
class ClientInfo:
    ip: str | None = None
    user_agent: str | None = None


def normalize_email(email: str) -> str:
    return email.strip().lower()


# --- Register / login -------------------------------------------------------


async def register_user(db: AsyncSession, email: str, password: str) -> User:
    user = User(email=normalize_email(email), password_hash=hash_password(password))
    db.add(user)
    try:
        # Rely on the unique constraint instead of "check then insert", which has a race
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise EmailAlreadyRegistered from exc
    await db.refresh(user)
    return user


async def authenticate(db: AsyncSession, email: str, password: str) -> User:
    settings = get_settings()
    now = datetime.now(UTC)
    user = await db.scalar(select(User).where(User.email == normalize_email(email)))

    if user is None or user.password_hash is None:
        # Do the same slow hash work as a real check, so response time doesn't
        # reveal whether the email is registered
        verify_password(password, dummy_password_hash())
        raise InvalidCredentials

    if user.locked_until is not None and user.locked_until > now:
        raise AccountLocked(int((user.locked_until - now).total_seconds()))

    if not verify_password(password, user.password_hash):
        # Lock the account after repeated failures, so an attacker cannot work
        # through a password list even from many different IP addresses
        user.failed_login_count += 1
        if user.failed_login_count >= settings.login_max_failed_attempts:
            user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
            user.failed_login_count = 0
        await db.commit()
        raise InvalidCredentials
    if not user.is_active:
        raise InvalidCredentials

    if user.failed_login_count or user.locked_until:
        user.failed_login_count = 0
        user.locked_until = None
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    return user


async def login(db: AsyncSession, email: str, password: str, client: ClientInfo) -> TokenPair:
    user = await authenticate(db, email, password)
    # A fresh login has no tenant yet; the client picks one with /tenants/{id}/switch
    pair, _ = await _issue_tokens(db, user, family_id=uuid.uuid4(), client=client, tenant_id=None)
    await db.commit()
    return pair


# --- Refresh / logout -------------------------------------------------------


async def rotate_refresh_token(
    db: AsyncSession,
    raw_token: str,
    client: ClientInfo,
    tenant_id: uuid.UUID | None | object = KEEP_TENANT,
) -> TokenPair:
    """Rotate a refresh token. By default the session stays in its current tenant;
    pass tenant_id to move it (see tenant_service.switch_tenant)."""
    now = datetime.now(UTC)
    # Lock the row so two concurrent refreshes with the same token can't both succeed
    token = await db.scalar(
        select(RefreshToken)
        .where(RefreshToken.token_hash == hash_refresh_token(raw_token))
        .with_for_update()
    )
    if token is None:
        raise InvalidRefreshToken

    if token.revoked_at is not None:
        # Reuse of a rotated-out token: an attacker or the real user holds a stolen copy.
        # We can't tell which, so end the whole session for both.
        await _revoke_family(db, token.family_id, now)
        await db.commit()
        raise RefreshTokenReused

    if token.expires_at <= now:
        raise InvalidRefreshToken

    user = await db.get(User, token.user_id)
    if user is None or not user.is_active:
        await _revoke_family(db, token.family_id, now)
        await db.commit()
        raise InvalidRefreshToken

    new_tenant_id = token.tenant_id if tenant_id is KEEP_TENANT else tenant_id
    pair, new_token = await _issue_tokens(
        db, user, family_id=token.family_id, client=client, tenant_id=new_tenant_id
    )
    token.revoked_at = now
    token.replaced_by_id = new_token.id
    await db.commit()
    return pair


async def logout(db: AsyncSession, raw_token: str) -> None:
    """Revoke the session this refresh token belongs to. Unknown tokens are ignored,
    so logout is idempotent and doesn't reveal whether a token exists."""
    family_id = await db.scalar(
        select(RefreshToken.family_id).where(
            RefreshToken.token_hash == hash_refresh_token(raw_token)
        )
    )
    if family_id is not None:
        await _revoke_family(db, family_id, datetime.now(UTC))
        await db.commit()


# --- Email verification and password reset ----------------------------------


async def _issue_one_time_token(
    db: AsyncSession, user: User, purpose: str, lifetime: timedelta
) -> str:
    # Any earlier token for the same purpose stops working, so a forwarded or
    # intercepted older email is useless
    await db.execute(
        update(OneTimeToken)
        .where(
            OneTimeToken.user_id == user.id,
            OneTimeToken.purpose == purpose,
            OneTimeToken.used_at.is_(None),
        )
        .values(used_at=datetime.now(UTC))
    )
    raw_token, token_hash = generate_refresh_token()
    db.add(
        OneTimeToken(
            user_id=user.id,
            purpose=purpose,
            token_hash=token_hash,
            expires_at=datetime.now(UTC) + lifetime,
        )
    )
    return raw_token


async def _consume_one_time_token(db: AsyncSession, raw_token: str, purpose: str) -> User:
    token = await db.scalar(
        select(OneTimeToken)
        .where(
            OneTimeToken.token_hash == hash_refresh_token(raw_token),
            OneTimeToken.purpose == purpose,
        )
        .with_for_update()
    )
    if token is None or not token.is_usable():
        raise InvalidOneTimeToken
    user = await db.get(User, token.user_id)
    if user is None or not user.is_active:  # pragma: no cover - deleted mid-flow
        raise InvalidOneTimeToken
    token.used_at = datetime.now(UTC)
    return user


async def request_email_verification(db: AsyncSession, user: User) -> None:
    if user.is_email_verified:
        return
    settings = get_settings()
    raw_token = await _issue_one_time_token(
        db, user, PURPOSE_VERIFY_EMAIL, timedelta(hours=settings.verification_token_ttl_hours)
    )
    await db.commit()
    await mailer.send_email(
        to=user.email,
        subject="Confirm your email address",
        body=f"Confirm your address: {mailer.link('/auth/verify-email/confirm', raw_token)}",
    )


async def confirm_email_verification(db: AsyncSession, raw_token: str) -> User:
    user = await _consume_one_time_token(db, raw_token, PURPOSE_VERIFY_EMAIL)
    user.is_email_verified = True
    await db.commit()
    await db.refresh(user)
    return user


async def request_password_reset(db: AsyncSession, email: str) -> None:
    """Always succeeds from the caller's point of view: an unknown address must look
    exactly like a known one, or this endpoint becomes an account-existence oracle."""
    settings = get_settings()
    user = await db.scalar(select(User).where(User.email == normalize_email(email)))
    if user is None or not user.is_active:
        return

    raw_token = await _issue_one_time_token(
        db,
        user,
        PURPOSE_RESET_PASSWORD,
        timedelta(minutes=settings.password_reset_token_ttl_minutes),
    )
    await db.commit()
    await mailer.send_email(
        to=user.email,
        subject="Reset your password",
        body=f"Reset your password: {mailer.link('/auth/password-reset/confirm', raw_token)}",
    )


async def confirm_password_reset(db: AsyncSession, raw_token: str, new_password: str) -> None:
    user = await _consume_one_time_token(db, raw_token, PURPOSE_RESET_PASSWORD)
    user.password_hash = hash_password(new_password)
    # A reset is also the remedy for a compromised account, so end every session
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(UTC))
    )
    user.failed_login_count = 0
    user.locked_until = None
    await db.commit()


# --- Helpers ----------------------------------------------------------------


async def _issue_tokens(
    db: AsyncSession,
    user: User,
    family_id: uuid.UUID,
    client: ClientInfo,
    tenant_id: uuid.UUID | None,
) -> tuple[TokenPair, RefreshToken]:
    settings = get_settings()
    raw_refresh, refresh_hash = generate_refresh_token()
    refresh_row = RefreshToken(
        user_id=user.id,
        token_hash=refresh_hash,
        family_id=family_id,
        tenant_id=tenant_id,
        expires_at=datetime.now(UTC) + timedelta(days=settings.refresh_token_ttl_days),
        created_ip=client.ip,
        user_agent=client.user_agent[:512] if client.user_agent else None,
    )
    db.add(refresh_row)
    await db.flush()  # assigns refresh_row.id

    pair = TokenPair(
        access_token=create_access_token(
            str(user.id), tenant_id=str(tenant_id) if tenant_id else None
        ),
        refresh_token=raw_refresh,
        expires_in=settings.access_token_ttl_minutes * 60,
    )
    return pair, refresh_row


async def _revoke_family(db: AsyncSession, family_id: uuid.UUID, now: datetime) -> None:
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )
