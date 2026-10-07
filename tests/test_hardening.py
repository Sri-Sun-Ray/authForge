import os
import re
import uuid
from collections.abc import AsyncIterator, Iterator

import pytest
from httpx import AsyncClient
from sqlalchemy import text, update

from app.core.config import get_settings
from app.core.redis import redis_client
from app.db.session import SessionLocal
from app.models import OneTimeToken, User
from app.services import mailer
from tests.test_auth import PASSWORD, bearer, login, new_email, register, registered_tokens

pytestmark = pytest.mark.skipif(
    not os.getenv("INTEGRATION"), reason="needs Postgres and Redis (set INTEGRATION=1)"
)


@pytest.fixture
def strict_limits() -> Iterator[None]:
    """Lower the rate limits for one test, then restore them."""
    settings = get_settings()
    original = {
        name: getattr(settings, name)
        for name in (
            "rate_limit_login_per_minute",
            "rate_limit_login_per_account_per_minute",
            "rate_limit_password_reset_per_hour",
        )
    }
    settings.rate_limit_login_per_minute = 3
    settings.rate_limit_login_per_account_per_minute = 3
    settings.rate_limit_password_reset_per_hour = 2
    yield
    for name, value in original.items():
        setattr(settings, name, value)


@pytest.fixture
async def clean_rate_limits() -> AsyncIterator[None]:
    """Rate-limit buckets are keyed by IP, which every test shares."""
    async for _ in _clear_buckets():
        yield


async def _clear_buckets() -> AsyncIterator[None]:
    keys = [key async for key in redis_client.scan_iter("rl:*")]
    if keys:
        await redis_client.delete(*keys)
    yield
    keys = [key async for key in redis_client.scan_iter("rl:*")]
    if keys:
        await redis_client.delete(*keys)


def last_link_token(to: str) -> str:
    """Pull the token out of the most recent email sent to this address."""
    for email in reversed(mailer.outbox):
        if email.to == to:
            match = re.search(r"token=([A-Za-z0-9_-]+)", email.body)
            assert match, f"no token in: {email.body}"
            return match.group(1)
    raise AssertionError(f"no email sent to {to}")


# --- Rate limiting ----------------------------------------------------------


async def test_login_is_rate_limited_per_ip(
    client: AsyncClient, strict_limits: None, clean_rate_limits: None
) -> None:
    email = new_email()
    await register(client, email)

    statuses = [(await login(client, email, "wrong-password")).status_code for _ in range(5)]

    assert statuses[:3] == [401, 401, 401]
    assert statuses[-1] == 429


async def test_rate_limited_response_says_when_to_retry(
    client: AsyncClient, strict_limits: None, clean_rate_limits: None
) -> None:
    for _ in range(4):
        response = await client.post("/auth/password-reset", json={"email": new_email()})

    assert response.status_code == 429
    assert 0 < int(response.headers["retry-after"]) <= 3600


async def test_rate_limit_counts_only_its_own_bucket(
    client: AsyncClient, strict_limits: None, clean_rate_limits: None
) -> None:
    for _ in range(4):
        await client.post("/auth/password-reset", json={"email": new_email()})

    # Registering uses a different bucket, so it is unaffected
    assert (await register(client, new_email())).status_code == 201


# --- Account lockout --------------------------------------------------------


async def test_account_locks_after_repeated_failures(
    client: AsyncClient, clean_rate_limits: None
) -> None:
    email = new_email()
    await register(client, email)
    attempts = get_settings().login_max_failed_attempts

    for _ in range(attempts):
        assert (await login(client, email, "wrong-password")).status_code == 401

    # Even the correct password is refused while the lock holds
    locked = await login(client, email)
    assert locked.status_code == 429
    assert int(locked.headers["retry-after"]) > 0


async def test_lock_expires(client: AsyncClient, clean_rate_limits: None) -> None:
    email = new_email()
    await register(client, email)
    for _ in range(get_settings().login_max_failed_attempts):
        await login(client, email, "wrong-password")

    async with SessionLocal() as session:
        await session.execute(
            update(User)
            .where(User.email == email)
            .values(locked_until=text("now() - interval '1 minute'"))
        )
        await session.commit()

    assert (await login(client, email)).status_code == 200


async def test_successful_login_clears_the_failure_count(
    client: AsyncClient, clean_rate_limits: None
) -> None:
    email = new_email()
    await register(client, email)
    attempts = get_settings().login_max_failed_attempts

    for _ in range(attempts - 1):
        await login(client, email, "wrong-password")
    assert (await login(client, email)).status_code == 200

    # The counter restarted, so this run of failures does not lock the account
    for _ in range(attempts - 1):
        await login(client, email, "wrong-password")
    assert (await login(client, email)).status_code == 200


# --- Email verification -----------------------------------------------------


async def test_email_verification_flow(client: AsyncClient) -> None:
    email = new_email()
    await register(client, email)
    tokens = (await login(client, email)).json()

    requested = await client.post(
        "/auth/verify-email/request", headers=bearer(tokens["access_token"])
    )
    assert requested.status_code == 202

    confirmed = await client.post(
        "/auth/verify-email/confirm", json={"token": last_link_token(email)}
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["is_email_verified"] is True


async def test_verification_token_is_single_use(client: AsyncClient) -> None:
    email = new_email()
    await register(client, email)
    tokens = (await login(client, email)).json()
    await client.post("/auth/verify-email/request", headers=bearer(tokens["access_token"]))
    token = last_link_token(email)

    first = await client.post("/auth/verify-email/confirm", json={"token": token})
    second = await client.post("/auth/verify-email/confirm", json={"token": token})
    assert first.status_code == 200
    assert second.status_code == 400


async def test_requesting_again_invalidates_the_previous_link(client: AsyncClient) -> None:
    email = new_email()
    await register(client, email)
    tokens = (await login(client, email)).json()

    await client.post("/auth/verify-email/request", headers=bearer(tokens["access_token"]))
    first_token = last_link_token(email)
    await client.post("/auth/verify-email/request", headers=bearer(tokens["access_token"]))
    second_token = last_link_token(email)

    assert first_token != second_token
    assert (
        await client.post("/auth/verify-email/confirm", json={"token": first_token})
    ).status_code == 400
    assert (
        await client.post("/auth/verify-email/confirm", json={"token": second_token})
    ).status_code == 200


async def test_verification_requires_a_session(client: AsyncClient) -> None:
    assert (await client.post("/auth/verify-email/request")).status_code == 401


# --- Password reset ---------------------------------------------------------


async def test_password_reset_flow_and_session_revocation(
    client: AsyncClient, clean_rate_limits: None
) -> None:
    email = new_email()
    await register(client, email)
    old_session = (await login(client, email)).json()
    new_password = "br4nd-new-passw0rd"

    assert (await client.post("/auth/password-reset", json={"email": email})).status_code == 202
    reset = await client.post(
        "/auth/password-reset/confirm",
        json={"token": last_link_token(email), "new_password": new_password},
    )
    assert reset.status_code == 204

    assert (await login(client, email, PASSWORD)).status_code == 401
    assert (await login(client, email, new_password)).status_code == 200
    # Sessions opened before the reset are dead, which matters if the account was stolen
    refreshed = await client.post(
        "/auth/refresh", json={"refresh_token": old_session["refresh_token"]}
    )
    assert refreshed.status_code == 401


async def test_reset_unlocks_a_locked_account(client: AsyncClient, clean_rate_limits: None) -> None:
    email = new_email()
    await register(client, email)
    for _ in range(get_settings().login_max_failed_attempts):
        await login(client, email, "wrong-password")

    await client.post("/auth/password-reset", json={"email": email})
    await client.post(
        "/auth/password-reset/confirm",
        json={"token": last_link_token(email), "new_password": "an0ther-passw0rd"},
    )
    assert (await login(client, email, "an0ther-passw0rd")).status_code == 200


async def test_reset_for_unknown_address_reveals_nothing(
    client: AsyncClient, clean_rate_limits: None
) -> None:
    known, unknown = new_email(), new_email()
    await register(client, known)

    for address in (known, unknown):
        response = await client.post("/auth/password-reset", json={"email": address})
        assert response.status_code == 202
        assert "If that address has an account" in response.json()["detail"]

    assert all(email.to != unknown for email in mailer.outbox)


async def test_expired_reset_token_is_rejected(
    client: AsyncClient, clean_rate_limits: None
) -> None:
    email = new_email()
    await register(client, email)
    await client.post("/auth/password-reset", json={"email": email})
    token = last_link_token(email)

    async with SessionLocal() as session:
        await session.execute(
            update(OneTimeToken).values(expires_at=text("now() - interval '1 hour'"))
        )
        await session.commit()

    response = await client.post(
        "/auth/password-reset/confirm", json={"token": token, "new_password": "wh4tever-pass"}
    )
    assert response.status_code == 400


async def test_reset_rejects_made_up_tokens(client: AsyncClient) -> None:
    response = await client.post(
        "/auth/password-reset/confirm",
        json={"token": uuid.uuid4().hex, "new_password": "wh4tever-pass"},
    )
    assert response.status_code == 400


async def test_reset_enforces_password_rules(client: AsyncClient) -> None:
    response = await client.post(
        "/auth/password-reset/confirm", json={"token": "x", "new_password": "short"}
    )
    assert response.status_code == 422


async def test_a_verification_token_cannot_reset_a_password(client: AsyncClient) -> None:
    """Tokens are bound to a purpose, so one flow's link is useless in the other."""
    _, tokens = await registered_tokens(client)
    me = (await client.get("/auth/me", headers=bearer(tokens["access_token"]))).json()
    await client.post("/auth/verify-email/request", headers=bearer(tokens["access_token"]))

    response = await client.post(
        "/auth/password-reset/confirm",
        json={"token": last_link_token(me["email"]), "new_password": "n0t-happening-pass"},
    )
    assert response.status_code == 400
