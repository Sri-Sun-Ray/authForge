import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import update

from app.core.security import hash_refresh_token
from app.db.session import SessionLocal
from app.models import RefreshToken, User

pytestmark = pytest.mark.skipif(
    not os.getenv("INTEGRATION"), reason="needs Postgres (set INTEGRATION=1)"
)

PASSWORD = "s3cure-passw0rd"


def new_email() -> str:
    return f"user-{uuid.uuid4().hex[:10]}@example.com"


async def register(client: AsyncClient, email: str, password: str = PASSWORD):
    return await client.post("/auth/register", json={"email": email, "password": password})


async def login(client: AsyncClient, email: str, password: str = PASSWORD):
    return await client.post("/auth/login", data={"username": email, "password": password})


async def registered_tokens(client: AsyncClient) -> tuple[str, dict]:
    email = new_email()
    await register(client, email)
    response = await login(client, email)
    assert response.status_code == 200
    return email, response.json()


def bearer(access_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}


# --- Register ---------------------------------------------------------------


async def test_register_creates_user_with_lowercased_email(client: AsyncClient) -> None:
    email = new_email()
    response = await register(client, email.upper())

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == email
    assert "password" not in body and "password_hash" not in body


async def test_register_rejects_duplicate_email_in_any_case(client: AsyncClient) -> None:
    email = new_email()
    await register(client, email)
    response = await register(client, email.upper())
    assert response.status_code == 409


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "not-an-email", "password": PASSWORD},
        {"email": "a@example.com", "password": "short"},
        {"email": "a@example.com", "password": "x" * 129},
    ],
)
async def test_register_validates_input(client: AsyncClient, payload: dict) -> None:
    response = await client.post("/auth/register", json=payload)
    assert response.status_code == 422


# --- Login / me -------------------------------------------------------------


async def test_login_then_me(client: AsyncClient) -> None:
    email, tokens = await registered_tokens(client)

    assert tokens["token_type"] == "bearer"
    assert tokens["expires_in"] > 0
    response = await client.get("/auth/me", headers=bearer(tokens["access_token"]))
    assert response.status_code == 200
    assert response.json()["email"] == email


async def test_login_is_case_insensitive_on_email(client: AsyncClient) -> None:
    email = new_email()
    await register(client, email)
    response = await login(client, email.upper())
    assert response.status_code == 200


async def test_wrong_password_and_unknown_email_look_identical(client: AsyncClient) -> None:
    email = new_email()
    await register(client, email)

    wrong_password = await login(client, email, "wrong-password")
    unknown_email = await login(client, new_email())

    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer not-a-jwt"}])
async def test_me_requires_valid_token(client: AsyncClient, headers: dict) -> None:
    response = await client.get("/auth/me", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


async def test_deactivated_user_cannot_login_or_use_existing_token(client: AsyncClient) -> None:
    email, tokens = await registered_tokens(client)
    async with SessionLocal() as session:
        await session.execute(update(User).where(User.email == email).values(is_active=False))
        await session.commit()

    assert (await login(client, email)).status_code == 401
    me = await client.get("/auth/me", headers=bearer(tokens["access_token"]))
    assert me.status_code == 401
    refreshed = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 401


# --- Refresh rotation -------------------------------------------------------


async def test_refresh_rotates_tokens(client: AsyncClient) -> None:
    _, tokens = await registered_tokens(client)

    response = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert response.status_code == 200
    new_tokens = response.json()
    assert new_tokens["refresh_token"] != tokens["refresh_token"]

    me = await client.get("/auth/me", headers=bearer(new_tokens["access_token"]))
    assert me.status_code == 200


async def test_reusing_a_rotated_refresh_token_revokes_the_whole_session(
    client: AsyncClient,
) -> None:
    _, first = await registered_tokens(client)
    second = (
        await client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    ).json()

    # An attacker replays the old token...
    replay = await client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert replay.status_code == 401

    # ...so the legitimate newer token is revoked too; the user has to log in again
    legit = await client.post("/auth/refresh", json={"refresh_token": second["refresh_token"]})
    assert legit.status_code == 401


async def test_refresh_sessions_are_independent(client: AsyncClient) -> None:
    email, laptop = await registered_tokens(client)
    phone = (await login(client, email)).json()

    # Reuse on the laptop session must not log out the phone
    await client.post("/auth/refresh", json={"refresh_token": laptop["refresh_token"]})
    await client.post("/auth/refresh", json={"refresh_token": laptop["refresh_token"]})

    response = await client.post("/auth/refresh", json={"refresh_token": phone["refresh_token"]})
    assert response.status_code == 200


async def test_expired_refresh_token_is_rejected(client: AsyncClient) -> None:
    _, tokens = await registered_tokens(client)
    token_hash = hash_refresh_token(tokens["refresh_token"])
    async with SessionLocal() as session:
        await session.execute(
            update(RefreshToken)
            .where(RefreshToken.token_hash == token_hash)
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await session.commit()

    response = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert response.status_code == 401


async def test_unknown_refresh_token_is_rejected(client: AsyncClient) -> None:
    response = await client.post("/auth/refresh", json={"refresh_token": "made-up"})
    assert response.status_code == 401


# --- Logout -----------------------------------------------------------------


async def test_logout_revokes_refresh_token(client: AsyncClient) -> None:
    _, tokens = await registered_tokens(client)

    response = await client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    assert response.status_code == 204
    refreshed = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 401


async def test_logout_is_idempotent_for_unknown_tokens(client: AsyncClient) -> None:
    response = await client.post("/auth/logout", json={"refresh_token": "made-up"})
    assert response.status_code == 204
