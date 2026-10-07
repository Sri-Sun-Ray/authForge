import os
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text, update

from app.db.session import SessionLocal
from app.models import Invite, Membership, User
from tests.test_auth import bearer, login, new_email, register, registered_tokens

pytestmark = pytest.mark.skipif(
    not os.getenv("INTEGRATION"), reason="needs Postgres (set INTEGRATION=1)"
)


async def create_tenant(client: AsyncClient, access_token: str, name: str = "Acme Inc"):
    return await client.post("/tenants", json={"name": name}, headers=bearer(access_token))


async def tenant_session(client: AsyncClient) -> tuple[dict, dict]:
    """Register a user, create a tenant and switch into it. Returns (tokens, tenant)."""
    _, tokens = await registered_tokens(client)
    tenant = (await create_tenant(client, tokens["access_token"])).json()
    tokens = (
        await client.post(
            f"/tenants/{tenant['id']}/switch", json={"refresh_token": tokens["refresh_token"]}
        )
    ).json()
    return tokens, tenant


# --- Creating and listing ---------------------------------------------------


async def test_create_tenant_generates_slug_and_adds_creator(client: AsyncClient) -> None:
    _, tokens = await registered_tokens(client)

    response = await create_tenant(client, tokens["access_token"], "Acme Industries")
    assert response.status_code == 201
    tenant = response.json()
    assert tenant["slug"].startswith("acme-industries-")

    mine = await client.get("/tenants", headers=bearer(tokens["access_token"]))
    assert [t["id"] for t in mine.json()] == [tenant["id"]]


async def test_create_tenant_rejects_duplicate_slug(client: AsyncClient) -> None:
    _, tokens = await registered_tokens(client)
    slug = f"acme-{uuid.uuid4().hex[:8]}"
    payload = {"name": "Acme", "slug": slug}

    first = await client.post("/tenants", json=payload, headers=bearer(tokens["access_token"]))
    second = await client.post("/tenants", json=payload, headers=bearer(tokens["access_token"]))
    assert first.status_code == 201
    assert second.status_code == 409


async def test_tenant_endpoints_require_authentication(client: AsyncClient) -> None:
    assert (await client.get("/tenants")).status_code == 401
    assert (await client.post("/tenants", json={"name": "Acme"})).status_code == 401


# --- Switching --------------------------------------------------------------


async def test_switch_scopes_the_session_to_the_tenant(client: AsyncClient) -> None:
    tokens, tenant = await tenant_session(client)

    current = await client.get("/tenants/current", headers=bearer(tokens["access_token"]))
    assert current.status_code == 200
    assert current.json()["id"] == tenant["id"]


async def test_tenant_survives_a_refresh(client: AsyncClient) -> None:
    tokens, tenant = await tenant_session(client)

    refreshed = (
        await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    ).json()
    current = await client.get("/tenants/current", headers=bearer(refreshed["access_token"]))
    assert current.json()["id"] == tenant["id"]


async def test_switch_rotates_the_refresh_token(client: AsyncClient) -> None:
    _, tokens = await registered_tokens(client)
    tenant = (await create_tenant(client, tokens["access_token"])).json()

    await client.post(
        f"/tenants/{tenant['id']}/switch", json={"refresh_token": tokens["refresh_token"]}
    )
    replay = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert replay.status_code == 401


async def test_cannot_switch_into_someone_elses_tenant(client: AsyncClient) -> None:
    _, outsider = await registered_tokens(client)
    _, owner = await registered_tokens(client)
    tenant = (await create_tenant(client, owner["access_token"])).json()

    response = await client.post(
        f"/tenants/{tenant['id']}/switch", json={"refresh_token": outsider["refresh_token"]}
    )
    assert response.status_code == 403


async def test_tenant_scoped_endpoint_requires_a_selected_tenant(client: AsyncClient) -> None:
    _, tokens = await registered_tokens(client)
    response = await client.get("/tenants/current", headers=bearer(tokens["access_token"]))
    assert response.status_code == 403
    assert "No tenant selected" in response.json()["detail"]


async def test_removed_member_loses_access_before_token_expiry(client: AsyncClient) -> None:
    tokens, tenant = await tenant_session(client)
    async with SessionLocal() as session:
        await session.execute(
            Membership.__table__.delete().where(Membership.tenant_id == uuid.UUID(tenant["id"]))
        )
        await session.commit()

    response = await client.get("/tenants/current", headers=bearer(tokens["access_token"]))
    assert response.status_code == 403


# --- Invites ----------------------------------------------------------------


async def test_invite_and_accept_flow(client: AsyncClient) -> None:
    owner_tokens, tenant = await tenant_session(client)
    guest_email = new_email()
    await register(client, guest_email)
    guest = (await login(client, guest_email)).json()

    invite = await client.post(
        "/tenants/current/invites",
        json={"email": guest_email},
        headers=bearer(owner_tokens["access_token"]),
    )
    assert invite.status_code == 201

    accepted = await client.post(
        "/invites/accept",
        json={"token": invite.json()["token"]},
        headers=bearer(guest["access_token"]),
    )
    assert accepted.status_code == 200
    assert accepted.json()["id"] == tenant["id"]

    members = await client.get(
        "/tenants/current/members", headers=bearer(owner_tokens["access_token"])
    )
    assert guest_email in [m["email"] for m in members.json()]


async def test_invite_cannot_be_redeemed_by_another_user(client: AsyncClient) -> None:
    owner_tokens, _ = await tenant_session(client)
    invite = await client.post(
        "/tenants/current/invites",
        json={"email": new_email()},
        headers=bearer(owner_tokens["access_token"]),
    )
    _, outsider = await registered_tokens(client)

    response = await client.post(
        "/invites/accept",
        json={"token": invite.json()["token"]},
        headers=bearer(outsider["access_token"]),
    )
    assert response.status_code == 400


async def test_invite_is_single_use(client: AsyncClient) -> None:
    owner_tokens, _ = await tenant_session(client)
    guest_email = new_email()
    await register(client, guest_email)
    guest = (await login(client, guest_email)).json()
    invite = await client.post(
        "/tenants/current/invites",
        json={"email": guest_email},
        headers=bearer(owner_tokens["access_token"]),
    )
    payload = {"token": invite.json()["token"]}

    first = await client.post(
        "/invites/accept", json=payload, headers=bearer(guest["access_token"])
    )
    second = await client.post(
        "/invites/accept", json=payload, headers=bearer(guest["access_token"])
    )
    assert first.status_code == 200
    assert second.status_code == 400


async def test_expired_invite_is_rejected(client: AsyncClient) -> None:
    owner_tokens, _ = await tenant_session(client)
    guest_email = new_email()
    await register(client, guest_email)
    guest = (await login(client, guest_email)).json()
    invite = await client.post(
        "/tenants/current/invites",
        json={"email": guest_email},
        headers=bearer(owner_tokens["access_token"]),
    )
    async with SessionLocal() as session:
        await session.execute(
            update(Invite)
            .where(Invite.id == uuid.UUID(invite.json()["id"]))
            .values(expires_at=text("now() - interval '1 day'"))
        )
        await session.commit()

    response = await client.post(
        "/invites/accept",
        json={"token": invite.json()["token"]},
        headers=bearer(guest["access_token"]),
    )
    assert response.status_code == 400


async def test_members_list_shows_only_this_tenant(client: AsyncClient) -> None:
    first_tokens, _ = await tenant_session(client)
    second_tokens, _ = await tenant_session(client)

    members = await client.get(
        "/tenants/current/members", headers=bearer(first_tokens["access_token"])
    )
    emails = [m["email"] for m in members.json()]
    other = await client.get("/auth/me", headers=bearer(second_tokens["access_token"]))
    assert other.json()["email"] not in emails


# --- Row-level security (database level) ------------------------------------


async def test_rls_hides_other_tenants_rows(client: AsyncClient) -> None:
    """Even a query with no tenant filter sees only the tenant set on the connection."""
    # Both tenants are created here, so the assertions never depend on rows other
    # tests happened to leave behind
    _, tenant_a = await tenant_session(client)
    _, tenant_b = await tenant_session(client)
    target, other = uuid.UUID(tenant_a["id"]), uuid.UUID(tenant_b["id"])

    async with SessionLocal() as session:
        await session.execute(
            text("SELECT set_config('app.tenant_id', :tid, true)"), {"tid": str(target)}
        )
        visible = set(await session.scalars(select(Membership.tenant_id)))
        assert visible == {target}

        # Clearing the setting restores the system-wide view
        await session.execute(text("SELECT set_config('app.tenant_id', '', true)"))
        system_view = set(await session.scalars(select(Membership.tenant_id)))
        assert {target, other} <= system_view
        await session.rollback()


async def test_rls_blocks_cross_tenant_writes(client: AsyncClient) -> None:
    _, tenant_a = await tenant_session(client)
    _, tenant_b = await tenant_session(client)

    async with SessionLocal() as session:
        # A brand-new user, so the insert can only fail because of the policy and
        # never because the membership already exists
        user = User(email=new_email(), password_hash="x")
        session.add(user)
        await session.flush()

        await session.execute(
            text("SELECT set_config('app.tenant_id', :tid, true)"), {"tid": tenant_a["id"]}
        )
        session.add(Membership(tenant_id=uuid.UUID(tenant_b["id"]), user_id=user.id))
        with pytest.raises(Exception, match="row-level security"):
            await session.flush()
        await session.rollback()
