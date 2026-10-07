import os
import uuid

import pytest
from httpx import AsyncClient

from app.core import permissions as perms
from tests.test_auth import bearer, login, new_email, register, registered_tokens
from tests.test_tenants import tenant_session

pytestmark = pytest.mark.skipif(
    not os.getenv("INTEGRATION"), reason="needs Postgres and Redis (set INTEGRATION=1)"
)


async def add_member(client: AsyncClient, owner_tokens: dict, tenant_id: str) -> dict:
    """Invite a new user into the tenant and return their tenant-scoped tokens."""
    email = new_email()
    await register(client, email)
    guest = (await login(client, email)).json()

    invite = await client.post(
        "/tenants/current/invites",
        json={"email": email},
        headers=bearer(owner_tokens["access_token"]),
    )
    await client.post(
        "/invites/accept",
        json={"token": invite.json()["token"]},
        headers=bearer(guest["access_token"]),
    )
    guest = (
        await client.post(
            f"/tenants/{tenant_id}/switch", json={"refresh_token": guest["refresh_token"]}
        )
    ).json()
    guest["email"] = email
    return guest


async def my_permissions(client: AsyncClient, tokens: dict) -> list[str]:
    response = await client.get(
        "/tenants/current/permissions", headers=bearer(tokens["access_token"])
    )
    return response.json()


async def user_id_of(client: AsyncClient, tokens: dict) -> str:
    return (await client.get("/auth/me", headers=bearer(tokens["access_token"]))).json()["id"]


# --- Built-in roles ---------------------------------------------------------


async def test_tenant_creator_is_owner_with_every_permission(client: AsyncClient) -> None:
    tokens, _ = await tenant_session(client)

    granted = await my_permissions(client, tokens)
    assert set(granted) == set(perms.CATALOGUE)

    roles = await client.get("/tenants/current/roles", headers=bearer(tokens["access_token"]))
    assert {r["name"] for r in roles.json()} == {perms.OWNER, perms.ADMIN, perms.MEMBER}
    assert all(r["is_system"] for r in roles.json())


async def test_invited_user_joins_as_member(client: AsyncClient) -> None:
    owner, tenant = await tenant_session(client)
    guest = await add_member(client, owner, tenant["id"])

    assert set(await my_permissions(client, guest)) == set(perms.SYSTEM_ROLES[perms.MEMBER])


async def test_member_cannot_invite_or_manage_roles(client: AsyncClient) -> None:
    owner, tenant = await tenant_session(client)
    guest = await add_member(client, owner, tenant["id"])

    invite = await client.post(
        "/tenants/current/invites",
        json={"email": new_email()},
        headers=bearer(guest["access_token"]),
    )
    assert invite.status_code == 403
    assert perms.USERS_INVITE in invite.json()["detail"]

    roles = await client.get("/tenants/current/roles", headers=bearer(guest["access_token"]))
    assert roles.status_code == 403


async def test_permissions_are_per_tenant(client: AsyncClient) -> None:
    """Owner in their own tenant, plain member in someone else's."""
    owner, tenant = await tenant_session(client)
    guest = await add_member(client, owner, tenant["id"])

    own = await client.post(
        "/tenants", json={"name": "Guest Co"}, headers=bearer(guest["access_token"])
    )
    guest_own = (
        await client.post(
            f"/tenants/{own.json()['id']}/switch",
            json={"refresh_token": guest["refresh_token"]},
        )
    ).json()

    assert set(await my_permissions(client, guest_own)) == set(perms.CATALOGUE)


# --- Custom roles -----------------------------------------------------------


async def test_create_and_assign_custom_role(client: AsyncClient) -> None:
    owner, tenant = await tenant_session(client)
    guest = await add_member(client, owner, tenant["id"])
    guest_id = await user_id_of(client, guest)

    role = await client.post(
        "/tenants/current/roles",
        json={"name": "Recruiter", "permissions": [perms.USERS_READ, perms.USERS_INVITE]},
        headers=bearer(owner["access_token"]),
    )
    assert role.status_code == 201
    assert role.json()["is_system"] is False

    assigned = await client.put(
        f"/tenants/current/users/{guest_id}/roles",
        json={"role_ids": [role.json()["id"]]},
        headers=bearer(owner["access_token"]),
    )
    assert assigned.status_code == 200
    assert [r["name"] for r in assigned.json()] == ["Recruiter"]

    # The guest can invite now, and lost the member role's permissions
    invite = await client.post(
        "/tenants/current/invites",
        json={"email": new_email()},
        headers=bearer(guest["access_token"]),
    )
    assert invite.status_code == 201
    assert perms.TENANT_READ not in await my_permissions(client, guest)


async def test_editing_a_role_takes_effect_immediately(client: AsyncClient) -> None:
    """Proves the Redis permission cache is invalidated, not left to expire."""
    owner, tenant = await tenant_session(client)
    guest = await add_member(client, owner, tenant["id"])
    guest_id = await user_id_of(client, guest)

    role = (
        await client.post(
            "/tenants/current/roles",
            json={"name": "Temp", "permissions": [perms.USERS_READ]},
            headers=bearer(owner["access_token"]),
        )
    ).json()
    await client.put(
        f"/tenants/current/users/{guest_id}/roles",
        json={"role_ids": [role["id"]]},
        headers=bearer(owner["access_token"]),
    )
    # Warm the cache
    assert await my_permissions(client, guest) == [perms.USERS_READ]

    await client.put(
        f"/tenants/current/roles/{role['id']}",
        json={"permissions": [perms.USERS_READ, perms.USERS_INVITE]},
        headers=bearer(owner["access_token"]),
    )
    assert perms.USERS_INVITE in await my_permissions(client, guest)


async def test_revoking_all_roles_removes_access(client: AsyncClient) -> None:
    owner, tenant = await tenant_session(client)
    guest = await add_member(client, owner, tenant["id"])
    guest_id = await user_id_of(client, guest)

    await client.put(
        f"/tenants/current/users/{guest_id}/roles",
        json={"role_ids": []},
        headers=bearer(owner["access_token"]),
    )
    assert await my_permissions(client, guest) == []


async def test_deleting_a_role_revokes_it(client: AsyncClient) -> None:
    owner, tenant = await tenant_session(client)
    guest = await add_member(client, owner, tenant["id"])
    guest_id = await user_id_of(client, guest)
    role = (
        await client.post(
            "/tenants/current/roles",
            json={"name": "Doomed", "permissions": [perms.USERS_INVITE]},
            headers=bearer(owner["access_token"]),
        )
    ).json()
    await client.put(
        f"/tenants/current/users/{guest_id}/roles",
        json={"role_ids": [role["id"]]},
        headers=bearer(owner["access_token"]),
    )

    deleted = await client.delete(
        f"/tenants/current/roles/{role['id']}", headers=bearer(owner["access_token"])
    )
    assert deleted.status_code == 204
    assert await my_permissions(client, guest) == []


@pytest.mark.parametrize("role_name", [perms.OWNER, perms.MEMBER])
async def test_built_in_roles_cannot_be_changed_or_deleted(
    client: AsyncClient, role_name: str
) -> None:
    owner, _ = await tenant_session(client)
    roles = (
        await client.get("/tenants/current/roles", headers=bearer(owner["access_token"]))
    ).json()
    role_id = next(r["id"] for r in roles if r["name"] == role_name)

    updated = await client.put(
        f"/tenants/current/roles/{role_id}",
        json={"permissions": []},
        headers=bearer(owner["access_token"]),
    )
    deleted = await client.delete(
        f"/tenants/current/roles/{role_id}", headers=bearer(owner["access_token"])
    )
    assert updated.status_code == deleted.status_code == 403


async def test_role_names_are_unique_per_tenant(client: AsyncClient) -> None:
    owner, _ = await tenant_session(client)
    payload = {"name": "Duplicate", "permissions": []}

    first = await client.post(
        "/tenants/current/roles", json=payload, headers=bearer(owner["access_token"])
    )
    second = await client.post(
        "/tenants/current/roles", json=payload, headers=bearer(owner["access_token"])
    )
    assert first.status_code == 201
    assert second.status_code == 409


async def test_unknown_permission_is_rejected(client: AsyncClient) -> None:
    owner, _ = await tenant_session(client)
    response = await client.post(
        "/tenants/current/roles",
        json={"name": "Bogus", "permissions": ["cats:herd"]},
        headers=bearer(owner["access_token"]),
    )
    assert response.status_code == 400
    assert "cats:herd" in response.json()["detail"]


async def test_cannot_assign_a_role_from_another_tenant(client: AsyncClient) -> None:
    owner_a, tenant_a = await tenant_session(client)
    owner_b, _ = await tenant_session(client)
    foreign_role = (
        await client.post(
            "/tenants/current/roles",
            json={"name": "Foreign", "permissions": []},
            headers=bearer(owner_b["access_token"]),
        )
    ).json()
    guest = await add_member(client, owner_a, tenant_a["id"])
    guest_id = await user_id_of(client, guest)

    response = await client.put(
        f"/tenants/current/users/{guest_id}/roles",
        json={"role_ids": [foreign_role["id"]]},
        headers=bearer(owner_a["access_token"]),
    )
    assert response.status_code == 400


async def test_cannot_assign_roles_to_a_non_member(client: AsyncClient) -> None:
    owner, _ = await tenant_session(client)
    _, outsider = await registered_tokens(client)
    outsider_id = await user_id_of(client, outsider)

    response = await client.put(
        f"/tenants/current/users/{outsider_id}/roles",
        json={"role_ids": []},
        headers=bearer(owner["access_token"]),
    )
    assert response.status_code == 404


async def test_roles_from_other_tenants_are_not_listed(client: AsyncClient) -> None:
    owner_a, _ = await tenant_session(client)
    owner_b, _ = await tenant_session(client)
    await client.post(
        "/tenants/current/roles",
        json={"name": "Secret", "permissions": []},
        headers=bearer(owner_b["access_token"]),
    )

    roles = await client.get("/tenants/current/roles", headers=bearer(owner_a["access_token"]))
    assert "Secret" not in {r["name"] for r in roles.json()}


async def test_permission_catalogue_is_public_to_signed_in_users(client: AsyncClient) -> None:
    _, tokens = await registered_tokens(client)
    response = await client.get("/permissions", headers=bearer(tokens["access_token"]))

    assert response.status_code == 200
    assert {p["code"] for p in response.json()} == set(perms.CATALOGUE)


async def test_role_endpoints_need_a_tenant(client: AsyncClient) -> None:
    _, tokens = await registered_tokens(client)
    response = await client.get("/tenants/current/roles", headers=bearer(tokens["access_token"]))
    assert response.status_code == 403


async def test_unknown_role_id_is_a_404(client: AsyncClient) -> None:
    owner, _ = await tenant_session(client)
    response = await client.delete(
        f"/tenants/current/roles/{uuid.uuid4()}", headers=bearer(owner["access_token"])
    )
    assert response.status_code == 404
