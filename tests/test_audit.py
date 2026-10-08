import os

import pytest
from httpx import AsyncClient
from sqlalchemy import delete, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import permissions as perms
from app.db.session import SessionLocal
from app.models import AuditLog
from app.services import audit_service
from tests.test_auth import bearer, login, new_email, register
from tests.test_rbac import add_member, user_id_of
from tests.test_tenants import tenant_session

pytestmark = pytest.mark.skipif(
    not os.getenv("INTEGRATION"), reason="needs Postgres and Redis (set INTEGRATION=1)"
)


async def audit_entries(client: AsyncClient, tokens: dict, **params) -> list[dict]:
    response = await client.get(
        "/audit-logs", params=params, headers=bearer(tokens["access_token"])
    )
    assert response.status_code == 200
    return response.json()


# --- Recording --------------------------------------------------------------


async def test_tenant_creation_is_recorded(client: AsyncClient) -> None:
    tokens, tenant = await tenant_session(client)

    entries = await audit_entries(client, tokens)
    created = next(e for e in entries if e["action"] == audit_service.TENANT_CREATED)
    assert created["details"]["slug"] == tenant["slug"]
    assert created["target_id"] == tenant["id"]
    assert created["actor_user_id"] == await user_id_of(client, tokens)


async def test_membership_and_role_changes_are_recorded(client: AsyncClient) -> None:
    owner, tenant = await tenant_session(client)
    guest = await add_member(client, owner, tenant["id"])
    guest_id = await user_id_of(client, guest)
    role = (
        await client.post(
            "/tenants/current/roles",
            json={"name": "Auditor", "permissions": [perms.AUDIT_READ]},
            headers=bearer(owner["access_token"]),
        )
    ).json()
    await client.put(
        f"/tenants/current/users/{guest_id}/roles",
        json={"role_ids": [role["id"]]},
        headers=bearer(owner["access_token"]),
    )

    actions = [e["action"] for e in await audit_entries(client, owner)]
    assert audit_service.INVITE_CREATED in actions
    assert audit_service.INVITE_ACCEPTED in actions
    assert audit_service.ROLE_CREATED in actions
    assert audit_service.ROLES_ASSIGNED in actions


async def test_entries_can_be_filtered(client: AsyncClient) -> None:
    owner, tenant = await tenant_session(client)
    await add_member(client, owner, tenant["id"])

    filtered = await audit_entries(client, owner, action=audit_service.INVITE_CREATED)
    assert filtered and all(e["action"] == audit_service.INVITE_CREATED for e in filtered)

    limited = await audit_entries(client, owner, limit=1)
    assert len(limited) == 1


async def test_account_events_stay_out_of_tenant_logs(client: AsyncClient) -> None:
    """A failed login belongs to no tenant, so it must not surface in a tenant's log."""
    owner, _ = await tenant_session(client)
    email = new_email()
    await register(client, email)
    await login(client, email, "wrong-password")

    actions = [e["action"] for e in await audit_entries(client, owner)]
    assert audit_service.LOGIN_FAILED not in actions


async def test_tenants_cannot_see_each_others_entries(client: AsyncClient) -> None:
    first, _ = await tenant_session(client)
    second, second_tenant = await tenant_session(client)

    entries = await audit_entries(client, first)
    assert all(e["target_id"] != second_tenant["id"] for e in entries)


async def test_reading_the_log_needs_permission(client: AsyncClient) -> None:
    owner, tenant = await tenant_session(client)
    guest = await add_member(client, owner, tenant["id"])  # joins as a plain member

    response = await client.get("/audit-logs", headers=bearer(guest["access_token"]))
    assert response.status_code == 403


# --- Tamper evidence --------------------------------------------------------


async def test_chain_is_intact_for_a_normal_tenant(client: AsyncClient) -> None:
    owner, tenant = await tenant_session(client)
    await add_member(client, owner, tenant["id"])

    response = await client.get("/audit-logs/verify", headers=bearer(owner["access_token"]))
    assert response.status_code == 200
    assert response.json()["intact"] is True
    assert response.json()["entries"] >= 3


async def test_editing_an_entry_breaks_the_chain(
    client: AsyncClient, admin_session: AsyncSession
) -> None:
    owner, tenant = await tenant_session(client)
    await add_member(client, owner, tenant["id"])

    # Only the schema owner can rewrite rows, which is exactly what the app role may not do
    target = await admin_session.scalar(
        select(AuditLog.seq)
        .where(AuditLog.tenant_id == tenant["id"])
        .order_by(AuditLog.seq)
        .offset(1)
        .limit(1)
    )
    await admin_session.execute(
        update(AuditLog).where(AuditLog.seq == target).values(action="tenant.something.else")
    )
    await admin_session.commit()

    verified = (
        await client.get("/audit-logs/verify", headers=bearer(owner["access_token"]))
    ).json()
    assert verified["intact"] is False
    assert verified["broken_at_seq"] == target


async def test_deleting_an_entry_breaks_the_chain(
    client: AsyncClient, admin_session: AsyncSession
) -> None:
    owner, tenant = await tenant_session(client)
    await add_member(client, owner, tenant["id"])

    victim = await admin_session.scalar(
        select(AuditLog.seq)
        .where(AuditLog.tenant_id == tenant["id"])
        .order_by(AuditLog.seq)
        .offset(1)
        .limit(1)
    )
    await admin_session.execute(delete(AuditLog).where(AuditLog.seq == victim))
    await admin_session.commit()

    verified = (
        await client.get("/audit-logs/verify", headers=bearer(owner["access_token"]))
    ).json()
    assert verified["intact"] is False


@pytest.mark.parametrize(
    "statement", ["UPDATE audit_logs SET action = 'x'", "DELETE FROM audit_logs"]
)
async def test_application_role_cannot_rewrite_history(client: AsyncClient, statement: str) -> None:
    """The append-only rule is a database privilege, not a convention in the code."""
    await tenant_session(client)

    async with SessionLocal() as session:
        with pytest.raises(Exception, match="permission denied"):
            await session.execute(text(statement))
        await session.rollback()
