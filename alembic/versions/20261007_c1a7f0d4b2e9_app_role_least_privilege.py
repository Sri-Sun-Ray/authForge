"""app role with least privilege

Row-level security is bypassed by superusers and (without FORCE) by a table's owner.
Migrations therefore run as the owner, while the API connects as this restricted role,
which can only read and write rows the policies allow.

Revision ID: c1a7f0d4b2e9
Revises: 8ce695b8f254
Create Date: 2026-10-07
"""

import os
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c1a7f0d4b2e9"
down_revision: str | None = "8ce695b8f254"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLES = ("users", "refresh_tokens", "tenants", "memberships", "invites")

# The password is passed as a bind parameter and quoted by Postgres itself
# (format %L), never pasted into the statement by Python.
CREATE_ROLE = """
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authforge_app') THEN
        EXECUTE format(
            'CREATE ROLE %I LOGIN PASSWORD %L',
            'authforge_app',
            current_setting('authforge.app_password')
        );
    END IF;
END $$;
"""


def upgrade() -> None:
    connection = op.get_bind()
    # Set APP_DB_PASSWORD in every environment except local development
    password = os.environ.get("APP_DB_PASSWORD", "authforge_app")
    connection.execute(
        sa.text("SELECT set_config('authforge.app_password', :password, true)"),
        {"password": password},
    )
    connection.execute(sa.text(CREATE_ROLE))

    # Data access only: no DDL, no ownership, so it cannot drop policies either
    op.execute("GRANT USAGE ON SCHEMA public TO authforge_app")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authforge_app"
    )
    # Tables added by later migrations are granted automatically
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO authforge_app"
    )


def downgrade() -> None:
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM authforge_app"
    )
    for table in TABLES:
        op.execute(f"REVOKE ALL ON {table} FROM authforge_app")  # noqa: S608 (fixed table list)
    op.execute("REVOKE USAGE ON SCHEMA public FROM authforge_app")
    # The role itself is left in place: other databases may still use it
