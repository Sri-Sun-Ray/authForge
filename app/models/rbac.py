import uuid

from sqlalchemy import ForeignKey, Index, String, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Permission(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A single thing a user may do, e.g. "users:invite". Global, not per tenant."""

    __tablename__ = "permissions"

    code: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(String(255))

    def __repr__(self) -> str:
        return f"<Permission {self.code}>"


class Role(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A named bundle of permissions.

    tenant_id is null for the built-in roles (owner, admin, member), which every
    tenant shares and nobody may edit. Tenants can also define their own roles.
    """

    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="tenant_role_name"),
        # The constraint above does not catch duplicate built-in names, because in
        # SQL two NULLs are never equal
        Index(
            "uq_roles_system_name",
            "name",
            unique=True,
            postgresql_where=text("tenant_id IS NULL"),
        ),
    )

    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(64))

    @property
    def is_system(self) -> bool:
        return self.tenant_id is None

    def __repr__(self) -> str:
        return f"<Role {self.name} tenant={self.tenant_id}>"


class RolePermission(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "role_permissions"
    __table_args__ = (UniqueConstraint("role_id", "permission_id", name="role_permission"),)

    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), index=True
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"), index=True
    )


class UserRole(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Grants a role to a user inside one tenant.

    tenant_id is repeated here (rather than only on the role) so that a built-in role
    can be granted per tenant, and so row-level security can scope the table.
    """

    __tablename__ = "user_roles"
    __table_args__ = (UniqueConstraint("user_id", "role_id", "tenant_id", name="user_role"),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), index=True
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True
    )

    def __repr__(self) -> str:
        return f"<UserRole user={self.user_id} role={self.role_id} tenant={self.tenant_id}>"
