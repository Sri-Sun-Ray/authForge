"""The permission catalogue.

Codes are seeded into the database by a migration; these constants keep route code
free of typos. Built-in roles are defined here too, and the same lists seed the
`roles` and `role_permissions` tables.
"""

TENANT_READ = "tenant:read"
TENANT_UPDATE = "tenant:update"
USERS_READ = "users:read"
USERS_INVITE = "users:invite"
USERS_REMOVE = "users:remove"
ROLES_READ = "roles:read"
ROLES_CREATE = "roles:create"
ROLES_UPDATE = "roles:update"
ROLES_DELETE = "roles:delete"
ROLES_ASSIGN = "roles:assign"
AUDIT_READ = "audit:read"

CATALOGUE: dict[str, str] = {
    TENANT_READ: "View the tenant's details",
    TENANT_UPDATE: "Change the tenant's name or settings",
    USERS_READ: "List the tenant's members",
    USERS_INVITE: "Invite people to the tenant",
    USERS_REMOVE: "Remove people from the tenant",
    ROLES_READ: "View roles and their permissions",
    ROLES_CREATE: "Create custom roles",
    ROLES_UPDATE: "Change a custom role's permissions",
    ROLES_DELETE: "Delete a custom role",
    ROLES_ASSIGN: "Grant or revoke a member's roles",
    AUDIT_READ: "Read the tenant's audit log",
}

OWNER = "owner"
ADMIN = "admin"
MEMBER = "member"

SYSTEM_ROLES: dict[str, list[str]] = {
    OWNER: list(CATALOGUE),  # everything
    ADMIN: [
        TENANT_READ,
        USERS_READ,
        USERS_INVITE,
        USERS_REMOVE,
        ROLES_READ,
        ROLES_ASSIGN,
        AUDIT_READ,
    ],
    MEMBER: [TENANT_READ, USERS_READ],
}
