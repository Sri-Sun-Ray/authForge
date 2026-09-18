"""SQLAlchemy models. Import every model module here so Alembic autogenerate sees it.

Tables to design (one module each):

Milestone 1 (models/user.py, models/token.py)
- users: id, email (unique), password_hash (nullable for Google-only users),
  is_active, is_email_verified, failed_login_count, locked_until
- refresh_tokens: id, user_id, tenant_id, token_hash (unique), family_id,
  expires_at, revoked_at, replaced_by_id, created_ip, user_agent

Milestone 2 (models/tenant.py)
- tenants: id, name, slug (unique)
- memberships: user_id, tenant_id (unique together), status
- invites: tenant_id, email, token_hash, role_id, expires_at, accepted_at

Milestone 3 (models/rbac.py)
- permissions: id, code (e.g. "users:invite"), description
- roles: id, tenant_id (null = built-in role), name
- role_permissions: role_id, permission_id
- user_roles: user_id, role_id, tenant_id

Milestone 4 (models/token.py)
- one_time_tokens: user_id, purpose (verify_email | reset_password), token_hash,
  expires_at, used_at

Milestone 5 (models/audit.py)
- audit_logs: id, tenant_id, actor_user_id, action, target_type, target_id,
  ip, user_agent, metadata (JSONB), created_at, prev_hash, hash
"""

from app.db.base import Base
from app.models.token import RefreshToken
from app.models.user import User

__all__ = ["Base", "RefreshToken", "User"]
