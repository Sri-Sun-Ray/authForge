# AuthForge

A multi-tenant authentication and authorization service: OAuth2/JWT with refresh-token
rotation, per-tenant role-based access control (RBAC), Postgres row-level security,
Redis rate limiting, and tamper-evident audit logs.

**Stack:** FastAPI · PostgreSQL · SQLAlchemy 2.0 (async) · Alembic · Redis · Docker · GitHub Actions

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -e ".[dev]"
copy .env.example .env            # macOS/Linux: cp .env.example .env
python scripts/generate_keys.py

docker compose up -d db redis     # Postgres + Redis
alembic upgrade head
uvicorn app.main:app --reload
```

API docs: http://localhost:8000/docs · Health: http://localhost:8000/health/ready

Run everything in Docker instead: `docker compose up --build`

### Two database roles

Postgres lets superusers — and, unless a table is set to `FORCE ROW LEVEL SECURITY`, its
owner — bypass row-level security, so one connection string is not enough:

| Role | Used by | Rights |
| --- | --- | --- |
| `authforge` (`DATABASE_ADMIN_URL`) | Alembic migrations | owns the schema |
| `authforge_app` (`DATABASE_URL`) | the API | read/write rows the policies allow, no DDL |

Migrations create `authforge_app` with the password from `APP_DB_PASSWORD`; set that
outside local development.

## API

| Endpoint | Purpose |
| --- | --- |
| `POST /auth/register` · `/login` · `/refresh` · `/logout` · `GET /auth/me` | accounts and sessions |
| `GET /.well-known/jwks.json` | public keys for verifying access tokens |
| `POST /tenants` · `GET /tenants` | create an organization, list your own |
| `POST /tenants/{id}/switch` | move the session into a tenant (rotates its tokens) |
| `GET /tenants/current` · `/current/members` | the tenant the token is scoped to |
| `POST /tenants/current/invites` · `POST /invites/accept` | invite by email, redeem once |
| `GET /permissions` · `GET /tenants/current/permissions` | the catalogue, and what you may do here |
| `GET/POST /tenants/current/roles` · `PUT/DELETE .../{role_id}` | built-in and custom roles |
| `GET/PUT /tenants/current/users/{user_id}/roles` | read or replace a member's roles |
| `POST /auth/verify-email/request` · `/confirm` | confirm an address with a one-time link |
| `POST /auth/password-reset` · `/password-reset/confirm` | reset a forgotten password |
| `GET /audit-logs` · `/audit-logs/verify` | read the tenant's history, prove it is unaltered |

### Audit log

Logins, invites, role changes and resets are recorded. Entries are chained: each stores
the hash of the previous entry for the same tenant, so editing or deleting one makes
`GET /audit-logs/verify` report where the chain breaks. Writes take a per-tenant advisory
lock, so two concurrent events cannot claim the same predecessor.

Append-only is a database privilege, not a convention: the API's role holds `SELECT` and
`INSERT` on `audit_logs` and nothing else, so even a fully compromised API cannot rewrite
history. Tests assert that `UPDATE` and `DELETE` are refused.

### Abuse protection

- **Rate limits** use a Redis sorted set per bucket — a true sliding window, where a fixed
  window would let twice the limit through at the boundary. Login is limited per IP *and*
  per account, so a botnet spread across many addresses still cannot grind one victim's
  password. Limits come from settings, and a Redis outage fails open rather than locking
  everybody out.
- **Account lockout** after `LOGIN_MAX_FAILED_ATTEMPTS` failures, cleared by a successful
  login or a password reset.
- **One-time links** for verification and reset are stored as hashes, expire, work once,
  and are bound to a purpose, so a verification link cannot reset a password. Requesting a
  new link invalidates the previous one, and a reset revokes every existing session.
- **No account-existence oracle:** password reset answers identically for addresses that
  exist and ones that don't.

Email is not wired to a provider: messages are logged and kept in an in-memory outbox
(`app/services/mailer.py`). Swapping in SES or SendGrid means replacing one function.

### Roles and permissions

Three built-in roles (`owner`, `admin`, `member`) are seeded by a migration and shared by
every tenant; tenants can add their own. Endpoints declare what they need, e.g.
`Depends(require_permission("users:invite"))`.

A user's permissions are cached in Redis for 5 minutes. Any role change bumps a per-tenant
counter that forms part of the cache key, so every cached entry for that tenant is dropped
at once — O(1), with no key scanning. If Redis is unavailable the check falls back to
Postgres rather than failing.

## Tests and linting

```bash
docker compose run --rm --build test    # lint + full suite against real Postgres/Redis
python -m pytest                        # unit tests only, locally
python -m ruff check . && python -m ruff format --check .
```

> **Windows note:** if Windows Application Control / Smart App Control blocks `greenlet`
> (needed by async SQLAlchemy), run the app and tests through Docker as shown above.

## Project layout

```
app/
  api/routes/   HTTP endpoints (thin; call services)
  api/deps.py   auth, tenant and permission dependencies
  core/         settings, JWT/password security, Redis, rate limiting
  db/           SQLAlchemy base and async session
  models/       database tables
  schemas/      Pydantic request/response models
  services/     business logic
alembic/        database migrations
scripts/        key generation and other tooling
tests/
```

## Roadmap

- [x] **1. Core auth:** register, login, logout, Argon2 hashing, RS256 access tokens,
      refresh-token rotation with reuse detection, JWKS endpoint
- [x] **2. Multi-tenancy:** tenants, memberships, invites, tenant switching, Postgres RLS
- [x] **3. RBAC:** roles, permissions, `require_permission()` dependency, Redis permission cache
- [x] **4. Hardening:** sliding-window rate limiting, account lockout, email verification,
      password reset _(Google OAuth2 login still open — needs client credentials)_
- [x] **5. Audit logs:** append-only, hash-chained, searchable per tenant
- [ ] **6. Production:** 80%+ coverage, load test (k6/Locust), deploy to GCP Cloud Run,
      architecture diagrams

## Design decisions

_Fill this in as you build. Interviewers read this section._

- Why RS256 instead of HS256
- Why refresh tokens are opaque and stored hashed
- How tenant isolation is enforced (application layer and RLS)
- How permission-cache invalidation works
