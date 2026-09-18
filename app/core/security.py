"""Password hashing and JWT helpers.

Milestone 1 — implement these yourself:
- hash_password / verify_password with argon2-cffi (PasswordHasher)
- create_access_token: RS256-signed JWT with sub, tenant_id, iss, aud, iat, exp, jti
- decode_access_token: verify signature, iss, aud and exp; raise on failure
- generate_refresh_token: opaque random string (secrets.token_urlsafe);
  store only its SHA-256 hash in the database
- get_jwks: expose the public key as a JWKS for /.well-known/jwks.json
"""

from typing import Any


def hash_password(password: str) -> str:
    raise NotImplementedError


def verify_password(password: str, password_hash: str) -> bool:
    raise NotImplementedError


def create_access_token(
    subject: str, tenant_id: str | None, extra: dict[str, Any] | None = None
) -> str:
    raise NotImplementedError


def decode_access_token(token: str) -> dict[str, Any]:
    raise NotImplementedError


def generate_refresh_token() -> tuple[str, str]:
    """Return (raw_token, token_hash)."""
    raise NotImplementedError


def get_jwks() -> dict[str, Any]:
    raise NotImplementedError
