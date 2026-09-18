"""Password hashing, JWT access tokens and refresh tokens."""

import base64
import hashlib
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from jwt.algorithms import RSAAlgorithm

from app.core.config import get_settings

ALGORITHM = "RS256"
ACCESS_TOKEN_TYPE = "access"  # noqa: S105 (a claim value, not a secret)

# Claims we set ourselves; callers can't override them through `extra`.
_RESERVED_CLAIMS = {"iss", "aud", "sub", "iat", "nbf", "exp", "jti", "type", "tenant_id"}

_password_hasher = PasswordHasher()  # argon2id with the library's recommended parameters


class TokenError(Exception):
    """Raised for any invalid, expired or tampered token."""


# --- Passwords --------------------------------------------------------------


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    """True if the hash used weaker parameters than today's; rehash after a successful login."""
    return _password_hasher.check_needs_rehash(password_hash)


@lru_cache
def dummy_password_hash() -> str:
    """Verify against this when the email doesn't exist, so login takes the same time
    whether or not the account exists (prevents discovering emails by timing)."""
    return hash_password(secrets.token_urlsafe(16))


# --- Signing keys -----------------------------------------------------------


def _read_key_file(path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"JWT key not found at {path}. Run `python scripts/generate_keys.py`."
        ) from exc


@lru_cache
def _private_key() -> RSAPrivateKey:
    key = serialization.load_pem_private_key(
        _read_key_file(get_settings().jwt_private_key_path), password=None
    )
    if not isinstance(key, RSAPrivateKey):
        raise RuntimeError("JWT private key must be an RSA key")
    return key


@lru_cache
def _public_key() -> RSAPublicKey:
    key = serialization.load_pem_public_key(_read_key_file(get_settings().jwt_public_key_path))
    if not isinstance(key, RSAPublicKey):
        raise RuntimeError("JWT public key must be an RSA key")
    return key


@lru_cache
def _public_jwk() -> dict[str, str]:
    jwk = json.loads(RSAAlgorithm.to_jwk(_public_key()))
    # Key ID = RFC 7638 thumbprint, so it changes automatically when the key is rotated
    canonical = json.dumps({k: jwk[k] for k in ("e", "kty", "n")}, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).digest()
    kid = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return {**jwk, "kid": kid, "use": "sig", "alg": ALGORITHM}


def get_jwks() -> dict[str, Any]:
    """Public keys for /.well-known/jwks.json; other services verify our tokens with these."""
    return {"keys": [_public_jwk()]}


# --- Access tokens (JWT) ----------------------------------------------------


def create_access_token(
    subject: str,
    tenant_id: str | None = None,
    extra: dict[str, Any] | None = None,
    expires_delta: timedelta | None = None,
) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    expires_delta = expires_delta or timedelta(minutes=settings.access_token_ttl_minutes)

    if extra and (clash := _RESERVED_CLAIMS & extra.keys()):
        raise ValueError(f"extra claims may not override reserved claims: {sorted(clash)}")

    payload = {
        **(extra or {}),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": subject,
        "tenant_id": tenant_id,
        "type": ACCESS_TOKEN_TYPE,
        "iat": now,
        "nbf": now,
        "exp": now + expires_delta,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(
        payload, _private_key(), algorithm=ALGORITHM, headers={"kid": _public_jwk()["kid"]}
    )


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        claims = jwt.decode(
            token,
            _public_key(),
            # Never trust the token's own "alg" header: pinning the algorithm blocks
            # "alg: none" and RS256->HS256 key-confusion attacks.
            algorithms=[ALGORITHM],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "jti"]},
            leeway=5,  # seconds of clock skew tolerated between servers
        )
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc

    if claims.get("type") != ACCESS_TOKEN_TYPE:
        raise TokenError("not an access token")
    return claims


# --- Refresh tokens (opaque) ------------------------------------------------


def hash_refresh_token(raw_token: str) -> str:
    # A fast hash is safe here: the token is 256 random bits, so it can't be brute-forced,
    # and a deterministic hash lets us look the token up by its hash.
    return hashlib.sha256(raw_token.encode()).hexdigest()


def generate_refresh_token() -> tuple[str, str]:
    """Return (raw_token, token_hash). Send the raw token to the client; store only the hash."""
    raw_token = secrets.token_urlsafe(32)
    return raw_token, hash_refresh_token(raw_token)
