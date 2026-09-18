from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import get_settings
from app.core.security import (
    TokenError,
    _private_key,
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    get_jwks,
    hash_password,
    hash_refresh_token,
    password_needs_rehash,
    verify_password,
)

# --- Passwords --------------------------------------------------------------


def test_password_hash_roundtrip() -> None:
    password_hash = hash_password("correct horse battery staple")

    assert password_hash.startswith("$argon2id$")
    assert verify_password("correct horse battery staple", password_hash)
    assert not verify_password("wrong password", password_hash)
    assert not password_needs_rehash(password_hash)


def test_same_password_gets_different_hashes() -> None:
    # Random salt per hash, so identical passwords don't produce identical hashes
    assert hash_password("same") != hash_password("same")


def test_verify_password_with_malformed_hash_returns_false() -> None:
    assert not verify_password("anything", "not-a-real-hash")


# --- Access tokens ----------------------------------------------------------


def test_access_token_roundtrip() -> None:
    token = create_access_token("user-123", tenant_id="tenant-9", extra={"email": "a@b.com"})
    claims = decode_access_token(token)

    assert claims["sub"] == "user-123"
    assert claims["tenant_id"] == "tenant-9"
    assert claims["email"] == "a@b.com"
    assert claims["type"] == "access"
    assert claims["iss"] == get_settings().jwt_issuer


def test_each_token_has_unique_jti() -> None:
    first = decode_access_token(create_access_token("u"))
    second = decode_access_token(create_access_token("u"))
    assert first["jti"] != second["jti"]


def test_expired_token_is_rejected() -> None:
    token = create_access_token("u", expires_delta=timedelta(seconds=-30))
    with pytest.raises(TokenError, match="expired"):
        decode_access_token(token)


def test_tampered_token_is_rejected() -> None:
    header, payload, signature = create_access_token("u").split(".")
    forged_payload = jwt.utils.base64url_encode(b'{"sub":"admin"}').decode()
    with pytest.raises(TokenError):
        decode_access_token(f"{header}.{forged_payload}.{signature}")


def test_unsigned_alg_none_token_is_rejected() -> None:
    settings = get_settings()
    now = datetime.now(UTC)
    forged = jwt.encode(
        {
            "sub": "admin",
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "jti": "x",
            "type": "access",
        },
        key=None,
        algorithm="none",
    )
    with pytest.raises(TokenError):
        decode_access_token(forged)


def test_validly_signed_non_access_token_is_rejected() -> None:
    # e.g. a future email-verification JWT must not work as a login token
    settings = get_settings()
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "u",
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "jti": "x",
            "type": "verify_email",
        },
        _private_key(),
        algorithm="RS256",
    )
    with pytest.raises(TokenError, match="not an access token"):
        decode_access_token(token)


def test_extra_claims_cannot_override_reserved_claims() -> None:
    with pytest.raises(ValueError, match="sub"):
        create_access_token("user-123", extra={"sub": "admin"})


def test_token_verifies_with_published_jwks() -> None:
    token = create_access_token("u")
    jwk = get_jwks()["keys"][0]

    assert jwt.get_unverified_header(token)["kid"] == jwk["kid"]
    public_key = jwt.PyJWK(jwk).key
    claims = jwt.decode(
        token, public_key, algorithms=["RS256"], audience=get_settings().jwt_audience
    )
    assert claims["sub"] == "u"


def test_jwks_never_exposes_private_key_material() -> None:
    jwk = get_jwks()["keys"][0]
    assert {"d", "p", "q", "dp", "dq", "qi"}.isdisjoint(jwk)


# --- Refresh tokens ---------------------------------------------------------


def test_refresh_token_generation() -> None:
    raw, token_hash = generate_refresh_token()

    assert len(raw) >= 43  # 32 random bytes, base64url-encoded
    assert token_hash == hash_refresh_token(raw)
    assert len(token_hash) == 64
    assert raw not in token_hash


def test_refresh_tokens_are_unique() -> None:
    assert len({generate_refresh_token()[0] for _ in range(100)}) == 100
