from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "AuthForge"
    environment: str = "local"  # local | test | production
    debug: bool = False

    # The API connects as a restricted role that cannot bypass row-level security
    database_url: str = "postgresql+asyncpg://authforge_app:authforge_app@localhost:5432/authforge"
    # Migrations need table ownership, so they use this one (defaults to database_url)
    database_admin_url: str | None = None
    redis_url: str = "redis://localhost:6380/0"

    # JWT (RS256): generate keys with `python scripts/generate_keys.py`
    jwt_private_key_path: Path = Path("keys/private.pem")
    jwt_public_key_path: Path = Path("keys/public.pem")
    jwt_issuer: str = "authforge"
    jwt_audience: str = "authforge-clients"
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 7
    invite_ttl_days: int = 7

    # Security
    login_max_failed_attempts: int = 5
    login_lockout_minutes: int = 15
    verification_token_ttl_hours: int = 24
    password_reset_token_ttl_minutes: int = 30

    # Rate limits (per client IP unless stated otherwise)
    rate_limit_login_per_minute: int = 10
    rate_limit_login_per_account_per_minute: int = 5
    rate_limit_register_per_hour: int = 20
    rate_limit_password_reset_per_hour: int = 5

    # Used to build the links sent by email
    app_base_url: str = "http://localhost:8000"

    # OAuth2 (Google)
    google_client_id: str = ""
    google_client_secret: str = ""

    cors_origins: list[str] = ["http://localhost:3000"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
