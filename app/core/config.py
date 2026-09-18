from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "AuthForge"
    environment: str = "local"  # local | test | production
    debug: bool = False

    database_url: str = "postgresql+asyncpg://authforge:authforge@localhost:5432/authforge"
    redis_url: str = "redis://localhost:6380/0"

    # JWT (RS256): generate keys with `python scripts/generate_keys.py`
    jwt_private_key_path: Path = Path("keys/private.pem")
    jwt_public_key_path: Path = Path("keys/public.pem")
    jwt_issuer: str = "authforge"
    jwt_audience: str = "authforge-clients"
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 7

    # Security
    login_max_failed_attempts: int = 5
    login_lockout_minutes: int = 15
    rate_limit_login_per_minute: int = 10

    # OAuth2 (Google)
    google_client_id: str = ""
    google_client_secret: str = ""

    cors_origins: list[str] = ["http://localhost:3000"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
