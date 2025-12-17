from functools import lru_cache
from typing import List
import secrets

from pydantic import AnyHttpUrl, PostgresDsn, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "SecureApp"
    ENV: str = "development"
    DEBUG: bool = False

    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    # Database
    DATABASE_URL: PostgresDsn

    # Security
    SECRET_KEY: str = secrets.token_urlsafe(64)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    SESSION_IDLE_TIMEOUT_MINUTES: int = 30
    SESSION_ABSOLUTE_TIMEOUT_HOURS: int = 8
    PASSWORD_HASH_ROUNDS: int = 12
    SESSION_COOKIE_NAME: str = "session_id"

    # CSRF
    CSRF_COOKIE_NAME: str = "csrf_token"
    CSRF_HEADER_NAME: str = "X-CSRF-Token"

    # Rate limiting
    RATE_LIMIT_GENERAL: str = "100/minute"
    RATE_LIMIT_AUTH: str = "5/minute"

    # Encryption (PII) – in production, keys must come from a KMS / secret manager
    PII_ENCRYPTION_KEY_ID: str = "local-dev-key"

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v):
        if isinstance(v, str) and v:
            return [i.strip() for i in v.split(",")]
        return v

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


@lru_cache
def get_settings() -> Settings:
    return Settings()



