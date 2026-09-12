"""
SentinelScan Configuration.

Validates critical production settings at startup.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator
from typing import Optional
import secrets


# Known weak/placeholder SECRET_KEY values that must be rejected in production
_WEAK_SECRETS = {
    "change-this-in-production-at-least-32-characters-long",
    "your-super-secret-jwt-key-change-in-production-min-32-chars",
    "secret",
    "changeme",
    "password",
    "dev",
    "development",
    "test",
}


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://sentinelscan:sentinelscan_pass@localhost:5432/sentinelscan"
    SYNC_DATABASE_URL: str = "postgresql://sentinelscan:sentinelscan_pass@localhost:5432/sentinelscan"

    # Security
    SECRET_KEY: str = "change-this-in-production-at-least-32-characters-long"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    REQUIRE_EMAIL_VERIFICATION: bool = True

    # Development bypass — allows bypassing email verification in dev WITHOUT SMTP.
    # FORBIDDEN in production (enforced by validator below).
    DEV_BYPASS_EMAIL_VERIFICATION: bool = False

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Google OAuth
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/api/auth/google/callback"

    # Email / SMTP
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: str = "noreply@sentinelscan.io"
    SMTP_FROM_NAME: str = "SentinelScan"

    # URLs
    FRONTEND_URL: str = "http://localhost:3000"
    BACKEND_URL: str = "http://localhost:8000"

    # App
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    APP_NAME: str = "SentinelScan"
    APP_VERSION: str = "1.0.0"

    # Rate Limits
    RATE_LIMIT_SCANS_PER_HOUR: int = 10
    RATE_LIMIT_AUTH_PER_MINUTE: int = 5

    # Scanner
    MAX_SCAN_TIMEOUT: int = 600        # Overall scan job timeout (seconds)
    MAX_CONCURRENT_SCANS: int = 5      # Kept for UI display / planning

    # ARQ Worker
    WORKER_CONCURRENCY: int = 5        # Max concurrent scan jobs per worker
    WORKER_MAX_TRIES: int = 3          # Max delivery attempts per job
    ARQ_QUEUE_NAME: str = "arq:queue"
    # A worker heartbeat is considered stale when its last update is older
    # than this many seconds. Must exceed MAX_SCAN_TIMEOUT + health_check_interval
    # (600 + 60) because ARQ only refreshes the heartbeat between jobs — a healthy
    # worker running a long scan will legitimately have an old heartbeat.
    WORKER_HEARTBEAT_STALE_SECONDS: int = 720

    # Per-user limits
    MAX_ACTIVE_SCANS_PER_USER: int = 2  # Max pending+running scans per user

    # SSE one-time ticket TTL (seconds). Env-agnostic — same value in all environments.
    SSE_TICKET_TTL_SECONDS: int = 300

    # CVE / NVD Integration
    NVD_API_KEY: Optional[str] = None

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        is_prod = self.ENVIRONMENT == "production"

        # --- SECRET_KEY validation ---
        key = self.SECRET_KEY
        if is_prod:
            if key in _WEAK_SECRETS:
                raise ValueError(
                    "FATAL: SECRET_KEY is a known placeholder value. "
                    "Set a strong, unique SECRET_KEY before deploying to production. "
                    "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
                )
            if len(key) < 32:
                raise ValueError(
                    f"FATAL: SECRET_KEY is too short ({len(key)} chars). "
                    "Minimum 32 characters required for production."
                )

        # --- Production-only mandatory checks ---
        if is_prod:
            if not self.REQUIRE_EMAIL_VERIFICATION:
                raise ValueError(
                    "REQUIRE_EMAIL_VERIFICATION cannot be False in production environment"
                )
            if self.DEBUG:
                raise ValueError("DEBUG cannot be True in production environment")
            if self.DEV_BYPASS_EMAIL_VERIFICATION:
                raise ValueError(
                    "DEV_BYPASS_EMAIL_VERIFICATION cannot be True in production environment. "
                    "This setting exists only for local development convenience."
                )

        return self


settings = Settings()
