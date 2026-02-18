"""Application configuration management for PhishGuard."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

try:
    from dotenv import load_dotenv  # type: ignore
except Exception:  # pragma: no cover
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv(PROJECT_ROOT / ".env")


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean environment variable."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int | None = None) -> int:
    """Read an integer environment variable with optional floor."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        parsed = int(raw.strip())
    except ValueError:
        return default

    if minimum is not None:
        return max(minimum, parsed)
    return parsed


@dataclass(frozen=True)
class AppConfig:
    """Runtime settings for the PhishGuard application."""

    host: str
    port: int
    debug: bool
    secret_key: str
    max_content_length_bytes: int
    max_url_length: int
    max_email_length: int
    enable_cors: bool
    cors_origins: str
    log_level: str
    rate_limit_requests: int
    rate_limit_window_seconds: int
    use_waitress: bool
    waitress_threads: int
    waitress_connection_limit: int

    @classmethod
    def from_env(cls) -> "AppConfig":
        """Construct config from environment variables."""
        return cls(
            host=os.getenv("PHISHGUARD_HOST", "0.0.0.0"),
            port=_env_int("PHISHGUARD_PORT", 5001, minimum=1),
            debug=_env_bool("PHISHGUARD_DEBUG", False),
            secret_key=os.getenv("PHISHGUARD_SECRET_KEY", "phishguard-dev-secret"),
            max_content_length_bytes=_env_int("PHISHGUARD_MAX_CONTENT_BYTES", 512_000, minimum=1024),
            max_url_length=_env_int("PHISHGUARD_MAX_URL_LENGTH", 2048, minimum=64),
            max_email_length=_env_int("PHISHGUARD_MAX_EMAIL_LENGTH", 250_000, minimum=1024),
            enable_cors=_env_bool("PHISHGUARD_ENABLE_CORS", False),
            cors_origins=os.getenv("PHISHGUARD_CORS_ORIGINS", "*"),
            log_level=os.getenv("PHISHGUARD_LOG_LEVEL", "INFO").upper(),
            rate_limit_requests=_env_int("PHISHGUARD_RATE_LIMIT_REQUESTS", 120, minimum=1),
            rate_limit_window_seconds=_env_int("PHISHGUARD_RATE_LIMIT_WINDOW_SECONDS", 60, minimum=1),
            use_waitress=_env_bool("PHISHGUARD_USE_WAITRESS", True),
            waitress_threads=_env_int("PHISHGUARD_WAITRESS_THREADS", 8, minimum=1),
            waitress_connection_limit=_env_int("PHISHGUARD_WAITRESS_CONNECTION_LIMIT", 1000, minimum=10),
        )
