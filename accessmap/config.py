"""Application configuration.

All settings are read from the environment (with automatic ``.env``
loading when present) so the same code runs in development, in the
Ubuntu installer, and behind a reverse proxy.

Secrets are never hard-coded: in production (``REQUIRE_SECRET_KEY=1``
or ``FLASK_ENV=production``), startup fails fast if ``SECRET_KEY`` is
missing or weak; in local development, an ephemeral per-process random
key is generated if ``SECRET_KEY`` is not set.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(dotenv_path: Path | None = None) -> None:
    """Load simple KEY=VALUE pairs from ``.env`` into ``os.environ`` if unset."""
    path = dotenv_path or (BASE_DIR / ".env")
    if not path.is_file():
        return
    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                os.environ.setdefault(key, value)
    except OSError:
        pass


_load_dotenv()


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse a boolean environment variable (1/true/yes/on)."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


_EPHEMERAL_DEV_SECRET = secrets.token_hex(32)


class Config:
    """Flask configuration populated from the environment."""

    # --- core -------------------------------------------------------
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "") or _EPHEMERAL_DEV_SECRET
    REQUIRE_SECRET_KEY: bool = _env_bool(
        "REQUIRE_SECRET_KEY",
        os.environ.get("FLASK_ENV", "").strip().lower() == "production",
    )
    DATABASE_URL: str = os.environ.get(
        "DATABASE_URL", str(BASE_DIR / "data" / "accessmap.db")
    )
    HOST: str = os.environ.get("HOST", "0.0.0.0")
    PORT: int = int(os.environ.get("PORT", "5000"))
    DEBUG: bool = _env_bool("DEBUG", False)
    PUBLIC_BASE_URL: str = os.environ.get("PUBLIC_BASE_URL", "").strip()

    # --- security ---------------------------------------------------
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    # Set COOKIE_SECURE=1 when serving over HTTPS (installer sets this
    # when TLS is configured on the nginx reverse proxy).
    SESSION_COOKIE_SECURE: bool = _env_bool("COOKIE_SECURE", False)
    ALLOW_FRAME_EMBED: bool = _env_bool("ALLOW_FRAME_EMBED", False)
    PERMANENT_SESSION_LIFETIME: int = 60 * 60 * 8  # 8 hours

    # --- geo lookup -------------------------------------------------
    GEO_LOOKUP_ENABLED: bool = _env_bool("GEO_LOOKUP_ENABLED", True)
    GEO_LOOKUP_TIMEOUT: float = float(os.environ.get("GEO_LOOKUP_TIMEOUT", "2.5"))
    GEO_LOOKUP_URL: str = os.environ.get(
        "GEO_LOOKUP_URL", "http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp,query"
    )
    GEO_RATE_LIMIT_PER_MIN: int = int(os.environ.get("GEO_RATE_LIMIT_PER_MIN", "30"))
    MAX_GEO_CACHE_ENTRIES: int = int(os.environ.get("MAX_GEO_CACHE_ENTRIES", "10000"))

    # --- ingestion --------------------------------------------------
    MAX_INGEST_BATCH: int = int(os.environ.get("MAX_INGEST_BATCH", "500"))
    MAX_CONTENT_LENGTH: int = 5 * 1024 * 1024  # 5 MB request cap

    # --- auth -------------------------------------------------------
    PBKDF2_ITERATIONS: int = int(os.environ.get("PBKDF2_ITERATIONS", "260000"))
    LOGIN_MAX_ATTEMPTS: int = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
    LOGIN_IP_MAX_ATTEMPTS: int = int(os.environ.get("LOGIN_IP_MAX_ATTEMPTS", "20"))
    LOGIN_LOCKOUT_SECONDS: int = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "300"))
