"""Application configuration.

All settings are read from the environment so the same code runs in
development, in the Ubuntu installer, and behind a reverse proxy.
Secrets are never hard-coded: ``SECRET_KEY`` must be supplied via the
environment (the installer generates one into ``.env``).
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse a boolean environment variable (1/true/yes/on)."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    """Flask configuration populated from the environment."""

    # --- core -------------------------------------------------------
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "dev-only-change-me")
    DATABASE_URL: str = os.environ.get(
        "DATABASE_URL", str(BASE_DIR / "data" / "accessmap.db")
    )
    HOST: str = os.environ.get("HOST", "0.0.0.0")
    PORT: int = int(os.environ.get("PORT", "5000"))
    DEBUG: bool = _env_bool("DEBUG", False)

    # --- security ---------------------------------------------------
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    # Set COOKIE_SECURE=1 when serving over HTTPS (installer does this
    # automatically when it configures the nginx TLS reverse proxy).
    SESSION_COOKIE_SECURE: bool = _env_bool("COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME: int = 60 * 60 * 8  # 8 hours

    # --- geo lookup -------------------------------------------------
    GEO_LOOKUP_ENABLED: bool = _env_bool("GEO_LOOKUP_ENABLED", True)
    GEO_LOOKUP_TIMEOUT: float = float(os.environ.get("GEO_LOOKUP_TIMEOUT", "2.5"))
    GEO_LOOKUP_URL: str = os.environ.get(
        "GEO_LOOKUP_URL", "http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp,query"
    )

    # --- ingestion --------------------------------------------------
    MAX_INGEST_BATCH: int = int(os.environ.get("MAX_INGEST_BATCH", "500"))
    MAX_CONTENT_LENGTH: int = 5 * 1024 * 1024  # 5 MB request cap

    # --- auth -------------------------------------------------------
    PBKDF2_ITERATIONS: int = int(os.environ.get("PBKDF2_ITERATIONS", "260000"))
    LOGIN_MAX_ATTEMPTS: int = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
    LOGIN_LOCKOUT_SECONDS: int = int(os.environ.get("LOGIN_LOCKOUT_SECONDS", "300"))
