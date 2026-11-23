"""Authentication, sessions, CSRF, token hashing, and rate limiting.

* Passwords: PBKDF2-HMAC-SHA256 with a per-password random salt
  (stdlib ``hashlib`` — no third-party crypto dependency).
* Ingest tokens: SHA-256 hashed at rest (raw token shown strictly once).
* Sessions: Flask signed cookies (HttpOnly + SameSite=Lax; Secure
  when behind HTTPS) bound to a password-hash fingerprint so password
  changes immediately invalidate any other sessions.
* CSRF: a per-session token is embedded in every form and verified
  on every state-changing POST (constant-time comparison).
* Login throttling: keyed by ``(client_ip, username)`` plus a per-IP
  cap with bounded memory eviction so an attacker cannot globally lock
  out a legitimate admin from another IP.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from functools import wraps
from typing import Optional

from flask import abort, current_app, flash, g, redirect, request, session, url_for

_MAX_THROTTLE_KEYS = 4096
# (scope_ip, username_or_star) -> (failures, locked_until)
_THROTTLE: dict[tuple[str, str], tuple[int, float]] = {}
# (bucket, client_ip) -> [timestamps...]
_RATE_BUCKETS: dict[tuple[str, str], list[float]] = {}
# iterations -> precomputed dummy password hash (mitigates timing oracle)
_DUMMY_HASHES: dict[int, str] = {}


# ---------------------------------------------------------------------------
# Password & token hashing
# ---------------------------------------------------------------------------

def hash_password(password: str, iterations: Optional[int] = None) -> str:
    """Hash a password as ``pbkdf2_sha256$<iter>$<salt_hex>$<hash_hex>``."""
    rounds = iterations or current_app.config["PBKDF2_ITERATIONS"]
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return f"pbkdf2_sha256${rounds}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Check a password against a stored hash (constant-time compare)."""
    try:
        scheme, rounds, salt_hex, hash_hex = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), hash_hex)


def dummy_verify_password(password: str) -> None:
    """Run a constant-work PBKDF2 check when a username does not exist."""
    rounds = int(current_app.config["PBKDF2_ITERATIONS"])
    dummy = _DUMMY_HASHES.get(rounds)
    if dummy is None:
        dummy = hash_password("dummy-timing-equalizer-password-1", iterations=rounds)
        _DUMMY_HASHES[rounds] = dummy
    verify_password(password, dummy)


def hash_token(raw_token: str) -> str:
    """Return the hex SHA-256 digest of a high-entropy firewall ingest token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _pwd_fingerprint(password_hash: str) -> str:
    """Short non-reversible session tag derived from the current password hash."""
    return hashlib.sha256(password_hash.encode("utf-8")).hexdigest()[:16]


def validate_password(password: str) -> Optional[str]:
    """Return a human-readable error, or None if the password is strong."""
    if len(password) < 10:
        return "Password must be at least 10 characters long."
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        return "Password must contain at least one letter and one digit."
    return None


# ---------------------------------------------------------------------------
# Sessions, RBAC & CSRF
# ---------------------------------------------------------------------------

def login_admin(admin_id: int, password_hash: Optional[str] = None) -> None:
    """Start (or refresh) an authenticated session bound to ``password_hash``."""
    if password_hash is None:
        from accessmap import db

        row = db.get_admin_by_id(admin_id)
        password_hash = str(row["password_hash"]) if row else ""
    session.clear()
    session["admin_id"] = admin_id
    session["pwd_ver"] = _pwd_fingerprint(password_hash)
    session["csrf"] = secrets.token_hex(16)
    session.permanent = True


def logout_admin() -> None:
    """End the current session."""
    session.clear()
    g.pop("admin", None)


def current_admin() -> Optional[dict]:
    """Return the logged-in admin as a dict, or None if unauthenticated/stale."""
    admin_id = session.get("admin_id")
    if admin_id is None:
        return None
    cache_key = (int(admin_id), str(session.get("pwd_ver", "")))
    if g.get("_admin_cache_key") != cache_key:
        from accessmap import db

        row = db.get_admin_by_id(int(admin_id))
        if row is None:
            session.clear()
            g.admin = None
        else:
            expected_ver = _pwd_fingerprint(str(row["password_hash"]))
            provided_ver = str(session.get("pwd_ver", ""))
            if not provided_ver or not hmac.compare_digest(expected_ver, provided_ver):
                session.clear()
                g.admin = None
            else:
                g.admin = dict(row)
        g._admin_cache_key = cache_key
    return g.admin


def csrf_token() -> str:
    """Return (creating if needed) the per-session CSRF token."""
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return str(session["csrf"])


def check_csrf() -> None:
    """Abort with 400 if the submitted CSRF token does not match."""
    expected = session.get("csrf", "")
    provided = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    if not expected or not hmac.compare_digest(expected, provided):
        abort(400, "Invalid or missing CSRF token.")


def login_required(view):
    """Decorator: require an authenticated admin for a view."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        if current_admin() is None:
            flash("Please sign in to continue.", "error")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapper


def super_required(view):
    """Decorator: require an authenticated super-admin for privileged actions."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        admin = current_admin()
        if admin is None:
            flash("Please sign in to continue.", "error")
            return redirect(url_for("auth.login", next=request.path))
        if not bool(admin.get("is_super")):
            abort(403, "Only a super-admin can perform this action.")
        return view(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Client IP, login throttling & API rate limiting
# ---------------------------------------------------------------------------

def client_ip() -> str:
    """Return the direct remote client address."""
    return (request.remote_addr or "unknown").strip()


def _prune_throttle(now: float) -> None:
    if len(_THROTTLE) < _MAX_THROTTLE_KEYS:
        return
    expired = [k for k, (_, until) in _THROTTLE.items() if until <= now]
    for k in expired:
        _THROTTLE.pop(k, None)
    while len(_THROTTLE) >= _MAX_THROTTLE_KEYS:
        _THROTTLE.pop(next(iter(_THROTTLE)))


def is_locked_out(username: str, ip: Optional[str] = None) -> bool:
    """Return True if ``(ip, username)`` or ``(ip, '*')`` is in lockout."""
    now = time.time()
    addr = ip or client_ip()
    u_fail, u_until = _THROTTLE.get((addr, username.lower()), (0, 0.0))
    if u_fail >= current_app.config["LOGIN_MAX_ATTEMPTS"] and now < u_until:
        return True
    ip_max = int(current_app.config.get("LOGIN_IP_MAX_ATTEMPTS", 20))
    i_fail, i_until = _THROTTLE.get((addr, "*"), (0, 0.0))
    return i_fail >= ip_max and now < i_until


def record_failure(username: str, ip: Optional[str] = None) -> None:
    """Count a failed login attempt for both ``(ip, username)`` and ``(ip, '*')``."""
    now = time.time()
    _prune_throttle(now)
    addr = ip or client_ip()
    lockout = float(current_app.config["LOGIN_LOCKOUT_SECONDS"])
    for key in ((addr, username.lower()), (addr, "*")):
        failures, prev_until = _THROTTLE.get(key, (0, 0.0))
        if prev_until and now >= prev_until:
            failures = 0
        _THROTTLE[key] = (failures + 1, now + lockout)


def record_success(username: str, ip: Optional[str] = None) -> None:
    """Clear the ``(ip, username)`` failure counter after a successful login."""
    addr = ip or client_ip()
    _THROTTLE.pop((addr, username.lower()), None)


def allow_rate_limit(bucket: str, limit: int, window_seconds: float = 60.0) -> bool:
    """Simple sliding-window per-IP rate limiter for public API endpoints."""
    now = time.time()
    if len(_RATE_BUCKETS) >= _MAX_THROTTLE_KEYS:
        _RATE_BUCKETS.clear()
    key = (bucket, client_ip())
    cutoff = now - window_seconds
    hits = [t for t in _RATE_BUCKETS.get(key, []) if t > cutoff]
    if len(hits) >= limit:
        _RATE_BUCKETS[key] = hits
        return False
    hits.append(now)
    _RATE_BUCKETS[key] = hits
    return True
