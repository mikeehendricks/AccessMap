"""Authentication, sessions and CSRF protection.

* Passwords: PBKDF2-HMAC-SHA256 with a per-password random salt
  (stdlib ``hashlib`` — no third-party crypto dependency).
* Sessions: Flask signed cookies (HttpOnly + SameSite=Lax; Secure
  when behind HTTPS). The session stores only the admin id.
* CSRF: a per-session token is embedded in every form and verified
  on every state-changing POST (constant-time comparison).
* Login throttling: per-username failure counter with lockout.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from functools import wraps
from typing import Optional

from flask import abort, current_app, flash, g, redirect, request, session, url_for

# In-memory login-throttle state: username -> (failures, locked_until).
# Adequate for a single-process deployment; documented in README.
_THROTTLE: dict[str, tuple[int, float]] = {}


# ---------------------------------------------------------------------------
# Password hashing
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


def validate_password(password: str) -> Optional[str]:
    """Return a human-readable error, or None if the password is strong."""
    if len(password) < 10:
        return "Password must be at least 10 characters long."
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        return "Password must contain at least one letter and one digit."
    return None


# ---------------------------------------------------------------------------
# Sessions & CSRF
# ---------------------------------------------------------------------------

def login_admin(admin_id: int) -> None:
    """Start an authenticated session for an admin."""
    session.clear()
    session["admin_id"] = admin_id
    session["csrf"] = secrets.token_hex(16)
    session.permanent = True


def logout_admin() -> None:
    """End the current session."""
    session.clear()


def current_admin() -> Optional[dict]:
    """Return the logged-in admin as a dict, or None."""
    admin_id = session.get("admin_id")
    if admin_id is None:
        return None
    if "admin" not in g:
        from accessmap import db

        row = db.get_admin_by_id(int(admin_id))
        g.admin = dict(row) if row else None
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


# ---------------------------------------------------------------------------
# Login throttling
# ---------------------------------------------------------------------------

def is_locked_out(username: str) -> bool:
    """Return True while a username is in its lockout window."""
    failures, locked_until = _THROTTLE.get(username.lower(), (0, 0.0))
    return failures >= current_app.config["LOGIN_MAX_ATTEMPTS"] and time.time() < locked_until


def record_failure(username: str) -> None:
    """Count a failed login attempt and arm the lockout if needed."""
    key = username.lower()
    failures, _ = _THROTTLE.get(key, (0, 0.0))
    failures += 1
    locked_until = time.time() + current_app.config["LOGIN_LOCKOUT_SECONDS"]
    _THROTTLE[key] = (failures, locked_until)


def record_success(username: str) -> None:
    """Clear throttle state after a successful login."""
    _THROTTLE.pop(username.lower(), None)
