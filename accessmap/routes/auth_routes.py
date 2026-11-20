"""Authentication routes: one-time registration, login, logout.

One-time registration rule: the public ``/register`` page is only
available while *zero* admins exist. The first admin created becomes
a super-admin; afterwards the route returns 403 and additional
admins can only be created from the admin panel by a signed-in admin.
"""

from __future__ import annotations

import re

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for

from accessmap import auth, db

bp = Blueprint("auth", __name__)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


@bp.route("/register", methods=["GET", "POST"])
def register():
    """One-time first-admin registration (disabled once an admin exists)."""
    if db.count_admins() > 0:
        abort(403, "Registration is closed. Ask an existing admin to add you.")
    if request.method == "POST":
        auth.check_csrf()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        error = _validate_registration(username, email, password, confirm)
        if error:
            flash(error, "error")
            return render_template("register.html", username=username, email=email)
        db.create_admin(username, email, auth.hash_password(password), is_super=True)
        flash("Admin account created. Please sign in.", "success")
        return redirect(url_for("auth.login"))
    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    """Sign in with username + password (throttled)."""
    if auth.current_admin() is not None:
        return redirect(url_for("admin.dashboard"))
    if request.method == "POST":
        auth.check_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if auth.is_locked_out(username):
            flash("Too many failed attempts. Try again later.", "error")
            return render_template("login.html", username=username)
        admin = db.get_admin_by_username(username)
        if admin is None or not auth.verify_password(password, admin["password_hash"]):
            auth.record_failure(username)
            flash("Invalid username or password.", "error")
            return render_template("login.html", username=username)
        auth.record_success(username)
        auth.login_admin(int(admin["id"]))
        db.touch_login(int(admin["id"]))
        flash(f"Welcome back, {admin['username']}.", "success")
        next_url = request.args.get("next", "")
        if next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect(url_for("admin.dashboard"))
    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
def logout():
    """Sign out (POST + CSRF so logout cannot be triggered by a link)."""
    auth.check_csrf()
    auth.logout_admin()
    flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))


def _validate_registration(username: str, email: str, password: str, confirm: str) -> str | None:
    """Validate registration input; return an error message or None."""
    if not _USERNAME_RE.match(username):
        return "Username must be 3-32 characters: letters, digits, _ . -"
    if not _EMAIL_RE.match(email):
        return "Please enter a valid email address."
    if password != confirm:
        return "Passwords do not match."
    return auth.validate_password(password)


# Re-exported for tests / reuse by the admin panel.
validate_email = lambda value: bool(_EMAIL_RE.match(value or ""))  # noqa: E731
