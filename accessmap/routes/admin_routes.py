"""Admin panel routes (all require sign-in).

Capabilities: dashboard, enroll/disable/rotate/delete firewalls,
add another admin (super-admin only), change own password, view recent events.
"""

from __future__ import annotations

import re
import secrets

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for

from accessmap import auth, db
from accessmap.routes.auth_routes import _validate_registration

bp = Blueprint("admin", __name__, url_prefix="/admin")

VENDORS = ("fortinet", "paloalto", "other")
_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9.:-]+$")


def _safe_ingest_url() -> str:
    """Build a sanitized ingest URL so crafted Host headers cannot inject CLI text."""
    configured = str(current_app.config.get("PUBLIC_BASE_URL", "")).strip().rstrip("/")
    if configured.startswith(("http://", "https://")):
        return f"{configured}/api/ingest"
    scheme = "https" if request.is_secure else "http"
    host = (request.host or "").strip()
    if not host or not _SAFE_HOST_RE.match(host):
        host = f"localhost:{current_app.config.get('PORT', 5000)}"
    return f"{scheme}://{host}/api/ingest"


@bp.route("/", methods=["GET"])
@auth.login_required
def dashboard():
    """Admin dashboard: stats, firewalls, admins, recent events."""
    return render_template(
        "admin/dashboard.html",
        stats=db.event_stats(),
        firewalls=db.list_firewalls(),
        admins=db.list_admins(),
        events=db.list_events(limit=15),
        current=auth.current_admin(),
    )


@bp.route("/firewalls/new", methods=["GET", "POST"])
@auth.login_required
def new_firewall():
    """Enroll a new firewall and flash its one-time ingest token via session."""
    if request.method == "POST":
        auth.check_csrf()
        name = request.form.get("name", "").strip()[:80]
        vendor = request.form.get("vendor", "").strip().lower()
        host = request.form.get("host", "").strip()[:128]
        site = request.form.get("site", "").strip()[:80]
        if not name:
            flash("Firewall name is required.", "error")
            return render_template("admin/firewall_form.html", name=name, vendor=vendor, host=host, site=site)
        if vendor not in VENDORS:
            flash("Vendor must be Fortinet, Palo Alto or Other.", "error")
            return render_template("admin/firewall_form.html", name=name, vendor=vendor, host=host, site=site)
        token = secrets.token_urlsafe(32)
        current = auth.current_admin()
        firewall_id = db.create_firewall(name, vendor, host, site, token, int(current["id"]))
        session["new_firewall_token"] = {"firewall_id": firewall_id, "token": token}
        flash("Firewall enrolled. Copy the ingest token now — it will never be shown again.", "success")
        return redirect(url_for("admin.firewall_detail", firewall_id=firewall_id))
    return render_template("admin/firewall_form.html")


@bp.route("/firewalls/<int:firewall_id>", methods=["GET"])
@auth.login_required
def firewall_detail(firewall_id: int):
    """Show one firewall, revealing the raw token strictly once after enroll/rotate."""
    firewall = db.get_firewall(firewall_id)
    if firewall is None:
        abort(404)
    revealed_token = None
    pending = session.get("new_firewall_token")
    if isinstance(pending, dict) and pending.get("firewall_id") == firewall_id:
        session.pop("new_firewall_token", None)
        revealed_token = str(pending.get("token") or "") or None
    return render_template(
        "admin/firewall_detail.html",
        firewall=firewall,
        revealed_token=revealed_token,
        events=db.list_events(limit=20, firewall_id=firewall_id),
        ingest_url=_safe_ingest_url(),
    )


@bp.route("/firewalls/<int:firewall_id>/toggle", methods=["POST"])
@auth.login_required
def toggle_firewall(firewall_id: int):
    """Enable/disable a firewall (disabled firewalls cannot ingest)."""
    auth.check_csrf()
    firewall = db.get_firewall(firewall_id)
    if firewall is None:
        abort(404)
    db.update_firewall(firewall_id, enabled=not bool(firewall["enabled"]))
    flash("Firewall updated.", "success")
    return redirect(url_for("admin.firewall_detail", firewall_id=firewall_id))


@bp.route("/firewalls/<int:firewall_id>/rotate-token", methods=["POST"])
@auth.login_required
def rotate_token(firewall_id: int):
    """Rotate a firewall's ingest token (old token stops working immediately)."""
    auth.check_csrf()
    if db.get_firewall(firewall_id) is None:
        abort(404)
    token = secrets.token_urlsafe(32)
    db.update_firewall(firewall_id, token=token)
    session["new_firewall_token"] = {"firewall_id": firewall_id, "token": token}
    flash("Ingest token rotated. Copy the new token now — it will never be shown again.", "success")
    return redirect(url_for("admin.firewall_detail", firewall_id=firewall_id))


@bp.route("/firewalls/<int:firewall_id>/delete", methods=["POST"])
@auth.login_required
def delete_firewall(firewall_id: int):
    """Delete a firewall and all of its events."""
    auth.check_csrf()
    if db.get_firewall(firewall_id) is None:
        abort(404)
    db.delete_firewall(firewall_id)
    flash("Firewall and its events deleted.", "success")
    return redirect(url_for("admin.dashboard"))


@bp.route("/admins/new", methods=["GET", "POST"])
@auth.super_required
def new_admin():
    """Add another admin (restricted to signed-in super-admins)."""
    if request.method == "POST":
        auth.check_csrf()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        error = _validate_registration(username, email, password, confirm)
        if error:
            flash(error, "error")
            return render_template("admin/admin_form.html", username=username, email=email)
        if db.get_admin_by_username(username) is not None:
            flash("That username is already taken.", "error")
            return render_template("admin/admin_form.html", username=username, email=email)
        if db.get_admin_by_email(email) is not None:
            flash("That email address is already registered.", "error")
            return render_template("admin/admin_form.html", username=username, email=email)
        db.create_admin(username, email, auth.hash_password(password), is_super=False)
        flash(f"Admin '{username}' added.", "success")
        return redirect(url_for("admin.dashboard"))
    return render_template("admin/admin_form.html")


@bp.route("/password", methods=["GET", "POST"])
@auth.login_required
def change_password():
    """Change the signed-in admin's own password and invalidate other sessions."""
    current = auth.current_admin()
    if request.method == "POST":
        auth.check_csrf()
        old = request.form.get("old_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm", "")
        if not auth.verify_password(old, str(current["password_hash"])):
            flash("Current password is incorrect.", "error")
            return render_template("admin/password.html")
        if new != confirm:
            flash("New passwords do not match.", "error")
            return render_template("admin/password.html")
        error = auth.validate_password(new)
        if error:
            flash(error, "error")
            return render_template("admin/password.html")
        new_hash = auth.hash_password(new)
        db.set_password(int(current["id"]), new_hash)
        # Re-bind current session to the new password fingerprint; any other
        # sessions using the previous password_hash are invalidated immediately.
        auth.login_admin(int(current["id"]), new_hash)
        flash("Password changed.", "success")
        return redirect(url_for("admin.dashboard"))
    return render_template("admin/password.html")
