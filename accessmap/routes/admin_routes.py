"""Admin panel routes (all require sign-in).

Capabilities: dashboard, enroll/disable/rotate/delete firewalls,
add another admin, change own password, view recent events.
"""

from __future__ import annotations

import secrets

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for

from accessmap import auth, db
from accessmap.routes.auth_routes import _validate_registration

bp = Blueprint("admin", __name__, url_prefix="/admin")

VENDORS = ("fortinet", "paloalto", "other")


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
    """Enroll a new firewall and show its one-time ingest token."""
    if request.method == "POST":
        auth.check_csrf()
        name = request.form.get("name", "").strip()
        vendor = request.form.get("vendor", "").strip().lower()
        host = request.form.get("host", "").strip()
        site = request.form.get("site", "").strip()
        if not name:
            flash("Firewall name is required.", "error")
            return render_template("admin/firewall_form.html", name=name, vendor=vendor, host=host, site=site)
        if vendor not in VENDORS:
            flash("Vendor must be Fortinet, Palo Alto or Other.", "error")
            return render_template("admin/firewall_form.html", name=name, vendor=vendor, host=host, site=site)
        token = secrets.token_urlsafe(32)
        current = auth.current_admin()
        firewall_id = db.create_firewall(name, vendor, host, site, token, int(current["id"]))
        flash("Firewall enrolled. Copy the ingest token now — it is shown only once.", "success")
        return redirect(url_for("admin.firewall_detail", firewall_id=firewall_id))
    return render_template("admin/firewall_form.html")


@bp.route("/firewalls/<int:firewall_id>", methods=["GET"])
@auth.login_required
def firewall_detail(firewall_id: int):
    """Show one firewall, its token and forwarding instructions."""
    firewall = db.get_firewall(firewall_id)
    if firewall is None:
        abort(404)
    return render_template(
        "admin/firewall_detail.html",
        firewall=firewall,
        events=db.list_events(limit=20, firewall_id=firewall_id),
        ingest_url=request.host_url.rstrip("/") + "/api/ingest",
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
    """Rotate a firewall's ingest token (old token stops working)."""
    auth.check_csrf()
    if db.get_firewall(firewall_id) is None:
        abort(404)
    db.update_firewall(firewall_id, token=secrets.token_urlsafe(32))
    flash("Ingest token rotated. Update the firewall forwarder.", "success")
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
@auth.login_required
def new_admin():
    """Add another admin (only signed-in admins can do this)."""
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
        db.create_admin(username, email, auth.hash_password(password), is_super=False)
        flash(f"Admin '{username}' added.", "success")
        return redirect(url_for("admin.dashboard"))
    return render_template("admin/admin_form.html")


@bp.route("/password", methods=["GET", "POST"])
@auth.login_required
def change_password():
    """Change the signed-in admin's own password."""
    current = auth.current_admin()
    if request.method == "POST":
        auth.check_csrf()
        old = request.form.get("old_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm", "")
        if not auth.verify_password(old, current["password_hash"]):
            flash("Current password is incorrect.", "error")
            return render_template("admin/password.html")
        if new != confirm:
            flash("New passwords do not match.", "error")
            return render_template("admin/password.html")
        error = auth.validate_password(new)
        if error:
            flash(error, "error")
            return render_template("admin/password.html")
        db.set_password(int(current["id"]), auth.hash_password(new))
        flash("Password changed.", "success")
        return redirect(url_for("admin.dashboard"))
    return render_template("admin/password.html")
