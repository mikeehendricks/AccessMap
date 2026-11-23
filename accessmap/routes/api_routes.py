"""Public read-only API powering the threat map.

``GET /api/events``    recent events with geo coordinates (private IPs/usernames
                       redacted for unauthenticated viewers)
``GET /api/stats``     aggregate counters for the header
``GET /api/firewalls`` enrolled firewalls (no tokens; host omitted publicly)
``GET /api/geo``       rate-limited IP -> geo resolution
``GET /api/health``    liveness probe for the installer / systemd
"""

from __future__ import annotations

import ipaddress

from flask import Blueprint, current_app, jsonify, request

from accessmap import auth, db, geo

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.route("/health", methods=["GET"])
def health():
    """Liveness probe (also used by the Ubuntu installer's health check)."""
    return jsonify({"status": "ok", "events": db.count_events()})


@bp.route("/events", methods=["GET"])
def events():
    """Return recent events as JSON, redacting internal host details when logged out."""
    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        limit = 100
    firewall_id = request.args.get("firewall_id", type=int)
    threat = request.args.get("threat", "").strip() or None
    rows = db.list_events(limit=limit, firewall_id=firewall_id, threat=threat)
    is_admin = auth.current_admin() is not None

    payload = []
    for row in rows:
        item = dict(row)
        if not is_admin:
            item["src_ip"] = geo.redact_ip_for_public(str(item.get("src_ip", "")))
            item["dst_ip"] = geo.redact_ip_for_public(str(item.get("dst_ip", "")))
            item["user_name"] = ""
        payload.append(item)
    return jsonify(payload)


@bp.route("/stats", methods=["GET"])
def stats():
    """Return aggregate counters for the map header."""
    return jsonify(db.event_stats())


@bp.route("/firewalls", methods=["GET"])
def firewalls():
    """Return enrolled firewalls (tokens never exposed; host shown only to admins)."""
    rows = db.list_firewalls()
    is_admin = auth.current_admin() is not None
    result = []
    for r in rows:
        entry = {
            "id": r["id"],
            "name": r["name"],
            "vendor": r["vendor"],
            "site": r["site"],
            "enabled": bool(r["enabled"]),
            "event_count": r["event_count"],
            "last_seen_at": r["last_seen_at"],
        }
        if is_admin:
            entry["host"] = r["host"]
        result.append(entry)
    return jsonify(result)


@bp.route("/geo", methods=["GET"])
def geo_lookup():
    """Resolve one valid IP to a location (rate-limited)."""
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip query parameter is required"}), 400
    try:
        canonical_ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return jsonify({"error": "invalid IP address"}), 400

    limit = int(current_app.config.get("GEO_RATE_LIMIT_PER_MIN", 30))
    if not auth.allow_rate_limit("geo", limit, window_seconds=60.0):
        return jsonify({"error": "rate limit exceeded; try again shortly"}), 429

    result = geo.resolve(canonical_ip)
    return jsonify({
        "ip": result.ip, "country": result.country, "city": result.city,
        "lat": result.lat, "lon": result.lon, "isp": result.isp,
        "source": result.source,
    })
