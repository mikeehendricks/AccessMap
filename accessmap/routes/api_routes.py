"""Public read-only API powering the threat map.

``GET /api/events``   recent events with geo coordinates
``GET /api/stats``    aggregate counters for the header
``GET /api/firewalls`` enrolled firewalls (no tokens exposed)
``GET /api/health``   liveness probe for the installer / systemd
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from accessmap import db

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.route("/health", methods=["GET"])
def health():
    """Liveness probe (also used by the Ubuntu installer's health check)."""
    return jsonify({"status": "ok", "events": db.count_events()})


@bp.route("/events", methods=["GET"])
def events():
    """Return recent events as JSON for the map + live feed."""
    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        limit = 100
    firewall_id = request.args.get("firewall_id", type=int)
    threat = request.args.get("threat", "").strip() or None
    rows = db.list_events(limit=limit, firewall_id=firewall_id, threat=threat)
    return jsonify([dict(row) for row in rows])


@bp.route("/stats", methods=["GET"])
def stats():
    """Return aggregate counters for the map header."""
    return jsonify(db.event_stats())


@bp.route("/firewalls", methods=["GET"])
def firewalls():
    """Return enrolled firewalls (ingest tokens are never exposed)."""
    rows = db.list_firewalls()
    return jsonify([
        {
            "id": r["id"], "name": r["name"], "vendor": r["vendor"],
            "host": r["host"], "site": r["site"], "enabled": bool(r["enabled"]),
            "event_count": r["event_count"], "last_seen_at": r["last_seen_at"],
        }
        for r in rows
    ])


@bp.route("/geo", methods=["GET"])
def geo_lookup():
    """Resolve one IP to a location (used by the map's IP search box)."""
    from accessmap import geo

    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip query parameter is required"}), 400
    result = geo.resolve(ip)
    return jsonify({
        "ip": result.ip, "country": result.country, "city": result.city,
        "lat": result.lat, "lon": result.lon, "isp": result.isp,
        "source": result.source,
    })
