"""Firewall ingest endpoint.

Firewalls (or a syslog forwarder / small script on the firewall)
POST events here with their enrollment token exclusively in the
``Authorization`` header (never in URL query strings):

    POST /api/ingest
    Authorization: Bearer <ingest_token>
    Content-Type: application/json

    {"events": [{"src_ip": "10.0.0.5", "dst_ip": "203.0.113.10",
                 "dst_domain": "example.com", "dst_port": 443,
                 "protocol": "tcp", "action": "allow", "bytes_out": 1234}]}

Plain-text syslog bodies (FortiGate ``key=value`` / PAN-OS tokens)
are also accepted with ``Content-Type: text/plain``.
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from accessmap import db, ingest

bp = Blueprint("ingest", __name__, url_prefix="/api")


def _bearer_token() -> str:
    """Extract the Bearer token strictly from the Authorization header."""
    header = request.headers.get("Authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return ""


@bp.route("/ingest", methods=["POST"])
def receive_events():
    """Accept a batch of events from an enrolled firewall."""
    token = _bearer_token()
    if not token:
        return jsonify({"error": "missing Authorization: Bearer <token>"}), 401
    firewall = db.get_firewall_by_token(token)
    if firewall is None:
        return jsonify({"error": "invalid ingest token"}), 401
    if not bool(firewall["enabled"]):
        return jsonify({"error": "firewall is disabled"}), 403

    max_batch = int(current_app.config["MAX_INGEST_BATCH"])
    firewall_id = int(firewall["id"])
    content_type = request.headers.get("Content-Type", "")

    if "application/json" in content_type:
        payload = request.get_json(silent=True)
        if payload is None:
            return jsonify({"error": "invalid JSON body"}), 400
        if isinstance(payload, dict):
            raw_items = payload.get("events", [payload])
        elif isinstance(payload, list):
            raw_items = payload
        else:
            return jsonify({"error": "JSON payload must be an object or array"}), 400
        if not isinstance(raw_items, list):
            return jsonify({"error": "'events' must be a JSON array"}), 400
        if len(raw_items) > max_batch:
            return jsonify({"error": "batch too large"}), 413
        events, dropped = ingest.normalize_batch(raw_items, firewall_id)
    else:
        text = request.get_data(as_text=True)
        non_empty_lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        if len(non_empty_lines) > max_batch:
            return jsonify({"error": "batch too large"}), 413
        events, dropped = [], 0
        for line in non_empty_lines:
            normalized = ingest.normalize_event(ingest.parse_syslog_line(line), firewall_id)
            if normalized is None:
                dropped += 1
            else:
                events.append(normalized)

    for event in events:
        db.insert_event(event)
    if events:
        db.touch_firewall(firewall_id)
    return jsonify({"accepted": len(events), "dropped": dropped}), 201
