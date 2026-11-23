"""Ingest tests: JSON + syslog ingestion, auth, geo enrichment."""

from accessmap import db

SAMPLE_EVENT = {
    "src_ip": "10.0.0.5", "dst_ip": "203.0.113.10",
    "dst_domain": "news.example.com", "dst_port": 443,
    "protocol": "tcp", "action": "allow", "bytes_out": 1234,
    "user_name": "jdelacruz",
}


def _post_json(client, token, payload):
    return client.post(
        "/api/ingest", json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )


def test_ingest_json_accepts_and_enriches(enrolled_firewall):
    client, firewall = enrolled_firewall
    resp = _post_json(client, firewall["ingest_token"], {"events": [SAMPLE_EVENT]})
    assert resp.status_code == 201
    assert resp.get_json() == {"accepted": 1, "dropped": 0}
    with client.application.app_context():
        events = db.list_events()
        assert len(events) == 1
        event = events[0]
        assert event["dst_domain"] == "news.example.com"
        # Demo geo lookup: Manila -> Philippines
        assert event["src_country"] == "Internal"
        assert event["dst_country"] == "Philippines"
        assert event["dst_city"] == "Manila"
        assert event["dst_lat"] == 14.5995


def test_ingest_rejects_bad_token(enrolled_firewall):
    client, _firewall = enrolled_firewall
    resp = _post_json(client, "wrong-token", {"events": [SAMPLE_EVENT]})
    assert resp.status_code == 401


def test_ingest_rejects_missing_token(enrolled_firewall):
    client, _firewall = enrolled_firewall
    resp = client.post("/api/ingest", json={"events": [SAMPLE_EVENT]})
    assert resp.status_code == 401


def test_ingest_drops_invalid_ips(enrolled_firewall):
    client, firewall = enrolled_firewall
    bad = dict(SAMPLE_EVENT, src_ip="not-an-ip")
    resp = _post_json(client, firewall["ingest_token"], {"events": [bad, SAMPLE_EVENT]})
    assert resp.status_code == 201
    assert resp.get_json() == {"accepted": 1, "dropped": 1}


def test_ingest_syslog_fortigate(enrolled_firewall):
    client, firewall = enrolled_firewall
    line = ("date=2026-11-20 time=10:00:00 devname=FG1 srcip=10.0.0.5 "
            "dstip=203.0.113.11 dstport=443 proto=tcp action=allow "
            "dsthost=shop.example.net")
    resp = client.post(
        "/api/ingest", data=line, content_type="text/plain",
        headers={"Authorization": f"Bearer {firewall['ingest_token']}"},
    )
    assert resp.status_code == 201
    assert resp.get_json()["accepted"] == 1
    with client.application.app_context():
        event = db.list_events()[0]
        assert event["dst_domain"] == "shop.example.net"
        assert event["dst_port"] == 443


def test_ingest_syslog_paloalto(enrolled_firewall):
    client, firewall = enrolled_firewall
    line = "SRC=10.0.0.6 DST=198.51.100.20 DPORT=443 PROTO=tcp ACTION=deny HOST=cdn.example.de"
    resp = client.post(
        "/api/ingest", data=line, content_type="text/plain",
        headers={"Authorization": f"Bearer {firewall['ingest_token']}"},
    )
    assert resp.status_code == 201
    with client.application.app_context():
        event = db.list_events()[0]
        assert event["action"] == "deny"
        assert event["threat"] in {"medium", "high", "critical"}


def test_disabled_firewall_cannot_ingest(enrolled_firewall):
    from tests.conftest import fetch_csrf
    client, firewall = enrolled_firewall
    client.post(f"/admin/firewalls/{firewall['id']}/toggle",
                data={"csrf_token": fetch_csrf(client)})
    resp = _post_json(client, firewall["ingest_token"], {"events": [SAMPLE_EVENT]})
    assert resp.status_code == 403


def test_token_rotation_invalidates_old_token(enrolled_firewall):
    import re
    from tests.conftest import fetch_csrf
    client, firewall = enrolled_firewall
    old_token = firewall["ingest_token"]
    rot = client.post(f"/admin/firewalls/{firewall['id']}/rotate-token",
                      data={"csrf_token": fetch_csrf(client)})
    assert rot.status_code == 302
    detail = client.get(rot.headers["Location"])
    match = re.search(r'<code class="token">([^<]+)</code>', detail.get_data(as_text=True))
    assert match
    new_token = match.group(1)
    assert new_token != old_token
    resp = _post_json(client, old_token, {"events": [SAMPLE_EVENT]})
    assert resp.status_code == 401
    resp = _post_json(client, new_token, {"events": [SAMPLE_EVENT]})
    assert resp.status_code == 201
