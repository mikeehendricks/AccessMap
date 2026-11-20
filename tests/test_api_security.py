"""API + security tests: headers, XSS, SQL injection, token secrecy."""

from accessmap import db


def test_health_endpoint(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_events_and_stats_endpoints(enrolled_firewall):
    client, firewall = enrolled_firewall
    client.post("/api/ingest", json={"events": [{
        "src_ip": "10.0.0.5", "dst_ip": "203.0.113.10",
        "dst_domain": "news.example.com", "dst_port": 443,
        "action": "allow", "bytes_out": 10,
    }]}, headers={"Authorization": f"Bearer {firewall['ingest_token']}"})
    resp = client.get("/api/events")
    assert resp.status_code == 200
    events = resp.get_json()
    assert len(events) == 1 and events[0]["dst_domain"] == "news.example.com"
    resp = client.get("/api/stats")
    assert resp.get_json()["total_events"] == 1
    resp = client.get("/api/firewalls")
    assert resp.get_json()[0]["name"] == "FG-Test-01"


def test_firewall_api_never_exposes_tokens(enrolled_firewall):
    client, firewall = enrolled_firewall
    resp = client.get("/api/firewalls")
    assert firewall["ingest_token"] not in resp.get_data(as_text=True)


def test_security_headers_present(client):
    resp = client.get("/")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert "Content-Security-Policy" in resp.headers
    # strict-origin-when-cross-origin preserves origin Referer required by
    # OpenStreetMap's Tile Usage Policy without leaking paths/queries.
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_xss_payload_is_escaped(admin_client):
    from tests.conftest import fetch_csrf
    payload = "<script>alert('xss')</script>"
    resp = admin_client.post("/admin/firewalls/new", data={
        "csrf_token": fetch_csrf(admin_client), "name": payload,
        "vendor": "fortinet", "host": "", "site": "",
    })
    assert resp.status_code == 302
    resp = admin_client.get("/admin/")
    body = resp.get_data(as_text=True)
    assert "<script>alert('xss')</script>" not in body
    assert "&lt;script&gt;" in body


def test_sql_injection_attempt_is_harmless(client, csrf_token):
    resp = client.post("/login", data={
        "csrf_token": csrf_token,
        "username": "admin' OR '1'='1", "password": "whatever",
    })
    assert resp.status_code == 200  # treated as a literal username
    with client.application.app_context():
        assert db.count_admins() == 0


def test_geo_api_validates_input(client):
    resp = client.get("/api/geo")
    assert resp.status_code == 400
    resp = client.get("/api/geo?ip=203.0.113.10")
    assert resp.status_code == 200
    assert resp.get_json()["city"] == "Manila"


def test_404_page(client):
    resp = client.get("/no-such-page")
    assert resp.status_code == 404
