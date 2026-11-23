"""Regression tests for the Executive Security Vulnerability Assessment (SEC-01..SEC-08)."""

from __future__ import annotations

import pytest

from app import create_app
from accessmap import auth, db, geo
from tests.conftest import TestConfig, fetch_csrf


def test_sec01_token_hashed_at_rest_shown_once_and_query_param_rejected(enrolled_firewall):
    """SEC-01: Raw token is never stored in DB, never shown twice, and rejected in URL query."""
    client, firewall = enrolled_firewall
    raw_token = firewall["ingest_token"]

    # 1. Raw token is NOT stored anywhere in SQLite; only SHA-256 hash + 8-char prefix exist.
    with client.application.app_context():
        raw_row = db.get_db().execute(
            "SELECT token_hash, token_prefix FROM firewalls WHERE id = ?", (firewall["id"],)
        ).fetchone()
        assert raw_row["token_hash"] == auth.hash_token(raw_token)
        assert raw_row["token_hash"] != raw_token
        assert raw_row["token_prefix"] == raw_token[:8]

    # 2. Second visit to /admin/firewalls/<id> must NOT re-display the raw token.
    second_view = client.get(f"/admin/firewalls/{firewall['id']}").get_data(as_text=True)
    assert raw_token not in second_view
    assert f"{raw_token[:8]}••••" in second_view

    # 3. Query-string ?token=... must be rejected with 401.
    q_resp = client.post(
        f"/api/ingest?token={raw_token}",
        json={"events": [{"src_ip": "10.0.0.5", "dst_ip": "203.0.113.10"}]},
    )
    assert q_resp.status_code == 401


def test_sec02_public_apis_redact_private_ips_usernames_and_hosts(app, enrolled_firewall):
    """SEC-02: Unauthenticated /api/events and /api/firewalls redact internal LAN details."""
    admin_client, firewall = enrolled_firewall
    admin_client.post(
        "/api/ingest",
        json={"events": [{
            "src_ip": "10.0.0.5",
            "dst_ip": "203.0.113.10",
            "dst_domain": "news.example.com",
            "dst_port": 443,
            "action": "allow",
            "user_name": "jdelacruz",
        }]},
        headers={"Authorization": f"Bearer {firewall['ingest_token']}"},
    )

    # Signed-in admin sees full src_ip, user_name, and firewall host.
    admin_events = admin_client.get("/api/events").get_json()
    assert admin_events[0]["src_ip"] == "10.0.0.5"
    assert admin_events[0]["user_name"] == "jdelacruz"
    admin_fws = admin_client.get("/api/firewalls").get_json()
    assert admin_fws[0]["host"] == "fg-test.example.local"

    # Unauthenticated viewer sees masked internal IP, empty user_name, and no appliance host.
    anon = app.test_client()
    pub_events = anon.get("/api/events").get_json()
    assert pub_events[0]["src_ip"] == "10.x.x.x"
    assert pub_events[0]["dst_ip"] == "203.0.113.10"
    assert pub_events[0]["user_name"] == ""
    pub_fws = anon.get("/api/firewalls").get_json()
    assert "host" not in pub_fws[0]


def test_sec03_production_rejects_weak_or_missing_secret_key(tmp_path):
    """SEC-03: REQUIRE_SECRET_KEY=True refuses startup with weak/default SECRET_KEY."""
    class WeakProdConfig(TestConfig):
        DATABASE_URL = str(tmp_path / "prod.db")
        REQUIRE_SECRET_KEY = True
        SECRET_KEY = "dev-only-change-me"

    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(WeakProdConfig)


def test_sec04_geo_api_validates_ip_and_rate_limits(app, client):
    """SEC-04: /api/geo rejects non-IP input (400) and enforces per-IP rate limiting (429)."""
    bad = client.get("/api/geo?ip=not-a-valid-ip")
    assert bad.status_code == 400

    app.config["GEO_RATE_LIMIT_PER_MIN"] = 3
    for _ in range(3):
        assert client.get("/api/geo?ip=203.0.113.10").status_code == 200
    limited = client.get("/api/geo?ip=203.0.113.10")
    assert limited.status_code == 429


def test_sec05_ip_scoped_lockout_and_session_revocation_on_password_change(app):
    """SEC-05: Attacker IP lockout does not block admin IP; password change revokes other sessions."""
    import re

    c1 = app.test_client()
    r = c1.get("/register")
    csrf1 = re.search(r'name="csrf_token" value="([^"]+)"', r.get_data(as_text=True)).group(1)
    c1.post("/register", data={
        "csrf_token": csrf1, "username": "admin", "email": "admin@example.com",
        "password": "Admin12345", "confirm": "Admin12345",
    })

    # Attacker from 198.51.100.99 triggers lockout for (198.51.100.99, 'admin')
    attacker = app.test_client()
    ra = attacker.get("/login", environ_base={"REMOTE_ADDR": "198.51.100.99"})
    csrfa = re.search(r'name="csrf_token" value="([^"]+)"', ra.get_data(as_text=True)).group(1)
    for _ in range(5):
        attacker.post(
            "/login",
            data={"csrf_token": csrfa, "username": "admin", "password": "wrong"},
            environ_base={"REMOTE_ADDR": "198.51.100.99"},
        )
    blocked = attacker.post(
        "/login",
        data={"csrf_token": csrfa, "username": "admin", "password": "Admin12345"},
        environ_base={"REMOTE_ADDR": "198.51.100.99"},
    )
    assert b"Too many failed attempts" in blocked.data

    # Legitimate admin from 10.0.0.25 can still sign in!
    legit_a = app.test_client()
    rl = legit_a.get("/login", environ_base={"REMOTE_ADDR": "10.0.0.25"})
    csrfl = re.search(r'name="csrf_token" value="([^"]+)"', rl.get_data(as_text=True)).group(1)
    ok = legit_a.post(
        "/login",
        data={"csrf_token": csrfl, "username": "admin", "password": "Admin12345"},
        environ_base={"REMOTE_ADDR": "10.0.0.25"},
    )
    assert ok.status_code == 302

    # Second concurrent session B (e.g. stolen cookie / another browser)
    legit_b = app.test_client()
    rl2 = legit_b.get("/login", environ_base={"REMOTE_ADDR": "10.0.0.26"})
    csrfl2 = re.search(r'name="csrf_token" value="([^"]+)"', rl2.get_data(as_text=True)).group(1)
    assert legit_b.post(
        "/login",
        data={"csrf_token": csrfl2, "username": "admin", "password": "Admin12345"},
        environ_base={"REMOTE_ADDR": "10.0.0.26"},
    ).status_code == 302
    assert legit_b.get("/admin/").status_code == 200

    # Session A changes password -> Session A remains logged in, Session B is immediately revoked!
    pw_csrf = fetch_csrf(legit_a)
    pw_resp = legit_a.post("/admin/password", data={
        "csrf_token": pw_csrf,
        "old_password": "Admin12345",
        "new_password": "NewAdminPass99",
        "confirm": "NewAdminPass99",
    })
    assert pw_resp.status_code == 302
    assert legit_a.get("/admin/").status_code == 200
    revoked = legit_b.get("/admin/")
    assert revoked.status_code == 302
    assert "/login" in revoked.headers["Location"]


def test_sec06_oversized_ingest_batch_rejected_before_geo_lookup(app, enrolled_firewall, monkeypatch):
    """SEC-06: Oversized batches return 413 immediately without running geo.resolve."""
    client, firewall = enrolled_firewall
    app.config["MAX_INGEST_BATCH"] = 3
    calls = []
    orig_resolve = geo.resolve
    monkeypatch.setattr(geo, "resolve", lambda ip: (calls.append(ip), orig_resolve(ip))[1])

    oversized = [{"src_ip": "10.0.0.5", "dst_ip": "203.0.113.10"} for _ in range(5)]
    resp = client.post(
        "/api/ingest",
        json={"events": oversized},
        headers={"Authorization": f"Bearer {firewall['ingest_token']}"},
    )
    assert resp.status_code == 413
    assert calls == []


def test_sec07_duplicate_email_host_sanitization_and_csp_confirm(admin_client, enrolled_firewall):
    """SEC-07: Duplicate admin email handled cleanly; Host header sanitized; no inline onsubmit."""
    _client, firewall = enrolled_firewall
    # Duplicate email returns 200 with flash error, not 500 IntegrityError
    dup = admin_client.post("/admin/admins/new", data={
        "csrf_token": fetch_csrf(admin_client),
        "username": "second_admin",
        "email": "admin@example.com",  # already used by first admin
        "password": "SecondAdmin123",
        "confirm": "SecondAdmin123",
    })
    assert dup.status_code == 200
    assert b"email address is already registered" in dup.data

    # Crafted Host header is rejected/sanitized and no inline onsubmit handler exists
    detail = admin_client.get(
        f"/admin/firewalls/{firewall['id']}",
        headers={"Host": 'evil.example"; set bad "1'},
    ).get_data(as_text=True)
    assert "evil.example" not in detail
    assert "onsubmit=" not in detail
    assert 'data-confirm=' in detail


def test_sec08_non_super_admin_rbac_and_no_store_headers(app, admin_client):
    """SEC-08: Non-super admins get 403 on /admin/admins/new; admin/auth pages set no-store."""
    import re

    admin_resp = admin_client.get("/admin/")
    assert admin_resp.headers.get("Cache-Control") == "no-store"
    assert "Permissions-Policy" in admin_resp.headers

    # Create a regular (non-super) admin
    admin_client.post("/admin/admins/new", data={
        "csrf_token": fetch_csrf(admin_client),
        "username": "operator2",
        "email": "op2@example.com",
        "password": "Operator123",
        "confirm": "Operator123",
    })

    op_client = app.test_client()
    r = op_client.get("/login")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', r.get_data(as_text=True)).group(1)
    assert op_client.post("/login", data={
        "csrf_token": csrf, "username": "operator2", "password": "Operator123",
    }).status_code == 302

    assert op_client.get("/admin/admins/new").status_code == 403


def test_map_js_eliminates_raw_html_sinks_and_renders_dom_safely():
    """Verify map.js has zero raw HTML sinks (negative XSS test + positive rendering test)."""
    import pathlib
    import subprocess

    repo = pathlib.Path(__file__).resolve().parent.parent
    map_js_path = repo / "accessmap" / "static" / "js" / "map.js"
    source = map_js_path.read_text(encoding="utf-8")

    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert forbidden not in source, f"Raw HTML sink {forbidden!r} found in map.js"

    harness = r"""
const fs = require("fs");
const vm = require("vm");

class FakeNode {
  constructor(tag) {
    this.tagName = tag ? tag.toUpperCase() : "#TEXT";
    this.className = "";
    this.colSpan = 1;
    this.value = "";
    this._text = "";
    this.children = [];
    this.listeners = {};
    this.style = {};
  }
  set innerHTML(_v) { throw new Error("Forbidden innerHTML assignment!"); }
  set outerHTML(_v) { throw new Error("Forbidden outerHTML assignment!"); }
  set textContent(v) {
    this.children = [];
    this._text = v == null ? "" : String(v);
  }
  get textContent() {
    if (this.children.length === 0) return this._text;
    return this.children.map((c) => c.textContent).join("");
  }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...nodes) { this.children = [...nodes]; }
  addEventListener(ev, fn) { this.listeners[ev] = fn; }
}

class FakeOption extends FakeNode {
  constructor(label = "", value = "") {
    super("option");
    this.textContent = label;
    this.value = String(value);
  }
}

const elements = {
  "stat-events": new FakeNode("span"),
  "stat-threats": new FakeNode("span"),
  "stat-countries": new FakeNode("span"),
  "stat-firewalls": new FakeNode("span"),
  "filter-firewall": new FakeNode("select"),
  "filter-threat": new FakeNode("select"),
  "last-updated": new FakeNode("span"),
  "refresh-btn": new FakeNode("button"),
  "ip-search": new FakeNode("input"),
  "ip-search-btn": new FakeNode("button"),
  "#events-table tbody": new FakeNode("tbody"),
};

const boundPopups = [];
function makeLayer() {
  return {
    addTo() { return this; },
    clearLayers() {},
    bindPopup(content) { boundPopups.push(content); return this; },
    openPopup() { return this; },
  };
}

let eventsFixture = [];
let firewallsFixture = [];
let geoFixture = {};

function fakeFetch(url) {
  let data = {};
  if (url.startsWith("/static/vendor/world-countries.geojson")) {
    data = { type: "FeatureCollection", features: [] };
  } else if (url.startsWith("/api/firewalls")) {
    data = firewallsFixture;
  } else if (url.startsWith("/api/events")) {
    data = eventsFixture;
  } else if (url.startsWith("/api/stats")) {
    data = { total_events: eventsFixture.length, threat_events: 1, destination_countries: 2, firewalls: firewallsFixture.length };
  } else if (url.startsWith("/api/geo")) {
    data = geoFixture;
  }
  return Promise.resolve({ json: () => Promise.resolve(data) });
}

const context = {
  Option: FakeOption,
  URLSearchParams,
  Date,
  Math,
  Number,
  String,
  Object,
  Promise,
  encodeURIComponent,
  setInterval() {},
  fetch: fakeFetch,
  document: {
    createElement: (tag) => new FakeNode(tag),
    createTextNode: (txt) => { const n = new FakeNode(null); n._text = txt == null ? "" : String(txt); return n; },
    getElementById: (id) => elements[id],
    querySelector: (sel) => elements[sel],
  },
  L: {
    map: () => ({
      setView() { return this; },
      createPane() {},
      getPane: () => ({ style: {} }),
    }),
    layerGroup: () => makeLayer(),
    polyline: () => makeLayer(),
    circleMarker: () => makeLayer(),
    tileLayer: () => makeLayer(),
    geoJSON: () => makeLayer(),
    control: { layers: () => ({ addTo() {} }) },
  },
};

const code = fs.readFileSync(process.argv[1], "utf8");
vm.runInNewContext(code, context);

(async () => {
  await new Promise((r) => setTimeout(r, 20));
  // 1. Positive check: empty state row
  const tbody = elements["#events-table tbody"];
  if (tbody.children.length !== 1 || tbody.children[0].children[0].colSpan !== 7) {
    throw new Error("Empty table row failed");
  }

  // 2. Negative check: hostile XSS & attribute-breakout payloads across all fields
  firewallsFixture = [{
    id: "1' onmouseover='alert(1)",
    name: "<script>alert('fw')</script>",
    vendor: "<img src=x onerror=alert(1)>",
  }];
  eventsFixture = [
    {
      ts: "<svg onload=alert(1)>",
      src_ip: "10.x.x.x",
      src_city: "<img src=x onerror=alert(2)>",
      src_country: "Internal",
      src_lat: 14.5995,
      src_lon: 120.9842,
      dst_ip: "203.0.113.11",
      dst_city: "javascript:alert(3)",
      dst_country: "United States",
      dst_lat: 40.7128,
      dst_lon: -74.006,
      dst_domain: "<script>alert('dom')</script>",
      dst_port: 443,
      action: "' onclick='alert(4)",
      threat: "low' onmouseover='alert(5)' style='background:red",
      threat_score: 55,
    },
    {
      ts: "2026-11-20 12:00:00",
      src_ip: "10.x.x.x",
      src_city: "LAN",
      src_country: "Internal",
      src_lat: 14.5995,
      src_lon: 120.9842,
      dst_ip: "198.51.100.20",
      dst_city: "Frankfurt",
      dst_country: "Germany",
      dst_lat: 50.1109,
      dst_lon: 8.6821,
      dst_domain: "cdn.example.de",
      dst_port: 443,
      action: "deny",
      threat: "high",
      threat_score: 60,
    },
  ];
  geoFixture = {
    ip: "203.0.113.11",
    city: "<svg onload=alert(6)>",
    country: "US",
    lat: 40.7,
    lon: -74.0,
    isp: "<script>alert(7)</script>",
    source: "online",
  };

  elements["refresh-btn"].listeners.click();
  elements["ip-search"].value = "203.0.113.11";
  elements["ip-search-btn"].listeners.click();
  await new Promise((r) => setTimeout(r, 30));

  if (tbody.children.length !== 2) throw new Error("Expected 2 rendered rows");

  // Malicious threat string must normalize strictly to badge-unknown
  const badBadge = tbody.children[0].children[6].children[0];
  if (badBadge.className !== "badge badge-unknown" || badBadge.textContent !== "unknown") {
    throw new Error("Unexpected badge class/text: " + badBadge.className + " / " + badBadge.textContent);
  }
  // Valid threat string preserved
  const goodBadge = tbody.children[1].children[6].children[0];
  if (goodBadge.className !== "badge badge-high" || goodBadge.textContent !== "high") {
    throw new Error("Valid badge broken: " + goodBadge.className);
  }
  // Malicious domain preserved strictly as literal text node (no child elements)
  const domCell = tbody.children[0].children[3];
  if (domCell.children.length !== 0 || domCell.textContent !== "<script>alert('dom')</script>") {
    throw new Error("Domain cell was parsed as HTML instead of textContent");
  }
  // Every Leaflet popup binding must produce a FakeNode, never a raw HTML string
  if (boundPopups.length < 4) throw new Error("Expected bound popups");
  for (const p of boundPopups) {
    const resolved = typeof p === "function" ? p() : p;
    if (!(resolved instanceof FakeNode)) {
      throw new Error("Popup passed raw string instead of DOM node!");
    }
  }
  // Firewall select options built via Option constructor
  const sel = elements["filter-firewall"];
  if (sel.children.length !== 2 || !sel.children[1].textContent.includes("<script>alert('fw')</script>")) {
    throw new Error("Firewall select option rendering failed");
  }
  console.log("DOM_SAFE_OK");
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
"""
    proc = subprocess.run(
        ["node", "-e", harness, str(map_js_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"Node harness failed:\n{proc.stdout}\n{proc.stderr}"
    assert "DOM_SAFE_OK" in proc.stdout

