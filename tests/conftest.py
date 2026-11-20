"""Shared pytest fixtures: isolated app + test client per test."""

from __future__ import annotations

import pytest

from app import create_app
from accessmap import db


class TestConfig:
    """Test configuration: temp DB, fast hashing, no network geo."""

    SECRET_KEY = "test-secret-key"
    DATABASE_URL = ":memory:"  # replaced per-test below
    HOST = "127.0.0.1"
    PORT = 5000
    DEBUG = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False
    PERMANENT_SESSION_LIFETIME = 3600
    GEO_LOOKUP_ENABLED = False
    GEO_LOOKUP_TIMEOUT = 0.1
    GEO_LOOKUP_URL = "http://127.0.0.1:9/{ip}"
    MAX_INGEST_BATCH = 500
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    PBKDF2_ITERATIONS = 1000  # fast for tests
    LOGIN_MAX_ATTEMPTS = 5
    LOGIN_LOCKOUT_SECONDS = 300


@pytest.fixture(autouse=True)
def _reset_throttle():
    """Clear the in-memory login throttle between tests."""
    from accessmap import auth

    auth._THROTTLE.clear()
    yield
    auth._THROTTLE.clear()


@pytest.fixture()
def app(tmp_path):
    """Create an app bound to a throwaway SQLite file."""
    TestConfig.DATABASE_URL = str(tmp_path / "test.db")
    application = create_app(TestConfig)
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    """Flask test client with an app context pushed."""
    with app.test_client() as test_client:
        with app.app_context():
            yield test_client


@pytest.fixture()
def csrf_token(client):
    """Fetch a valid CSRF token from the login page."""
    resp = client.get("/login")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    import re

    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "CSRF token not found on login page"
    return match.group(1)


@pytest.fixture()
def admin_client(client, csrf_token):
    """A client with the first admin registered and signed in."""
    resp = client.post("/register", data={
        "csrf_token": csrf_token,
        "username": "admin",
        "email": "admin@example.com",
        "password": "Admin12345",
        "confirm": "Admin12345",
    })
    assert resp.status_code == 302, resp.get_data(as_text=True)
    resp = client.post("/login", data={
        "csrf_token": csrf_token, "username": "admin", "password": "Admin12345",
    })
    assert resp.status_code == 302
    return client


def fetch_csrf(client) -> str:
    """Fetch the *current* session CSRF token (it rotates on login)."""
    import re

    resp = client.get("/admin/")
    match = re.search(r'name="csrf_token" value="([^"]+)"', resp.get_data(as_text=True))
    assert match, "CSRF token not found"
    return match.group(1)


@pytest.fixture()
def enrolled_firewall(admin_client):
    """Enroll one Fortinet firewall; return (client, firewall_row)."""
    resp = admin_client.post("/admin/firewalls/new", data={
        "csrf_token": fetch_csrf(admin_client),
        "name": "FG-Test-01",
        "vendor": "fortinet",
        "host": "fg-test.example.local",
        "site": "Test Lab",
    })
    assert resp.status_code == 302
    with admin_client.application.app_context():
        row = db.list_firewalls()[0]
    return admin_client, row
