"""Auth tests: one-time registration, login, lockout, password rules."""

import pytest

from accessmap import auth, db


def test_first_registration_succeeds(client, csrf_token):
    resp = client.post("/register", data={
        "csrf_token": csrf_token, "username": "admin",
        "email": "admin@example.com", "password": "Admin12345",
        "confirm": "Admin12345",
    })
    assert resp.status_code == 302
    with client.application.app_context():
        assert db.count_admins() == 1


def test_second_registration_is_forbidden(client, csrf_token):
    client.post("/register", data={
        "csrf_token": csrf_token, "username": "admin",
        "email": "admin@example.com", "password": "Admin12345",
        "confirm": "Admin12345",
    })
    resp = client.get("/register")
    assert resp.status_code == 403
    resp = client.post("/register", data={
        "csrf_token": csrf_token, "username": "second",
        "email": "second@example.com", "password": "Second12345",
        "confirm": "Second12345",
    })
    assert resp.status_code == 403
    with client.application.app_context():
        assert db.count_admins() == 1


def test_weak_password_rejected(client, csrf_token):
    resp = client.post("/register", data={
        "csrf_token": csrf_token, "username": "admin",
        "email": "admin@example.com", "password": "short", "confirm": "short",
    })
    assert resp.status_code == 200  # form re-rendered with error
    with client.application.app_context():
        assert db.count_admins() == 0


def test_login_logout_flow(client, csrf_token):
    client.post("/register", data={
        "csrf_token": csrf_token, "username": "admin",
        "email": "admin@example.com", "password": "Admin12345",
        "confirm": "Admin12345",
    })
    resp = client.post("/login", data={
        "csrf_token": csrf_token, "username": "admin", "password": "wrong-pass",
    })
    assert resp.status_code == 200  # invalid credentials
    resp = client.post("/login", data={
        "csrf_token": csrf_token, "username": "admin", "password": "Admin12345",
    })
    assert resp.status_code == 302
    resp = client.get("/admin/")
    assert resp.status_code == 200
    from tests.conftest import fetch_csrf
    resp = client.post("/logout", data={"csrf_token": fetch_csrf(client)})
    assert resp.status_code == 302
    resp = client.get("/admin/")
    assert resp.status_code == 302  # redirected to login


def test_admin_panel_requires_login(client):
    resp = client.get("/admin/")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_admin_can_add_second_admin(admin_client):
    from tests.conftest import fetch_csrf
    resp = admin_client.post("/admin/admins/new", data={
        "csrf_token": fetch_csrf(admin_client), "username": "operator",
        "email": "op@example.com", "password": "Operator123",
        "confirm": "Operator123",
    })
    assert resp.status_code == 302
    with admin_client.application.app_context():
        assert db.count_admins() == 2


def test_password_hashing_roundtrip(app):
    with app.app_context():
        stored = auth.hash_password("CorrectHorse1")
        assert stored != "CorrectHorse1"
        assert auth.verify_password("CorrectHorse1", stored)
        assert not auth.verify_password("WrongHorse1", stored)
        assert not auth.verify_password("x", "not-a-real-hash")


def test_login_lockout_after_repeated_failures(client, csrf_token):
    client.post("/register", data={
        "csrf_token": csrf_token, "username": "admin",
        "email": "admin@example.com", "password": "Admin12345",
        "confirm": "Admin12345",
    })
    for _ in range(5):
        client.post("/login", data={
            "csrf_token": csrf_token, "username": "admin", "password": "bad",
        })
    resp = client.post("/login", data={
        "csrf_token": csrf_token, "username": "admin", "password": "Admin12345",
    })
    assert b"Too many failed attempts" in resp.data


def test_missing_csrf_rejected(client):
    resp = client.post("/login", data={"username": "x", "password": "y"})
    assert resp.status_code == 400
