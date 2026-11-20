"""Usability smoke tests: every page renders with its key controls.

These encode the manual usability checklist in docs/TESTING.md as
automated assertions so regressions are caught in CI.
"""

PAGES = [
    ("/", ["Live threat map", "filter-firewall", "filter-threat", "ip-search"]),
    ("/login", ["Sign in", "username", "password"]),
    ("/register", ["Create the first admin", "Confirm password"]),
]


def test_public_pages_render(client):
    for path, markers in PAGES:
        resp = client.get(path)
        assert resp.status_code == 200, path
        body = resp.get_data(as_text=True)
        for marker in markers:
            assert marker in body, f"{marker!r} missing on {path}"


def test_admin_pages_render(admin_client):
    for path, markers in [
        ("/admin/", ["Admin panel", "Enrolled firewalls", "Admins"]),
        ("/admin/firewalls/new", ["Enroll firewall", "Vendor"]),
        ("/admin/admins/new", ["Add another admin"]),
        ("/admin/password", ["Change my password"]),
    ]:
        resp = admin_client.get(path)
        assert resp.status_code == 200, path
        body = resp.get_data(as_text=True)
        for marker in markers:
            assert marker in body, f"{marker!r} missing on {path}"


def test_map_page_has_accessible_labels(client):
    body = client.get("/").get_data(as_text=True)
    assert 'aria-label="World threat map"' in body
    assert 'aria-label="Threat legend"' in body
    assert "<label>" in body


def test_forms_have_csrf_and_submit(admin_client):
    body = admin_client.get("/admin/firewalls/new").get_data(as_text=True)
    assert 'name="csrf_token"' in body
    assert 'type="submit"' in body
