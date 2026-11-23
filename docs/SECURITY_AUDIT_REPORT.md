# AccessMap — Executive Security Vulnerability Assessment Report

| Field | Value |
|---|---|
| **Application** | AccessMap — Firewall Live Threat Map (`mikeehendricks/AccessMap`) |
| **Assessment Date** | 2026-11-20 |
| **Methodology** | Manual White-Box Code Audit + OWASP Top 10 (2021) + Automated Regression Verification |
| **Scope** | Flask Backend (`app.py`, `accessmap/*`), Templates & Frontend JS, SQLite DAL, Ingestion API, Ubuntu Installer (`install.sh`), `systemd` & `nginx` Configs |
| **Remediation Status** | **All 8 Findings Remediated & Verified (`43 / 43` Automated Tests Passing)** |

---

## 1. Executive Summary

A comprehensive security vulnerability assessment was conducted across the AccessMap application, firewall log-ingestion pipeline, admin control plane, and Ubuntu deployment tooling.

### Key Strengths Confirmed Prior to Remediation
- **SQL Injection Immunity:** 100% parameterized SQLite queries across `accessmap/db.py`.
- **Cross-Site Scripting (XSS) Controls:** Jinja2 auto-escaping on server-rendered views and strict `textContent`-based DOM escaping in `accessmap/static/js/map.js`.
- **Password Cryptography & CSRF:** PBKDF2-HMAC-SHA256 (`260,000` rounds, random 128-bit per-user salts) and per-session CSRF tokens verified with `hmac.compare_digest`.
- **One-Time Admin Bootstrap:** Public `/register` permanently locks with `HTTP 403` once the initial super-admin exists.

### Vulnerabilities Identified & Fixed
The deep-dive review uncovered **8 actionable security findings** (**3 High**, **4 Medium**, **1 Low**) spanning credential storage, unauthenticated telemetry exposure, production secret enforcement, resource-exhaustion resistance, session lifecycle management, and Linux service hardening. **All 8 findings have been remediated in this release and locked down with automated regression tests in `tests/test_security_audit.py`.**

| ID | Severity | OWASP Category | Vulnerability Summary | Status |
|---|---|---|---|---|
| **SEC-01** | **High** | A02:2021 Cryptographic Failures | Firewall ingest tokens stored in cleartext, re-displayed on every admin page view, and accepted in URL query parameters | ✅ **Fixed** |
| **SEC-02** | **High** | A01:2021 Broken Access Control | Unauthenticated `/api/events` and `/api/firewalls` leaked internal RFC1918 host IPs, usernames, and appliance FQDNs | ✅ **Fixed** |
| **SEC-03** | **High** | A05:2021 Security Misconfiguration | Predictable static `SECRET_KEY` fallback (`"dev-only-change-me"`) enabled session forgery if env was unset | ✅ **Fixed** |
| **SEC-04** | **Medium** | A04:2021 Insecure Design | Unauthenticated `/api/geo` lacked IP validation, rate limiting, redirect blocking, and `geo_cache` bounds | ✅ **Fixed** |
| **SEC-05** | **Medium** | A07:2021 Identification & Auth Failures | Global per-username lockout DoS, PBKDF2 timing username oracle, and surviving sessions after password change | ✅ **Fixed** |
| **SEC-06** | **Medium** | A04:2021 Insecure Design | `MAX_INGEST_BATCH` enforced *after* normalizing & geo-resolving entire payload (CPU/network DoS) | ✅ **Fixed** |
| **SEC-07** | **Medium** | A05:2021 Security Misconfiguration | Dev WSGI server in `systemd`, hardcoded `/opt/accessmap` path, exposed backend port in `ufw`, `Host` header CLI injection, duplicate-email `500`, inline `onsubmit` blocked by CSP | ✅ **Fixed** |
| **SEC-08** | **Low** | A01:2021 Broken Access Control | Non-super admins permitted to create new admins; missing `Cache-Control: no-store` & `Permissions-Policy` headers | ✅ **Fixed** |

---

## 2. Detailed Technical Findings & Remediations

### SEC-01 (High) — Plaintext Storage, Repeated UI Exposure, and URL Query Acceptance of Ingest Tokens
- **Risk Description:**
  1. `firewalls` previously stored raw bearer tokens in SQLite (`ingest_token`), exposing all firewall credentials if a database file or backup was read.
  2. `/admin/firewalls/<id>` rendered the full plaintext token on every visit despite labelling it *"shown once"*.
  3. `/api/ingest` accepted `?token=<secret>` in the URL query string, exposing bearer secrets in reverse-proxy logs and browser histories.
- **Remediation Applied:**
  - Replaced plaintext storage with `token_hash` (`SHA-256` hex digest) + an 8-character non-secret `token_prefix` in `accessmap/db.py` (including automatic in-place migration for legacy databases).
  - Updated `accessmap/routes/admin_routes.py` and `firewall_detail.html` to reveal the raw token **strictly once** via a popped session flash after enrollment or rotation; subsequent views show only `prefix••••••••`.
  - Removed URL query-string token fallback in `accessmap/routes/ingest_routes.py`; tokens are accepted exclusively via `Authorization: Bearer <token>`.
- **Verification:** `tests/test_security_audit.py::test_sec01_token_hashed_at_rest_shown_once_and_query_param_rejected`

---

### SEC-02 (High) — Public API Exposure of Internal Network Topology & Usernames
- **Risk Description:** Unauthenticated visitors polling `/api/events` and `/api/firewalls` received raw internal workstation IPs (`10.0.0.5`, `172.16.0.5`, `192.168.1.10`), Active Directory/firewall `user_name` values, and internal firewall `host` FQDNs.
- **Remediation Applied:**
  - Added `geo.redact_ip_for_public()` (`accessmap/geo.py`) and role-aware serialization in `accessmap/routes/api_routes.py`.
  - Unauthenticated responses mask RFC1918/loopback/link-local/CGNAT/ULA addresses (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`), clear `user_name`, and omit firewall `host`, while preserving geographic coordinates and threat arcs. Authenticated admins continue to see full forensic details.
- **Verification:** `tests/test_security_audit.py::test_sec02_public_apis_redact_private_ips_usernames_and_hosts`

---

### SEC-03 (High) — Hardcoded Default `SECRET_KEY` Fallback
- **Risk Description:** `Config.SECRET_KEY` previously defaulted to `"dev-only-change-me"`, and `.env` was only loaded when invoked via `systemd` `EnvironmentFile`. Starting the app manually without exporting `SECRET_KEY` allowed attackers to sign arbitrary Flask session cookies (`{"admin_id": 1}`).
- **Remediation Applied:**
  - Added stdlib `.env` auto-loading in `accessmap/config.py`.
  - Replaced the static fallback with a per-process cryptographic `secrets.token_hex(32)` key in local dev, and enforced `REQUIRE_SECRET_KEY=1` in production (`app.py` raises `RuntimeError` at startup if `SECRET_KEY` is unset, `< 16` chars, or a placeholder).
- **Verification:** `tests/test_security_audit.py::test_sec03_production_rejects_weak_or_missing_secret_key`

---

### SEC-04 (Medium) — Unauthenticated `/api/geo` Amplification & Unbounded Cache Growth
- **Risk Description:** `/api/geo` accepted arbitrary unvalidated strings, performed outbound HTTP lookups without per-client rate limits or redirect restrictions, and grew `geo_cache` without an upper bound.
- **Remediation Applied:**
  - Validated `ip` strictly with `ipaddress.ip_address()` (`HTTP 400` on invalid input) and enforced per-IP sliding-window rate limiting (`GEO_RATE_LIMIT_PER_MIN`, `HTTP 429`) in `accessmap/routes/api_routes.py`.
  - Hardened `_online_lookup()` (`http/https` scheme check, `allow_redirects=False`, field length caps) and bounded `geo_cache` at `MAX_GEO_CACHE_ENTRIES` (`10,000`) with oldest-entry eviction in `accessmap/db.py`.
- **Verification:** `tests/test_security_audit.py::test_sec04_geo_api_validates_ip_and_rate_limits`

---

### SEC-05 (Medium) — Global Username Lockout DoS, Timing Enumeration, & Stale Sessions After Password Change
- **Risk Description:**
  1. Keying login lockout solely by `username` allowed any remote attacker to permanently lock out `admin` by sending 5 bad attempts every 5 minutes.
  2. Non-existent usernames skipped PBKDF2 hashing, creating a ~100 ms timing oracle for username enumeration.
  3. Changing an admin password left previously issued session cookies valid until their 8-hour expiry, and `g.admin` caching did not key on session identity.
- **Remediation Applied:**
  - Scoped login throttling by `(client_ip, username)` plus a global per-IP cap (`LOGIN_IP_MAX_ATTEMPTS`) with bounded 4,096-entry eviction (`accessmap/auth.py`).
  - Added `auth.dummy_verify_password()` on unknown usernames in `auth_routes.py` to equalize PBKDF2 CPU time.
  - Bound sessions to a SHA-256 fingerprint of `password_hash` (`session["pwd_ver"]`), immediately revoking any other active sessions whenever a password is changed.
- **Verification:** `tests/test_security_audit.py::test_sec05_ip_scoped_lockout_and_session_revocation_on_password_change`

---

### SEC-06 (Medium) — Post-Normalization `MAX_INGEST_BATCH` Check (Ingestion DoS)
- **Risk Description:** `/api/ingest` previously normalized and geo-resolved *all* items in a payload before checking `len(events) > MAX_INGEST_BATCH`, allowing a single oversized request to trigger thousands of synchronous geo lookups before returning `413`.
- **Remediation Applied:** Enforced `MAX_INGEST_BATCH` on raw JSON array length and non-empty syslog line count *prior* to normalization or geo resolution in `accessmap/routes/ingest_routes.py`.
- **Verification:** `tests/test_security_audit.py::test_sec06_oversized_ingest_batch_rejected_before_geo_lookup`

---

### SEC-07 (Medium) — Production WSGI, Installer Pathing, Firewall Port Exposure, Host Header & CSP Fixes
- **Risk Description:** `deploy/accessmap.service` ran Flask's development server with a hardcoded `/opt/accessmap` path; `install.sh` opened raw port `5000/tcp` in `ufw` even behind `nginx`; crafted `Host` headers flowed into CLI snippets on `/admin/firewalls/<id>`; duplicate admin emails caused unhandled `500 IntegrityError`s; and inline `onsubmit="return confirm(...)"` was blocked by `script-src 'self'` CSP. Also `seed.py` passed `created_by=0` when run before admin creation, violating `FOREIGN KEY` constraints.
- **Remediation Applied:**
  - Added `gunicorn` to `requirements.txt` and `deploy/accessmap.service` (`--workers 2 --threads 4`), added SQLite `busy_timeout=5000`, dynamically substituted `$APP_DIR` in `install.sh`, set `chmod 700` on `data/`, bound Gunicorn to `127.0.0.1` when `nginx` is enabled, and restricted `ufw` to `80/443`.
  - Added `_safe_ingest_url()` (`PUBLIC_BASE_URL` + strict `_SAFE_HOST_RE`), graceful duplicate-email validation (`db.get_admin_by_email`), external CSP-compliant `accessmap/static/js/admin.js` confirmation handler, and `created_by=None` in `seed.py`.
- **Verification:** `tests/test_security_audit.py::test_sec07_duplicate_email_host_sanitization_and_csp_confirm`

---

### SEC-08 (Low) — Super-Admin RBAC & Sensitive Page Cache/Permissions Headers
- **Risk Description:** Secondary admins (`is_super=0`) could create additional admin accounts at `/admin/admins/new`, and `/admin/*` responses lacked `Cache-Control: no-store` and `Permissions-Policy`.
- **Remediation Applied:** Enforced `@auth.super_required` (`HTTP 403` for non-super admins) on `/admin/admins/new`, hid the button for non-super operators in `dashboard.html`, added `Cache-Control: no-store` on `/admin/*`, `/login`, and `/register`, and added `Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()` across all responses.
- **Verification:** `tests/test_security_audit.py::test_sec08_non_super_admin_rbac_and_no_store_headers`

---

## 3. Residual Risk & Operational Recommendations

1. **Enable TLS in Production (`COOKIE_SECURE=1`):** Run `sudo certbot --nginx -d <domain>` after `install.sh` and set `COOKIE_SECURE=1` + `PUBLIC_BASE_URL=https://<domain>` in `.env` so session cookies and firewall bearer tokens traverse HTTPS exclusively.
2. **Multi-Node Scaling:** In-memory login throttling and `/api/geo` rate buckets apply per Gunicorn worker; high-traffic multi-server deployments should place rate limiting at the `nginx` / WAF edge (`limit_req_zone`).
3. **Geo-IP Privacy:** When `GEO_LOOKUP_ENABLED=1`, uncached public destination IPs are queried against `ip-api.com`; air-gapped or strict-privacy SOC environments can set `GEO_LOOKUP_ENABLED=0` to keep 100% of traffic local.
