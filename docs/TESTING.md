# AccessMap — Testing Report

Covers the three requested test types: **usability**, **bug** and
**vulnerability** testing. Automated tests live in `tests/` and run
with:

```bash
.venv/bin/python -m pytest tests/ -q
# 34 passed
```

## 1. Usability testing

### Automated smoke tests (`tests/test_usability.py`)

| Check | Result |
|---|---|
| Public pages (`/`, `/login`, `/register`) render with key controls | ✅ Pass |
| Admin pages (`/admin/`, firewall form, admin form, password form) render | ✅ Pass |
| Map has `aria-label` on map + legend, visible `<label>`s on controls | ✅ Pass |
| Every form includes a CSRF token + submit button | ✅ Pass |

### Manual usability checklist (verified in a browser)

- [x] First-run flow: `/register` → create admin → `/login` → `/admin/` works without documentation.
- [x] Threat map loads with demo data; filters (firewall, threat) and IP search respond.
- [x] Error messages are shown inline (flash messages) and preserve entered values.
- [x] Destructive actions (delete firewall) require confirmation.
- [x] Ingest token is labelled "shown once — copy it now" and forwarding examples are on the same page.
- [x] Layout is responsive (map height shrinks, topbar stacks under 640 px).
- [x] Colour is never the only signal: threat level is also printed as text (badges/table).

**Findings:** none blocking. Minor: the map needs internet access for
Leaflet/OpenStreetMap tiles (CDN); the API and tables work offline.
Documented in README.

## 2. Bug testing

Bugs found during development (all fixed, regression-tested):

| # | Bug | Severity | Root cause | Fix | Test |
|---|---|---|---|---|---|
| B1 | `IntegrityError: NOT NULL constraint failed: events.ts` on ingest without timestamp | High | `insert_event` passed explicit `NULL` for `ts`, overriding the column default | Default to current UTC time in Python | `test_ingest_json_accepts_and_enriches` |
| B2 | FortiGate `dsthost=` syslog field ignored (empty domain) | Medium | Alias table missing `dsthost` | Added alias | `test_ingest_syslog_fortigate` |
| B3 | Login lockout leaked across tests (flaky suite) | Low (test-only) | In-memory throttle is process-global | Autouse fixture resets throttle | full suite |
| B4 | `TemplateNotFound: index.html` | High | Flask looked for templates next to `app.py` | Explicit `template_folder`/`static_folder` | full suite |
| B5 | `TypeError: 'NoneType' object is not callable` in `base.html` | High | Context processor called `current_admin()` instead of passing the function | Pass function, call in template | full suite |
| B6 | CSRF 400s after login in tests | Low (test-only) | Session CSRF rotates on login (by design) | Tests fetch a fresh token | full suite |

### Functional test matrix (all passing)

| Area | Cases |
|---|---|
| Auth | one-time registration, second registration blocked (403), weak password rejected, login/logout, lockout after 5 failures, missing CSRF → 400, admin adds second admin |
| Firewall mgmt | enroll (Fortinet/Palo Alto/Other), invalid vendor rejected, toggle enable/disable, rotate token, delete |
| Ingest | JSON batch, single-object JSON, invalid IP dropped, FortiGate syslog, PAN-OS syslog, bad/missing token → 401, disabled firewall → 403, token rotation invalidates old token |
| Geo | demo IP → Manila, private IP → Internal, unknown IP → stable fallback, invalid IP → Unknown |
| Threat scoring | benign → low/unknown, C2-style event → high/critical with reasons, large transfer adds points |
| API | `/api/health`, `/api/events` (+filters), `/api/stats`, `/api/firewalls`, `/api/geo` validation |

## 3. Vulnerability testing

Manual + automated checks against the OWASP Top 10 (2021) relevant subset:

| # | Check | Method | Result |
|---|---|---|---|
| V1 | SQL injection | Login with `admin' OR '1'='1`; all queries parameterized (code review) | ✅ Literal match only; no auth bypass |
| V2 | Stored XSS | Enroll firewall named `<script>alert('xss')</script>` | ✅ Rendered escaped (`&lt;script&gt;`) |
| V3 | CSRF | POST without/with wrong token | ✅ 400 on every state-changing route |
| V4 | Broken access control | `GET /admin/` unauthenticated | ✅ 302 → `/login` |
| V5 | One-time registration bypass | `GET/POST /register` after first admin | ✅ 403 |
| V6 | Ingest token secrecy | `GET /api/firewalls` | ✅ Tokens never exposed |
| V7 | Token comparison | Code review | ✅ `hmac.compare_digest` |
| V8 | Password storage | Code review + test | ✅ PBKDF2-HMAC-SHA256, 260k iterations, per-password salt |
| V9 | Session security | Code review | ✅ HttpOnly + SameSite=Lax cookies; Secure flag behind HTTPS; CSRF rotates on login |
| V10 | Security headers | `GET /` | ✅ CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: no-referrer` |
| V11 | Brute force | 5 failed logins then correct password | ✅ Lockout message, login refused |
| V12 | Input validation | Oversized batch, bad JSON, invalid IPs | ✅ 413/400/dropped with counts |
| V13 | Verbose errors | `GET /no-such-page` | ✅ Generic 404 page, no stack traces |
| V14 | Secrets in repo | `git ls-files` + `.gitignore` | ✅ `.env`/`data/*.db` ignored; installer generates `SECRET_KEY` |

**Residual risks (accepted, documented):** the in-memory login throttle
resets on restart and is per-process (fine for the single-process
systemd deployment); geo lookup uses plain HTTP to ip-api.com (only
country/city/lat/lon are sent — the IP itself — and can be disabled
with `GEO_LOOKUP_ENABLED=0`); SQLite is suitable for the expected
single-server scale.

## 4. How to re-run

```bash
python3 -m venv .venv && .venv/bin/pip install flask requests pytest pillow
.venv/bin/python -m pytest tests/ -q          # automated suite
.venv/bin/python scripts/capture_screenshots.py  # regenerate README screenshots
```
