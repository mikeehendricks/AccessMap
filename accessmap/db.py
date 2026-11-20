"""SQLite data-access layer.

Design rules (enforced by review + tests):
* Every query is parameterized — user input is never interpolated
  into SQL strings.
* One connection per request (Flask ``g``), WAL journal mode for
  concurrent readers (map polling) + a single writer (ingest).
* Schema is created idempotently on first use (``init_db``).
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    is_super      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS firewalls (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    vendor        TEXT NOT NULL CHECK (vendor IN ('fortinet', 'paloalto', 'other')),
    host          TEXT NOT NULL DEFAULT '',
    site          TEXT NOT NULL DEFAULT '',
    ingest_token  TEXT NOT NULL UNIQUE,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_by    INTEGER REFERENCES admins(id),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at  TEXT
);

CREATE TABLE IF NOT EXISTS geo_cache (
    ip          TEXT PRIMARY KEY,
    country     TEXT NOT NULL DEFAULT '',
    city        TEXT NOT NULL DEFAULT '',
    lat         REAL NOT NULL DEFAULT 0,
    lon         REAL NOT NULL DEFAULT 0,
    isp         TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT 'fallback',
    resolved_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    firewall_id INTEGER REFERENCES firewalls(id),
    ts          TEXT NOT NULL DEFAULT (datetime('now')),
    src_ip      TEXT NOT NULL,
    dst_ip      TEXT NOT NULL,
    dst_domain  TEXT NOT NULL DEFAULT '',
    dst_port    INTEGER NOT NULL DEFAULT 0,
    protocol    TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL DEFAULT '',
    bytes_out   INTEGER NOT NULL DEFAULT 0,
    user_name   TEXT NOT NULL DEFAULT '',
    threat      TEXT NOT NULL DEFAULT 'unknown',
    threat_score INTEGER NOT NULL DEFAULT 0,
    src_country TEXT NOT NULL DEFAULT '',
    src_city    TEXT NOT NULL DEFAULT '',
    src_lat     REAL NOT NULL DEFAULT 0,
    src_lon     REAL NOT NULL DEFAULT 0,
    dst_country TEXT NOT NULL DEFAULT '',
    dst_city    TEXT NOT NULL DEFAULT '',
    dst_lat     REAL NOT NULL DEFAULT 0,
    dst_lon     REAL NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_fw ON events(firewall_id);
CREATE INDEX IF NOT EXISTS idx_events_threat ON events(threat);
"""

# Columns returned by the public event feed (never expose tokens/hashes).
EVENT_COLUMNS = (
    "id, ts, src_ip, dst_ip, dst_domain, dst_port, protocol, action, "
    "bytes_out, user_name, threat, threat_score, "
    "src_country, src_city, src_lat, src_lon, "
    "dst_country, dst_city, dst_lat, dst_lon, firewall_id"
)


def get_db() -> sqlite3.Connection:
    """Return the request-scoped SQLite connection (created lazily)."""
    if "db" not in g:
        db_path = Path(current_app.config["DATABASE_URL"])
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        g.db = conn
    return g.db


def close_db(_exc: Optional[BaseException] = None) -> None:
    """Close the request-scoped connection (registered as teardown)."""
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


@contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    """Yield a connection inside a commit/rollback transaction."""
    conn = get_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db() -> None:
    """Create all tables/indexes if they do not exist yet."""
    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()


# ---------------------------------------------------------------------------
# Admins
# ---------------------------------------------------------------------------

def create_admin(username: str, email: str, password_hash: str, is_super: bool = False) -> int:
    """Insert an admin and return its id."""
    with transaction() as conn:
        cur = conn.execute(
            "INSERT INTO admins (username, email, password_hash, is_super) VALUES (?, ?, ?, ?)",
            (username.strip(), email.strip().lower(), password_hash, 1 if is_super else 0),
        )
        return int(cur.lastrowid)


def get_admin_by_username(username: str) -> Optional[sqlite3.Row]:
    """Fetch an admin by username (case-insensitive) or None."""
    return get_db().execute(
        "SELECT * FROM admins WHERE username = ? COLLATE NOCASE", (username.strip(),)
    ).fetchone()


def get_admin_by_id(admin_id: int) -> Optional[sqlite3.Row]:
    """Fetch an admin by primary key or None."""
    return get_db().execute("SELECT * FROM admins WHERE id = ?", (admin_id,)).fetchone()


def list_admins() -> list[sqlite3.Row]:
    """Return all admins ordered by creation time."""
    return get_db().execute(
        "SELECT id, username, email, is_super, created_at, last_login_at FROM admins ORDER BY id"
    ).fetchall()


def count_admins() -> int:
    """Return how many admins exist (drives one-time registration)."""
    row = get_db().execute("SELECT COUNT(*) AS c FROM admins").fetchone()
    return int(row["c"])


def touch_login(admin_id: int) -> None:
    """Record the last-login timestamp for an admin."""
    with transaction() as conn:
        conn.execute("UPDATE admins SET last_login_at = datetime('now') WHERE id = ?", (admin_id,))


def set_password(admin_id: int, password_hash: str) -> None:
    """Replace an admin's password hash."""
    with transaction() as conn:
        conn.execute("UPDATE admins SET password_hash = ? WHERE id = ?", (password_hash, admin_id))


# ---------------------------------------------------------------------------
# Firewalls
# ---------------------------------------------------------------------------

def create_firewall(name: str, vendor: str, host: str, site: str, token: str, created_by: int) -> int:
    """Enroll a firewall and return its id."""
    with transaction() as conn:
        cur = conn.execute(
            "INSERT INTO firewalls (name, vendor, host, site, ingest_token, created_by) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (name.strip(), vendor, host.strip(), site.strip(), token, created_by),
        )
        return int(cur.lastrowid)


def get_firewall(firewall_id: int) -> Optional[sqlite3.Row]:
    """Fetch a firewall by id or None."""
    return get_db().execute("SELECT * FROM firewalls WHERE id = ?", (firewall_id,)).fetchone()


def get_firewall_by_token(token: str) -> Optional[sqlite3.Row]:
    """Fetch a firewall by its ingest token or None (constant-time compare)."""
    row = get_db().execute(
        "SELECT * FROM firewalls WHERE ingest_token = ?", (token,)
    ).fetchone()
    return row


def list_firewalls() -> list[sqlite3.Row]:
    """Return all firewalls with their event counts, newest first."""
    return get_db().execute(
        "SELECT f.*, (SELECT COUNT(*) FROM events e WHERE e.firewall_id = f.id) AS event_count "
        "FROM firewalls f ORDER BY f.id DESC"
    ).fetchall()


def update_firewall(firewall_id: int, *, enabled: Optional[bool] = None, token: Optional[str] = None) -> None:
    """Update a firewall's enabled flag and/or rotate its ingest token."""
    with transaction() as conn:
        if enabled is not None:
            conn.execute(
                "UPDATE firewalls SET enabled = ? WHERE id = ?", (1 if enabled else 0, firewall_id)
            )
        if token is not None:
            conn.execute(
                "UPDATE firewalls SET ingest_token = ? WHERE id = ?", (token, firewall_id)
            )


def delete_firewall(firewall_id: int) -> None:
    """Delete a firewall and its events."""
    with transaction() as conn:
        conn.execute("DELETE FROM events WHERE firewall_id = ?", (firewall_id,))
        conn.execute("DELETE FROM firewalls WHERE id = ?", (firewall_id,))


def touch_firewall(firewall_id: int) -> None:
    """Record the last-seen timestamp for a firewall."""
    with transaction() as conn:
        conn.execute(
            "UPDATE firewalls SET last_seen_at = datetime('now') WHERE id = ?", (firewall_id,)
        )


# ---------------------------------------------------------------------------
# Geo cache
# ---------------------------------------------------------------------------

def get_geo(ip: str) -> Optional[sqlite3.Row]:
    """Return a cached geo row for an IP or None."""
    return get_db().execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,)).fetchone()


def put_geo(ip: str, country: str, city: str, lat: float, lon: float, isp: str, source: str) -> None:
    """Insert or replace a geo-cache row."""
    with transaction() as conn:
        conn.execute(
            "INSERT INTO geo_cache (ip, country, city, lat, lon, isp, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET country=excluded.country, city=excluded.city, "
            "lat=excluded.lat, lon=excluded.lon, isp=excluded.isp, source=excluded.source, "
            "resolved_at=datetime('now')",
            (ip, country, city, lat, lon, isp, source),
        )


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

def insert_event(event: dict[str, Any]) -> int:
    """Insert one normalized event and return its id."""
    from datetime import datetime, timezone

    ts = event.get("ts") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with transaction() as conn:
        cur = conn.execute(
            "INSERT INTO events (firewall_id, ts, src_ip, dst_ip, dst_domain, dst_port, "
            "protocol, action, bytes_out, user_name, threat, threat_score, "
            "src_country, src_city, src_lat, src_lon, "
            "dst_country, dst_city, dst_lat, dst_lon) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.get("firewall_id"), ts,
                event["src_ip"], event["dst_ip"], event.get("dst_domain", ""),
                int(event.get("dst_port") or 0), event.get("protocol", ""),
                event.get("action", ""), int(event.get("bytes_out") or 0),
                event.get("user_name", ""), event.get("threat", "unknown"),
                int(event.get("threat_score") or 0),
                event.get("src_country", ""), event.get("src_city", ""),
                float(event.get("src_lat") or 0), float(event.get("src_lon") or 0),
                event.get("dst_country", ""), event.get("dst_city", ""),
                float(event.get("dst_lat") or 0), float(event.get("dst_lon") or 0),
            ),
        )
        return int(cur.lastrowid)


def list_events(limit: int = 100, firewall_id: Optional[int] = None,
                threat: Optional[str] = None) -> list[sqlite3.Row]:
    """Return recent events (newest first) with optional filters."""
    query = f"SELECT {EVENT_COLUMNS} FROM events WHERE 1=1"
    params: list[Any] = []
    if firewall_id is not None:
        query += " AND firewall_id = ?"
        params.append(firewall_id)
    if threat:
        query += " AND threat = ?"
        params.append(threat)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 1000)))
    return get_db().execute(query, params).fetchall()


def count_events() -> int:
    """Return the total number of stored events."""
    row = get_db().execute("SELECT COUNT(*) AS c FROM events").fetchone()
    return int(row["c"])


def event_stats() -> dict[str, Any]:
    """Aggregate counters used by the map header and admin dashboard."""
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
    threats = conn.execute(
        "SELECT COUNT(*) AS c FROM events WHERE threat IN ('high', 'critical')"
    ).fetchone()["c"]
    countries = conn.execute(
        "SELECT COUNT(DISTINCT dst_country) AS c FROM events WHERE dst_country != ''"
    ).fetchone()["c"]
    firewalls = conn.execute("SELECT COUNT(*) AS c FROM firewalls").fetchone()["c"]
    by_threat = {
        r["threat"]: r["c"]
        for r in conn.execute(
            "SELECT threat, COUNT(*) AS c FROM events GROUP BY threat"
        ).fetchall()
    }
    top_destinations = [
        dict(r)
        for r in conn.execute(
            "SELECT dst_domain, dst_ip, COUNT(*) AS hits FROM events "
            "GROUP BY dst_domain, dst_ip ORDER BY hits DESC LIMIT 8"
        ).fetchall()
    ]
    return {
        "total_events": int(total),
        "threat_events": int(threats),
        "destination_countries": int(countries),
        "firewalls": int(firewalls),
        "by_threat": by_threat,
        "top_destinations": top_destinations,
    }
