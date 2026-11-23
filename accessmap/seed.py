"""Demo-data seeder: ``python -m accessmap.seed``

Creates two demo firewalls (Fortinet + Palo Alto) and a batch of
realistic events so the threat map is alive on first run. Safe to
re-run: it refuses to duplicate data if events already exist.
"""

from __future__ import annotations

import random
import secrets

from accessmap import db, ingest

_DEMO_EVENTS: list[dict] = [
    {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.10", "dst_domain": "news.example.com", "dst_port": 443, "protocol": "tcp", "action": "allow", "bytes_out": 182340, "user_name": "jdelacruz"},
    {"src_ip": "10.0.0.6", "dst_ip": "203.0.113.11", "dst_domain": "shop.example.net", "dst_port": 443, "protocol": "tcp", "action": "allow", "bytes_out": 96412, "user_name": "mreyes"},
    {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.12", "dst_domain": "mail.example.org", "dst_port": 25, "protocol": "tcp", "action": "allow", "bytes_out": 45210, "user_name": "jdelacruz"},
    {"src_ip": "172.16.0.5", "dst_ip": "198.51.100.20", "dst_domain": "cdn.example.de", "dst_port": 443, "protocol": "tcp", "action": "allow", "bytes_out": 2209810, "user_name": "svc-backup"},
    {"src_ip": "10.0.0.6", "dst_ip": "198.51.100.21", "dst_domain": "video.example.co.uk", "dst_port": 443, "protocol": "tcp", "action": "allow", "bytes_out": 5402210, "user_name": "mreyes"},
    {"src_ip": "10.0.0.5", "dst_ip": "198.51.100.22", "dst_domain": "updates.example.jp", "dst_port": 443, "protocol": "tcp", "action": "allow", "bytes_out": 310540, "user_name": "jdelacruz"},
    {"src_ip": "192.168.1.10", "dst_ip": "192.0.2.50", "dst_domain": "maps.example.au", "dst_port": 443, "protocol": "tcp", "action": "allow", "bytes_out": 88210, "user_name": "areyes"},
    {"src_ip": "10.0.0.5", "dst_ip": "192.0.2.51", "dst_domain": "music.example.br", "dst_port": 443, "protocol": "tcp", "action": "allow", "bytes_out": 1205400, "user_name": "jdelacruz"},
    {"src_ip": "10.0.0.6", "dst_ip": "192.0.2.52", "dst_domain": "cloud.example.in", "dst_port": 443, "protocol": "tcp", "action": "allow", "bytes_out": 3301200, "user_name": "mreyes"},
    # Threat-flavoured events (blocked / suspicious ports / abuse TLDs).
    {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.11", "dst_domain": "login-verify.xyz", "dst_port": 4444, "protocol": "tcp", "action": "deny", "bytes_out": 0, "user_name": "jdelacruz"},
    {"src_ip": "10.0.0.6", "dst_ip": "198.51.100.20", "dst_domain": "free-games.top", "dst_port": 6666, "protocol": "tcp", "action": "deny", "bytes_out": 0, "user_name": "mreyes"},
    {"src_ip": "172.16.0.5", "dst_ip": "192.0.2.50", "dst_domain": "cdn-update.duckdns.org", "dst_port": 9999, "protocol": "tcp", "action": "deny", "bytes_out": 0, "user_name": "svc-backup"},
    {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.12", "dst_domain": "invoice.pdf.buzz", "dst_port": 80, "protocol": "tcp", "action": "allow", "bytes_out": 88000000, "user_name": "jdelacruz"},
]


def seed() -> None:
    """Insert demo firewalls + events if the database is empty."""
    if db.count_events() > 0:
        print("Events already exist — skipping demo seed.")
        return
    admin = db.get_admin_by_username("admin")
    created_by = int(admin["id"]) if admin else None

    fortinet = db.create_firewall(
        "FG-Manila-01", "fortinet", "fg-manila-01.example.local", "Manila HQ",
        secrets.token_urlsafe(32), created_by,
    )
    paloalto = db.create_firewall(
        "PA-Manila-01", "paloalto", "pa-manila-01.example.local", "Manila HQ",
        secrets.token_urlsafe(32), created_by,
    )
    rng = random.Random(42)
    for raw in _DEMO_EVENTS:
        firewall_id = fortinet if rng.random() < 0.55 else paloalto
        normalized = ingest.normalize_event(raw, firewall_id)
        if normalized is not None:
            db.insert_event(normalized)
    print(f"Seeded demo data: 2 firewalls, {len(_DEMO_EVENTS)} events.")


if __name__ == "__main__":
    from app import create_app

    app = create_app()
    with app.app_context():
        db.init_db()
        seed()
