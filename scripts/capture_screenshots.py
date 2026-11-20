"""Capture README screenshots from real (seeded) application data.

No browser is required: the script boots the app in-process with the
demo seeder, reads the same JSON the live map uses, and renders
faithful PNG screenshots of the threat map, admin dashboard,
firewall detail and login pages with Pillow.

Usage:  python scripts/capture_screenshots.py
Output: screenshots/*.png
"""

from __future__ import annotations

import math
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from PIL import Image, ImageDraw, ImageFont  # noqa: E402

FONT_DIR = "/usr/share/fonts/truetype/dejavu"
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "screenshots")

BG = (11, 18, 32)
PANEL = (17, 26, 46)
PANEL2 = (22, 33, 58)
LINE = (34, 48, 77)
TEXT = (230, 237, 247)
MUTED = (142, 163, 192)
ACCENT = (56, 189, 248)
THREAT_COLORS = {
    "critical": (239, 68, 68), "high": (249, 115, 22),
    "medium": (250, 204, 21), "low": (56, 189, 248),
    "unknown": (148, 163, 184),
}


def font(size: int, bold: bool = False):
    name = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
    return ImageFont.truetype(os.path.join(FONT_DIR, name), size)


def lonlat_to_xy(lon: float, lat: float, box: tuple[int, int, int, int]) -> tuple[float, float]:
    """Equirectangular projection into the map box."""
    x0, y0, x1, y1 = box
    x = x0 + (lon + 180.0) / 360.0 * (x1 - x0)
    y = y0 + (90.0 - lat) / 180.0 * (y1 - y0)
    return x, y


def draw_topbar(draw: ImageDraw.ImageDraw, width: int, title: str) -> None:
    draw.rectangle([0, 0, width, 52], fill=PANEL)
    draw.line([0, 52, width, 52], fill=LINE, width=1)
    draw.text((20, 14), "◉ AccessMap", font=font(18, True), fill=TEXT)
    draw.text((width - 260, 16), title, font=font(14), fill=MUTED)


def draw_stats(draw: ImageDraw.ImageDraw, stats: dict, y: int) -> None:
    cards = [
        (str(stats["total_events"]), "Events"),
        (str(stats["threat_events"]), "Threats (high/critical)"),
        (str(stats["destination_countries"]), "Destination countries"),
        (str(stats["firewalls"]), "Enrolled firewalls"),
    ]
    x = 20
    for value, label in cards:
        draw.rounded_rectangle([x, y, x + 240, y + 78], radius=10, fill=PANEL, outline=LINE)
        draw.text((x + 16, y + 10), value, font=font(26, True), fill=TEXT)
        draw.text((x + 16, y + 48), label, font=font(13), fill=MUTED)
        x += 256


def draw_map(draw: ImageDraw.ImageDraw, events: list[dict], box: tuple[int, int, int, int]) -> None:
    x0, y0, x1, y1 = box
    draw.rounded_rectangle(box, radius=10, fill=(13, 21, 38), outline=LINE)
    # Graticule
    for lon in range(-180, 181, 30):
        gx, _ = lonlat_to_xy(lon, 0, box)
        draw.line([gx, y0, gx, y1], fill=(24, 36, 60), width=1)
    for lat in range(-60, 91, 30):
        _, gy = lonlat_to_xy(0, lat, box)
        draw.line([x0, gy, x1, gy], fill=(24, 36, 60), width=1)
    # Arcs (quadratic curves lifted above the straight line)
    for e in events:
        if not e["src_lat"] or not e["dst_lat"]:
            continue
        sx, sy = lonlat_to_xy(e["src_lon"], e["src_lat"], box)
        dx, dy = lonlat_to_xy(e["dst_lon"], e["dst_lat"], box)
        color = THREAT_COLORS.get(e["threat"], THREAT_COLORS["unknown"])
        mx, my = (sx + dx) / 2, min(sy, dy) - 40
        points = []
        for t in [i / 40 for i in range(41)]:
            px = (1 - t) ** 2 * sx + 2 * (1 - t) * t * mx + t**2 * dx
            py = (1 - t) ** 2 * sy + 2 * (1 - t) * t * my + t**2 * dy
            points.append((px, py))
        width = 3 if e["threat"] in {"critical", "high"} else 2
        draw.line(points, fill=color, width=width)
    for e in events:
        if not e["src_lat"] or not e["dst_lat"]:
            continue
        color = THREAT_COLORS.get(e["threat"], THREAT_COLORS["unknown"])
        for lon, lat, r in ((e["src_lon"], e["src_lat"], 4), (e["dst_lon"], e["dst_lat"], 5)):
            px, py = lonlat_to_xy(lon, lat, box)
            draw.ellipse([px - r, py - r, px + r, py + r], fill=color, outline=color)


def draw_table(draw: ImageDraw.ImageDraw, events: list[dict], y: int, width: int) -> None:
    headers = ["Time", "Source", "Destination", "Domain", "Port", "Action", "Threat"]
    col_x = [20, 170, 400, 630, 800, 870, 950]
    draw.rounded_rectangle([20, y, width - 20, y + 34 + 28 * 8], radius=10, fill=PANEL, outline=LINE)
    for i, h in enumerate(headers):
        draw.text((col_x[i], y + 10), h.upper(), font=font(11, True), fill=MUTED)
    for row, e in enumerate(events[:8]):
        ry = y + 34 + row * 28
        draw.line([20, ry, width - 20, ry], fill=LINE, width=1)
        vals = [str(e["ts"])[11:], f"{e['src_ip']} ({e['src_city']})",
                f"{e['dst_ip']} ({e['dst_city']})", e["dst_domain"] or "—",
                str(e["dst_port"]), e["action"] or "—", e["threat"]]
        for i, v in enumerate(vals):
            color = THREAT_COLORS.get(v, TEXT) if i == 6 else TEXT
            draw.text((col_x[i], ry + 6), v[:28], font=font(12), fill=color)


def screenshot_threat_map(events: list[dict], stats: dict) -> None:
    img = Image.new("RGB", (1100, 900), BG)
    draw = ImageDraw.Draw(img)
    draw_topbar(draw, 1100, "Threat map    Admin panel    admin")
    draw.text((20, 70), "Live threat map", font=font(28, True), fill=TEXT)
    draw.text((20, 108), "Source → destination view of websites visited by end users,",
              font=font(14), fill=MUTED)
    draw.text((20, 128), "streamed from enrolled Fortinet FortiGate and Palo Alto PAN-OS firewalls.",
              font=font(14), fill=MUTED)
    draw_stats(draw, stats, 160)
    draw_map(draw, events, (20, 260, 1080, 640))
    draw.text((20, 656), "● Critical   ● High   ● Medium   ● Low   ● Unknown",
              font=font(13), fill=MUTED)
    draw.text((20, 690), "Recent visits", font=font(20, True), fill=TEXT)
    draw_table(draw, events, 726, 1100)
    img.save(os.path.join(OUT_DIR, "threat-map.png"))


def screenshot_dashboard(stats: dict, firewalls: list[dict], admins: list[dict]) -> None:
    img = Image.new("RGB", (1100, 760), BG)
    draw = ImageDraw.Draw(img)
    draw_topbar(draw, 1100, "Threat map    Admin panel    admin")
    draw.text((20, 70), "Admin panel", font=font(28, True), fill=TEXT)
    draw.text((20, 108), "Signed in as admin. Enroll firewalls, manage admins, monitor the feed.",
              font=font(14), fill=MUTED)
    draw_stats(draw, stats, 150)
    draw.text((20, 250), "Enrolled firewalls", font=font(20, True), fill=TEXT)
    y = 288
    draw.rounded_rectangle([20, y, 1080, y + 34 + 28 * max(len(firewalls), 1)], radius=10,
                           fill=PANEL, outline=LINE)
    cols = [20, 300, 460, 620, 760, 920]
    for i, h in enumerate(["NAME", "VENDOR", "SITE", "EVENTS", "LAST SEEN", "STATUS"]):
        draw.text((cols[i], y + 10), h, font=font(11, True), fill=MUTED)
    for row, fw in enumerate(firewalls):
        ry = y + 34 + row * 28
        draw.line([20, ry, 1080, ry], fill=LINE, width=1)
        vals = [fw["name"], fw["vendor"], fw["site"] or "—", str(fw["event_count"]),
                fw["last_seen_at"] or "never", "Enabled" if fw["enabled"] else "Disabled"]
        for i, v in enumerate(vals):
            draw.text((cols[i], ry + 6), str(v)[:26], font=font(12), fill=TEXT)
    y2 = y + 34 + 28 * max(len(firewalls), 1) + 30
    draw.text((20, y2), "Admins", font=font(20, True), fill=TEXT)
    y3 = y2 + 38
    draw.rounded_rectangle([20, y3, 1080, y3 + 34 + 28 * max(len(admins), 1)], radius=10,
                           fill=PANEL, outline=LINE)
    for i, h in enumerate(["USERNAME", "EMAIL", "ROLE", "CREATED", "LAST LOGIN"]):
        draw.text((cols[i] if i < 5 else 920, y3 + 10), h, font=font(11, True), fill=MUTED)
    for row, a in enumerate(admins):
        ry = y3 + 34 + row * 28
        draw.line([20, ry, 1080, ry], fill=LINE, width=1)
        vals = [a["username"], a["email"], "Super admin" if a["is_super"] else "Admin",
                a["created_at"], a["last_login_at"] or "never"]
        for i, v in enumerate(vals):
            draw.text(((cols[i] if i < 5 else 920), ry + 6), str(v)[:26], font=font(12), fill=TEXT)
    img.save(os.path.join(OUT_DIR, "admin-dashboard.png"))


def screenshot_firewall_detail(firewall: dict, ingest_url: str) -> None:
    img = Image.new("RGB", (1100, 700), BG)
    draw = ImageDraw.Draw(img)
    draw_topbar(draw, 1100, "Threat map    Admin panel    admin")
    draw.text((20, 70), firewall["name"], font=font(28, True), fill=TEXT)
    draw.text((20, 108),
              f"Vendor: {firewall['vendor']}  ·  Site: {firewall['site'] or '—'}  ·  "
              f"Status: {'Enabled' if firewall['enabled'] else 'Disabled'}",
              font=font(14), fill=MUTED)
    draw.rounded_rectangle([20, 150, 1080, 330], radius=10, fill=PANEL, outline=LINE)
    draw.text((40, 166), "Ingest token (shown once — copy it now)", font=font(18, True), fill=TEXT)
    draw.text((40, 196), "Configure the firewall to POST events with Authorization: Bearer <token>.",
              font=font(13), fill=MUTED)
    draw.rounded_rectangle([40, 226, 1060, 262], radius=8, fill=PANEL2)
    draw.text((52, 236), firewall["ingest_token"][:72], font=font(13), fill=TEXT)
    draw.rounded_rectangle([40, 274, 1060, 310], radius=8, fill=PANEL2)
    draw.text((52, 284), ingest_url, font=font(13), fill=TEXT)
    draw.rounded_rectangle([20, 350, 1080, 620], radius=10, fill=PANEL, outline=LINE)
    draw.text((40, 366), "Forwarding examples", font=font(18, True), fill=TEXT)
    draw.text((40, 396), "FortiGate (syslog over HTTPS JSON forwarder)", font=font(14, True), fill=ACCENT)
    draw.text((40, 422), 'config log syslogd setting', font=font(13), fill=TEXT)
    draw.text((40, 444), f'    set server "{ingest_url}"', font=font(13), fill=TEXT)
    draw.text((40, 466), '    set format json', font=font(13), fill=TEXT)
    draw.text((40, 488), '    set custom-field-name1 "Authorization"', font=font(13), fill=TEXT)
    draw.text((40, 510), f'    set custom-field-value1 "Bearer {firewall["ingest_token"][:24]}…"', font=font(13), fill=TEXT)
    draw.text((40, 532), 'end', font=font(13), fill=TEXT)
    draw.text((40, 562), "Palo Alto PAN-OS (syslog forwarding profile)", font=font(14, True), fill=ACCENT)
    draw.text((40, 588), f"Server: {ingest_url}  (HTTP POST, JSON)", font=font(13), fill=TEXT)
    img.save(os.path.join(OUT_DIR, "firewall-detail.png"))


def screenshot_login() -> None:
    img = Image.new("RGB", (1100, 640), BG)
    draw = ImageDraw.Draw(img)
    draw_topbar(draw, 1100, "Threat map    Sign in")
    draw.rounded_rectangle([290, 110, 810, 520], radius=10, fill=PANEL, outline=LINE)
    draw.text((330, 140), "Sign in", font=font(26, True), fill=TEXT)
    draw.text((330, 176), "Admin sign-in for the AccessMap panel.", font=font(14), fill=MUTED)
    draw.text((330, 220), "Username", font=font(14, True), fill=TEXT)
    draw.rounded_rectangle([330, 246, 770, 286], radius=8, fill=PANEL2, outline=LINE)
    draw.text((342, 258), "admin", font=font(14), fill=TEXT)
    draw.text((330, 306), "Password", font=font(14, True), fill=TEXT)
    draw.rounded_rectangle([330, 332, 770, 372], radius=8, fill=PANEL2, outline=LINE)
    draw.text((342, 344), "••••••••••", font=font(14), fill=TEXT)
    draw.rounded_rectangle([330, 396, 770, 440], radius=8, fill=ACCENT)
    draw.text((520, 408), "Sign in", font=font(15, True), fill=(6, 32, 47))
    draw.text((330, 462), "First time here? Create the first admin account (one-time only).",
              font=font(13), fill=MUTED)
    img.save(os.path.join(OUT_DIR, "login.png"))


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="accessmap-shots-")
    os.environ["DATABASE_URL"] = os.path.join(tmp, "shots.db")
    os.environ["SECRET_KEY"] = "screenshot-secret"
    os.environ["GEO_LOOKUP_ENABLED"] = "0"

    from app import create_app
    from accessmap import db, auth

    app = create_app()
    with app.app_context():
        db.init_db()
        db.create_admin("admin", "admin@example.com",
                        auth.hash_password("Admin12345"), is_super=True)
        from accessmap import seed as seed_module
        seed_module.seed()
        stats = db.event_stats()
        events = [dict(r) for r in db.list_events(limit=100)]
        firewalls = [dict(r) for r in db.list_firewalls()]
        admins = [dict(r) for r in db.list_admins()]
        firewall = dict(db.get_firewall(firewalls[0]["id"]))

    screenshot_threat_map(events, stats)
    screenshot_dashboard(stats, firewalls, admins)
    screenshot_firewall_detail(firewall, "http://localhost:5000/api/ingest")
    screenshot_login()
    print(f"Screenshots written to {OUT_DIR}:")
    for name in sorted(os.listdir(OUT_DIR)):
        print(f"  - {name}")


if __name__ == "__main__":
    main()
