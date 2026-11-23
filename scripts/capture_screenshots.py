"""Capture README screenshots from real (seeded) application data.

No browser is required: the script boots the app in-process with the
demo seeder, reads the same JSON + Natural Earth world GeoJSON that
the live Leaflet map uses, and renders faithful PNG screenshots of the
threat map, admin dashboard, firewall detail and login pages with Pillow.

Usage:  python scripts/capture_screenshots.py
Output: screenshots/*.png
"""

from __future__ import annotations

import json
import math
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from PIL import Image, ImageDraw, ImageFont  # noqa: E402

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FONT_DIR = "/usr/share/fonts/truetype/dejavu"
OUT_DIR = os.path.join(BASE_DIR, "screenshots")
WORLD_GEOJSON = os.path.join(
    BASE_DIR, "accessmap", "static", "vendor", "world-countries.geojson"
)

BG = (11, 18, 32)
PANEL = (17, 26, 46)
PANEL2 = (22, 33, 58)
OCEAN = (8, 18, 36)
LAND = (23, 41, 70)
LAND_BORDER = (47, 77, 125)
GRID = (16, 31, 56)
EQUATOR = (27, 51, 88)
LINE = (34, 48, 77)
TEXT = (230, 237, 247)
MUTED = (142, 163, 192)
ACCENT = (56, 189, 248)
THREAT_COLORS = {
    "critical": (239, 68, 68),
    "high": (249, 115, 22),
    "medium": (250, 204, 21),
    "low": (56, 189, 248),
    "unknown": (148, 163, 184),
}

LAT_MIN, LAT_MAX = -60.0, 82.0


def font(size: int, bold: bool = False):
    name = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
    return ImageFont.truetype(os.path.join(FONT_DIR, name), size)


def lonlat_to_xy(lon: float, lat: float, w: int, h: int) -> tuple[float, float]:
    """Project (lon, lat) into map canvas coordinates matching the world viewport."""
    clamped_lat = max(LAT_MIN, min(LAT_MAX, lat))
    x = (lon + 180.0) / 360.0 * w
    y = (LAT_MAX - clamped_lat) / (LAT_MAX - LAT_MIN) * h
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
        draw.rounded_rectangle([x, y, x + 248, y + 78], radius=10, fill=PANEL, outline=LINE)
        draw.text((x + 16, y + 10), value, font=font(26, True), fill=TEXT)
        draw.text((x + 16, y + 48), label, font=font(13), fill=MUTED)
        x += 264


def render_world_canvas(events: list[dict], width: int, height: int) -> Image.Image:
    """Render 2x-supersampled world map (continents + country borders + threat arcs)."""
    scale = 2
    sw, sh = width * scale, height * scale
    canvas = Image.new("RGBA", (sw, sh), (*OCEAN, 255))
    mdraw = ImageDraw.Draw(canvas, "RGBA")

    # Graticule lines every 30 degrees
    for lon in range(-180, 181, 30):
        gx, _ = lonlat_to_xy(lon, 0, sw, sh)
        col = (*EQUATOR, 255) if lon == 0 else (*GRID, 255)
        mdraw.line([gx, 0, gx, sh], fill=col, width=scale)
    for lat in (-60, -30, 0, 30, 60):
        _, gy = lonlat_to_xy(0, lat, sw, sh)
        col = (*EQUATOR, 255) if lat == 0 else (*GRID, 255)
        mdraw.line([0, gy, sw, gy], fill=col, width=scale)

    # World countries from the same self-hosted Natural Earth GeoJSON used by map.js
    with open(WORLD_GEOJSON, encoding="utf-8") as fh:
        world = json.load(fh)

    for feat in world.get("features", []):
        if (feat.get("properties") or {}).get("name") == "Antarctica":
            continue
        geom = feat.get("geometry") or {}
        gtype = geom.get("type")
        coords = geom.get("coordinates") or []
        polys = coords if gtype == "MultiPolygon" else ([coords] if gtype == "Polygon" else [])
        for poly in polys:
            if not poly:
                continue
            exterior = poly[0]
            pts = [lonlat_to_xy(pt[0], pt[1], sw, sh) for pt in exterior]
            if len(pts) >= 3:
                mdraw.polygon(pts, fill=(*LAND, 248), outline=(*LAND_BORDER, 255))
                mdraw.line(pts + [pts[0]], fill=(*LAND_BORDER, 255), width=max(1, int(1.4 * scale)))

    # Curved threat arcs (glow + crisp stroke)
    for e in events:
        if e.get("src_lat") is None or e.get("dst_lat") is None:
            continue
        sx, sy = lonlat_to_xy(float(e["src_lon"]), float(e["src_lat"]), sw, sh)
        dx, dy = lonlat_to_xy(float(e["dst_lon"]), float(e["dst_lat"]), sw, sh)
        rgb = THREAT_COLORS.get(e["threat"], THREAT_COLORS["unknown"])
        dist = math.hypot(dx - sx, dy - sy)
        lift = min(90 * scale, max(22 * scale, dist * 0.22))
        mx, my = (sx + dx) / 2.0, min(sy, dy) - lift
        points = []
        for i in range(45):
            t = i / 44.0
            u = 1.0 - t
            px = u * u * sx + 2 * u * t * mx + t * t * dx
            py = u * u * sy + 2 * u * t * my + t * t * dy
            points.append((px, py))
        is_high = e["threat"] in {"critical", "high"}
        mdraw.line(points, fill=(*rgb, 55), width=(7 if is_high else 5) * scale)
        mdraw.line(points, fill=(*rgb, 235), width=(3 if is_high else 2) * scale)

    # Source & destination markers
    for e in events:
        if e.get("src_lat") is None or e.get("dst_lat") is None:
            continue
        rgb = THREAT_COLORS.get(e["threat"], THREAT_COLORS["unknown"])
        is_high = e["threat"] in {"critical", "high"}
        sx, sy = lonlat_to_xy(float(e["src_lon"]), float(e["src_lat"]), sw, sh)
        dx, dy = lonlat_to_xy(float(e["dst_lon"]), float(e["dst_lat"]), sw, sh)
        sr = 4 * scale
        dr = (6 if is_high else 5) * scale
        mdraw.ellipse([dx - dr * 2, dy - dr * 2, dx + dr * 2, dy + dr * 2], fill=(*rgb, 48))
        mdraw.ellipse([dx - dr, dy - dr, dx + dr, dy + dr], fill=(*rgb, 245), outline=(230, 237, 247, 220), width=scale)
        mdraw.ellipse([sx - sr, sy - sr, sx + sr, sy + sr], fill=(*rgb, 235), outline=(230, 237, 247, 240), width=scale)

    down = canvas.resize((width, height), Image.Resampling.LANCZOS).convert("RGB")
    ui = ImageDraw.Draw(down)

    # Leaflet zoom control (top-left) & layer control badge (top-right)
    ui.rounded_rectangle([12, 12, 42, 72], radius=6, fill=PANEL2, outline=LINE)
    ui.line([12, 42, 42, 42], fill=LINE, width=1)
    ui.text((21, 16), "+", font=font(16, True), fill=TEXT)
    ui.text((22, 45), "−", font=font(16, True), fill=TEXT)

    ui.rounded_rectangle([width - 196, 12, width - 12, 40], radius=6, fill=PANEL2, outline=LINE)
    ui.text((width - 184, 18), "Layers: SOC Vector World", font=font(11, True), fill=TEXT)

    ui.rectangle([width - 210, height - 20, width - 6, height - 4], fill=(11, 18, 32))
    ui.text((width - 204, height - 18), "Leaflet | Natural Earth · OSM", font=font(10), fill=MUTED)
    return down


def draw_map_card(img: Image.Image, draw: ImageDraw.ImageDraw, events: list[dict], y: int) -> int:
    """Draw the complete map-wrap card (world map + filter controls + threat legend)."""
    card_h = 520
    draw.rounded_rectangle([20, y, 1080, y + card_h], radius=10, fill=PANEL, outline=LINE)
    map_w, map_h = 1036, 420
    world_img = render_world_canvas(events, map_w, map_h)
    img.paste(world_img, (32, y + 12))
    draw.rounded_rectangle([32, y + 12, 32 + map_w, y + 12 + map_h], radius=8, outline=(27, 44, 75))

    # Filter row
    cy = y + 12 + map_h + 12
    controls = [
        ("Firewall:", "All firewalls", 138),
        ("Threat:", "All levels", 118),
        ("Find IP:", "e.g. 203.0.113.10", 158),
    ]
    cx = 32
    for label, val, bw in controls:
        draw.text((cx, cy + 7), label, font=font(12, True), fill=MUTED)
        lw = int(draw.textlength(label, font=font(12, True))) + 8
        draw.rounded_rectangle([cx + lw, cy, cx + lw + bw, cy + 30], radius=6, fill=PANEL2, outline=LINE)
        draw.text((cx + lw + 10, cy + 7), val, font=font(12), fill=TEXT if "e.g." not in val else MUTED)
        cx += lw + bw + 14
    draw.rounded_rectangle([cx, cy, cx + 72, cy + 30], radius=6, fill=PANEL2, outline=LINE)
    draw.text((cx + 14, cy + 7), "Locate", font=font(12, True), fill=TEXT)
    cx += 80
    draw.rounded_rectangle([cx, cy, cx + 76, cy + 30], radius=6, fill=PANEL, outline=LINE)
    draw.text((cx + 13, cy + 7), "Refresh", font=font(12), fill=TEXT)

    # Legend with colour-coded dots
    ly = cy + 40
    lx = 32
    for key, label in (
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
        ("unknown", "Unknown"),
    ):
        col = THREAT_COLORS[key]
        draw.ellipse([lx, ly + 4, lx + 10, ly + 14], fill=col)
        draw.text((lx + 16, ly + 1), label, font=font(13), fill=MUTED)
        lx += int(draw.textlength(label, font=font(13))) + 38

    return y + card_h


def draw_table(draw: ImageDraw.ImageDraw, events: list[dict], y: int, width: int) -> None:
    headers = ["Time", "Source", "Destination", "Domain", "Port", "Action", "Threat"]
    col_x = [34, 165, 390, 625, 810, 875, 960]
    rows = events[:6]
    draw.rounded_rectangle([20, y, width - 20, y + 36 + 30 * len(rows)], radius=10, fill=PANEL, outline=LINE)
    for i, h in enumerate(headers):
        draw.text((col_x[i], y + 11), h.upper(), font=font(11, True), fill=MUTED)
    for row, e in enumerate(rows):
        ry = y + 36 + row * 30
        draw.line([20, ry, width - 20, ry], fill=LINE, width=1)
        vals = [
            str(e["ts"])[11:],
            f"{e['src_ip']} ({e['src_city']})",
            f"{e['dst_ip']} ({e['dst_city']})",
            e["dst_domain"] or "—",
            str(e["dst_port"]),
            e["action"] or "—",
            e["threat"],
        ]
        for i, v in enumerate(vals):
            color = THREAT_COLORS.get(v, TEXT) if i == 6 else TEXT
            draw.text((col_x[i], ry + 7), v[:28], font=font(12, i == 6), fill=color)


def screenshot_threat_map(events: list[dict], stats: dict) -> None:
    img = Image.new("RGB", (1100, 1060), BG)
    draw = ImageDraw.Draw(img)
    draw_topbar(draw, 1100, "Threat map    Admin panel    admin")
    draw.text((20, 68), "Live threat map", font=font(28, True), fill=TEXT)
    draw.text(
        (20, 106),
        "Real-time source → destination view of websites visited by end users, streamed from enrolled",
        font=font(14),
        fill=MUTED,
    )
    draw.text(
        (20, 126),
        "Fortinet FortiGate and Palo Alto PAN-OS firewalls. Arcs are coloured by threat level.",
        font=font(14),
        fill=MUTED,
    )
    draw_stats(draw, stats, 156)
    bottom_map = draw_map_card(img, draw, events, 250)
    draw.text((20, bottom_map + 18), "Recent visits", font=font(20, True), fill=TEXT)
    draw_table(draw, events, bottom_map + 50, 1100)
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
    cols = [34, 300, 460, 620, 760, 920]
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
        import secrets as _secrets
        demo_tok = _secrets.token_urlsafe(32)
        db.update_firewall(firewall["id"], token=demo_tok)
        firewall["ingest_token"] = demo_tok

    screenshot_threat_map(events, stats)
    screenshot_dashboard(stats, firewalls, admins)
    screenshot_firewall_detail(firewall, "http://localhost:5000/api/ingest")
    screenshot_login()
    print(f"Screenshots written to {OUT_DIR}:")
    for name in sorted(os.listdir(OUT_DIR)):
        print(f"  - {name}")


if __name__ == "__main__":
    main()
