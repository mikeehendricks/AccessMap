"""Generate a 15-second animated GIF demonstrating how AccessMap works.

Boots the real Flask application in-process with demo seed data and the
self-hosted Natural Earth world GeoJSON, then renders 150 frames at
10 fps (100 ms/frame = 15.00 s exact) across four workflow stages:

  1. (0.0s - 3.0s) One-time admin registration lock & admin sign-in
  2. (3.0s - 6.5s) Enrolling Fortinet & Palo Alto firewalls + Bearer token
  3. (6.5s - 12.5s) Live firewall event ingestion & curved world threat arcs
  4. (12.5s - 15.0s) Threat-level filtering & instant IP geo-lookup

Usage:  python scripts/generate_demo_gif.py
Output: screenshots/accessmap-demo.gif
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
OUT_PATH = os.path.join(BASE_DIR, "screenshots", "accessmap-demo.gif")
WORLD_GEOJSON = os.path.join(
    BASE_DIR, "accessmap", "static", "vendor", "world-countries.geojson"
)

W, H = 960, 620
FPS = 10
FRAME_MS = 100  # 10 centiseconds exact in GIF89a
TOTAL_FRAMES = 150  # 150 * 100ms = 15.00 seconds exact

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
OK = (52, 211, 153)
OK_BG = (15, 46, 34)
THREAT_COLORS = {
    "critical": (239, 68, 68),
    "high": (249, 115, 22),
    "medium": (250, 204, 21),
    "low": (56, 189, 248),
    "unknown": (148, 163, 184),
}

LAT_MIN, LAT_MAX = -58.0, 80.0
_FONT_CACHE: dict[tuple[int, bool], ImageFont.FreeTypeFont] = {}


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    key = (size, bold)
    if key not in _FONT_CACHE:
        name = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
        _FONT_CACHE[key] = ImageFont.truetype(os.path.join(FONT_DIR, name), size)
    return _FONT_CACHE[key]


def ease_in_out(t: float) -> float:
    t = max(0.0, min(1.0, t))
    return 3 * t * t - 2 * t * t * t


def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * ease_in_out(t)


def lonlat_to_xy(lon: float, lat: float, mw: int, mh: int) -> tuple[float, float]:
    clamped = max(LAT_MIN, min(LAT_MAX, lat))
    x = (lon + 180.0) / 360.0 * mw
    y = (LAT_MAX - clamped) / (LAT_MAX - LAT_MIN) * mh
    return x, y


def build_base_world(mw: int, mh: int) -> Image.Image:
    """Pre-render 2x-supersampled Natural Earth world map once for fast frame compositing."""
    scale = 2
    sw, sh = mw * scale, mh * scale
    canvas = Image.new("RGB", (sw, sh), OCEAN)
    draw = ImageDraw.Draw(canvas)

    for lon in range(-180, 181, 30):
        gx, _ = lonlat_to_xy(lon, 0, sw, sh)
        draw.line([gx, 0, gx, sh], fill=EQUATOR if lon == 0 else GRID, width=scale)
    for lat in (-30, 0, 30, 60):
        _, gy = lonlat_to_xy(0, lat, sw, sh)
        draw.line([0, gy, sw, gy], fill=EQUATOR if lat == 0 else GRID, width=scale)

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
            pts = [lonlat_to_xy(pt[0], pt[1], sw, sh) for pt in poly[0]]
            if len(pts) >= 3:
                draw.polygon(pts, fill=LAND, outline=LAND_BORDER)
                draw.line(pts + [pts[0]], fill=LAND_BORDER, width=2)

    return canvas.resize((mw, mh), Image.Resampling.LANCZOS)


def arc_points(
    sx: float, sy: float, dx: float, dy: float, steps: int = 36
) -> list[tuple[float, float]]:
    dist = math.hypot(dx - sx, dy - sy)
    lift = min(72.0, max(18.0, dist * 0.22))
    mx, my = (sx + dx) / 2.0, min(sy, dy) - lift
    pts = []
    for i in range(steps + 1):
        t = i / steps
        u = 1.0 - t
        pts.append((
            u * u * sx + 2 * u * t * mx + t * t * dx,
            u * u * sy + 2 * u * t * my + t * t * dy,
        ))
    return pts


def draw_topbar(draw: ImageDraw.ImageDraw, signed_in: bool, active: str) -> None:
    draw.rectangle([0, 0, W, 46], fill=PANEL)
    draw.line([0, 46, W, 46], fill=LINE, width=1)
    draw.text((18, 12), "◉ AccessMap", font=font(16, True), fill=TEXT)
    if signed_in:
        t_col = ACCENT if active == "map" else MUTED
        a_col = ACCENT if active == "admin" else MUTED
        draw.text((W - 285, 14), "Threat map", font=font(13, active == "map"), fill=t_col)
        draw.text((W - 190, 14), "Admin panel", font=font(13, active == "admin"), fill=a_col)
        draw.rounded_rectangle([W - 92, 10, W - 18, 35], radius=12, fill=PANEL2, outline=LINE)
        draw.text((W - 76, 14), "admin", font=font(12, True), fill=TEXT)
    else:
        draw.text((W - 175, 14), "Threat map", font=font(13), fill=MUTED)
        draw.text((W - 80, 14), "Sign in", font=font(13, True), fill=ACCENT)


def draw_step_footer(draw: ImageDraw.ImageDraw, frame_idx: int, step_label: str) -> None:
    """Draw step badge and smooth 15-second progress bar along the bottom."""
    bar_y = H - 34
    draw.rectangle([0, bar_y, W, H], fill=(9, 14, 26))
    draw.line([0, bar_y, W, bar_y], fill=LINE, width=1)
    draw.rounded_rectangle([16, bar_y + 5, 48, bar_y + 25], radius=4, fill=ACCENT)
    step_num = step_label.split("·")[0].strip()
    tw = draw.textlength(step_num, font=font(11, True))
    draw.text((32 - tw / 2, bar_y + 8), step_num, font=font(11, True), fill=(6, 32, 47))
    rest = step_label.split("·", 1)[1].strip() if "·" in step_label else step_label
    draw.text((56, bar_y + 8), rest, font=font(12, True), fill=TEXT)

    sec = (frame_idx + 1) / FPS
    timer = f"{sec:04.1f}s / 15.0s"
    draw.text((W - 106, bar_y + 9), timer, font=font(11), fill=MUTED)

    prog_w = int((W - 2) * ((frame_idx + 1) / TOTAL_FRAMES))
    draw.rectangle([0, H - 4, W, H], fill=PANEL2)
    draw.rectangle([0, H - 4, prog_w, H], fill=ACCENT)


def draw_cursor(draw: ImageDraw.ImageDraw, x: float, y: float, click: bool = False) -> None:
    ix, iy = int(x), int(y)
    if click:
        draw.ellipse([ix - 14, iy - 14, ix + 14, iy + 14], outline=ACCENT, width=2)
    poly = [(ix, iy), (ix, iy + 17), (ix + 5, iy + 13), (ix + 11, iy + 15)]
    draw.polygon(poly, fill=(255, 255, 255), outline=(15, 23, 42))


def render_scene1_login(frame_idx: int) -> Image.Image:
    """0.0s - 3.0s (frames 0..29): Admin sign-in + one-time registration lock."""
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    draw_topbar(draw, signed_in=False, active="login")

    # One-time registration security banner
    draw.rounded_rectangle([240, 66, 720, 98], radius=8, fill=OK_BG, outline=OK)
    draw.text(
        (256, 74),
        "✓ First admin created — public /register is now locked (HTTP 403)",
        font=font(12, True),
        fill=OK,
    )

    # Login card
    draw.rounded_rectangle([260, 116, 700, 500], radius=10, fill=PANEL, outline=LINE)
    draw.text((296, 140), "Sign in", font=font(24, True), fill=TEXT)
    draw.text((296, 174), "Admin sign-in for the AccessMap SOC panel.", font=font(13), fill=MUTED)

    # Typing animation
    uname_full = "admin"
    typed_u = uname_full[: min(len(uname_full), max(0, (frame_idx - 2) // 2))]
    pwd_count = min(10, max(0, (frame_idx - 10)))
    typed_p = "•" * pwd_count

    u_focus = 2 <= frame_idx < 10
    p_focus = 10 <= frame_idx < 21
    btn_click = 23 <= frame_idx <= 27

    draw.text((296, 214), "Username", font=font(13, True), fill=TEXT)
    draw.rounded_rectangle(
        [296, 236, 664, 274], radius=7, fill=PANEL2, outline=ACCENT if u_focus else LINE, width=2 if u_focus else 1
    )
    draw.text((308, 246), typed_u + ("|" if u_focus and frame_idx % 2 == 0 else ""), font=font(13), fill=TEXT)

    draw.text((296, 292), "Password", font=font(13, True), fill=TEXT)
    draw.rounded_rectangle(
        [296, 314, 664, 352], radius=7, fill=PANEL2, outline=ACCENT if p_focus else LINE, width=2 if p_focus else 1
    )
    draw.text((308, 324), typed_p + ("|" if p_focus and frame_idx % 2 == 0 else ""), font=font(13), fill=TEXT)

    btn_fill = (125, 211, 252) if btn_click else ACCENT
    draw.rounded_rectangle([296, 378, 664, 420], radius=8, fill=btn_fill)
    draw.text((452, 390), "Sign in", font=font(14, True), fill=(6, 32, 47))

    draw.text(
        (296, 444),
        "PBKDF2-SHA256 · Per-session CSRF · Brute-force lockout",
        font=font(11),
        fill=MUTED,
    )

    if frame_idx >= 25:
        msg = "✓ Authenticated — opening Admin panel…"
        mw_txt = int(draw.textlength(msg, font=font(12, True))) + 36
        draw.rounded_rectangle(
            [(W - mw_txt) // 2, 516, (W + mw_txt) // 2, 548],
            radius=8,
            fill=OK_BG,
            outline=OK,
        )
        draw.text(((W - mw_txt) // 2 + 18, 524), msg, font=font(12, True), fill=OK)

    # Cursor trajectory
    if frame_idx < 10:
        cx, cy = lerp(580, 410, frame_idx / 9.0), lerp(180, 255, frame_idx / 9.0)
    elif frame_idx < 20:
        cx, cy = lerp(410, 430, (frame_idx - 10) / 9.0), lerp(255, 333, (frame_idx - 10) / 9.0)
    else:
        cx, cy = lerp(430, 480, (frame_idx - 20) / 5.0), lerp(333, 399, (frame_idx - 20) / 5.0)
    draw_cursor(draw, cx, cy, click=btn_click)

    draw_step_footer(draw, frame_idx, "1/4 · One-Time Admin Setup & Sign-In (/login)")
    return img


def render_scene2_enroll(frame_idx: int, firewalls: list[dict], token: str) -> Image.Image:
    """3.0s - 6.5s (frames 30..64): Admin panel — enrolled Fortinet & Palo Alto firewalls + token."""
    local = frame_idx - 30  # 0..34
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    draw_topbar(draw, signed_in=True, active="admin")

    draw.text((22, 58), "Admin panel — Firewall Enrollment", font=font(21, True), fill=TEXT)
    draw.text(
        (22, 86),
        "Enroll Fortinet FortiGate & Palo Alto PAN-OS firewalls and copy their Bearer ingest token.",
        font=font(12),
        fill=MUTED,
    )

    # Enrolled firewalls table card
    draw.rounded_rectangle([22, 112, W - 22, 246], radius=10, fill=PANEL, outline=LINE)
    cols = [38, 200, 325, 450, 705, 810]
    headers = ["FIREWALL", "VENDOR", "SITE", "HOST", "EVENTS", "STATUS"]
    for i, h in enumerate(headers):
        draw.text((cols[i], 124), h, font=font(11, True), fill=MUTED)

    visible_fws = firewalls[:1] if local < 7 else firewalls[:2]
    for idx, fw in enumerate(visible_fws):
        ry = 152 + idx * 42
        is_new = idx == 1 and 7 <= local <= 14
        if is_new:
            draw.rectangle([24, ry - 4, W - 24, ry + 34], fill=(18, 42, 62))
        draw.line([22, ry - 4, W - 22, ry - 4], fill=LINE, width=1)
        vals = [
            fw["name"],
            fw["vendor"].upper(),
            fw["site"] or "Manila HQ",
            fw["host"] or "—",
            str(fw["event_count"]),
        ]
        for i, v in enumerate(vals):
            draw.text((cols[i], ry + 6), str(v)[:30], font=font(12, i == 0), fill=TEXT)
        draw.rounded_rectangle([cols[5], ry + 4, cols[5] + 74, ry + 26], radius=10, fill=OK_BG, outline=OK)
        draw.text((cols[5] + 12, ry + 7), "Enabled", font=font(11, True), fill=OK)

    # Token & Forwarding Configuration card
    draw.rounded_rectangle([22, 262, W - 22, 566], radius=10, fill=PANEL, outline=LINE)
    draw.text((40, 276), "PA-Manila-01 · Ingest Token & Syslog/HTTPS Forwarder", font=font(15, True), fill=TEXT)
    draw.text(
        (40, 300),
        "POST JSON or FortiGate/PAN-OS syslog to /api/ingest with Authorization: Bearer <token>",
        font=font(12),
        fill=MUTED,
    )

    copy_click = 20 <= local <= 25
    draw.rounded_rectangle(
        [40, 326, W - 150, 360],
        radius=7,
        fill=PANEL2,
        outline=ACCENT if copy_click else LINE,
    )
    draw.text((52, 336), f"Bearer {token[:48]}…", font=font(12), fill=ACCENT)
    draw.rounded_rectangle(
        [W - 138, 326, W - 40, 360],
        radius=7,
        fill=(125, 211, 252) if copy_click else ACCENT,
    )
    draw.text((W - 122, 336), "Copy token", font=font(12, True), fill=(6, 32, 47))

    # Side-by-side FortiGate + PAN-OS config snippets
    draw.rounded_rectangle([40, 374, 468, 548], radius=8, fill=OCEAN, outline=LINE)
    draw.text((54, 384), "Fortinet FortiGate CLI", font=font(12, True), fill=ACCENT)
    fg_lines = [
        "config log syslogd setting",
        '  set server "https://accessmap/api/ingest"',
        "  set format json",
        '  set custom-field-name1 "Authorization"',
        f'  set custom-field-value1 "Bearer {token[:14]}…"',
        "end",
    ]
    for i, ln in enumerate(fg_lines):
        draw.text((54, 408 + i * 21), ln, font=font(11), fill=TEXT)

    draw.rounded_rectangle([488, 374, W - 40, 548], radius=8, fill=OCEAN, outline=LINE)
    draw.text((502, 384), "Palo Alto PAN-OS HTTP Log Profile", font=font(12, True), fill=ACCENT)
    pa_lines = [
        "Endpoint:  POST /api/ingest",
        f"Header:    Authorization: Bearer {token[:14]}…",
        "Payload:   src_ip, dst_ip, dst_domain, dst_port",
        "Action:    Geo-resolve IPs -> Threat score -> Map",
    ]
    for i, ln in enumerate(pa_lines):
        draw.text((502, 412 + i * 26), ln, font=font(11), fill=TEXT)

    if local >= 21:
        msg = "✓ Token copied — firewalls streaming live events!"
        mw_txt = int(draw.textlength(msg, font=font(12, True))) + 36
        draw.rounded_rectangle(
            [(W - mw_txt) // 2, 524, (W + mw_txt) // 2, 556],
            radius=8,
            fill=OK_BG,
            outline=OK,
        )
        draw.text(((W - mw_txt) // 2 + 18, 532), msg, font=font(12, True), fill=OK)

    # Cursor movement: glide to Copy token, click there (20..25), then move to Threat map
    if local < 18:
        cx, cy = lerp(480, W - 89, local / 17.0), lerp(200, 343, local / 17.0)
    elif local <= 25:
        cx, cy = W - 89, 343
    else:
        cx, cy = lerp(W - 89, W - 250, (local - 25) / 9.0), lerp(343, 24, (local - 25) / 9.0)
    draw_cursor(draw, cx, cy, click=copy_click)

    draw_step_footer(draw, frame_idx, "2/4 · Enroll Fortinet & Palo Alto Firewalls (/admin/)")
    return img


def render_map_scene(
    frame_idx: int,
    base_world: Image.Image,
    events: list[dict],
    filter_high: bool = False,
    locate_ip: bool = False,
) -> Image.Image:
    """Scenes 3 & 4 (6.5s - 15.0s, frames 65..149): Live world threat map + filters/IP lookup."""
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)
    draw_topbar(draw, signed_in=True, active="map")

    # Determine visible events progressively in Scene 3
    ordered = list(reversed(events))  # chronological stream
    if not filter_high:
        local = frame_idx - 65  # 0..59
        shown_count = min(len(ordered), 3 + int(local * (len(ordered) - 2) / 36))
        active_events = ordered[:shown_count]
    else:
        active_events = [e for e in ordered if e["threat"] in {"high", "critical"}]

    threats_cnt = sum(1 for e in active_events if e["threat"] in {"high", "critical"})
    countries_cnt = len({e["dst_country"] for e in active_events if e.get("dst_country")})

    # Compact KPI stat strip
    kpis = [
        (str(len(active_events)), "Events streamed"),
        (str(threats_cnt), "Threats (high/crit)"),
        (str(countries_cnt), "Dest. countries"),
        ("2", "Enrolled firewalls"),
    ]
    kx = 18
    for val, lbl in kpis:
        draw.rounded_rectangle([kx, 56, kx + 222, 108], radius=8, fill=PANEL, outline=LINE)
        draw.text((kx + 14, 62), val, font=font(20, True), fill=ACCENT if "Events" in lbl else TEXT)
        draw.text((kx + 70, 68), lbl, font=font(12), fill=MUTED)
        kx += 234

    # Map container
    map_x, map_y = 18, 118
    mw, mh = W - 36, 310
    map_layer = base_world.copy().convert("RGBA")
    overlay = Image.new("RGBA", (mw, mh), (0, 0, 0, 0))
    odraw = ImageDraw.Draw(overlay, "RGBA")

    # Draw curved arcs + animated packet dots traveling along each arc!
    for idx, e in enumerate(active_events):
        sx, sy = lonlat_to_xy(float(e["src_lon"]), float(e["src_lat"]), mw, mh)
        dx, dy = lonlat_to_xy(float(e["dst_lon"]), float(e["dst_lat"]), mw, mh)
        rgb = THREAT_COLORS.get(e["threat"], THREAT_COLORS["unknown"])
        is_high = e["threat"] in {"high", "critical"}
        pts = arc_points(sx, sy, dx, dy, steps=32)

        # Progressive draw-in for the newest event in Scene 3
        if not filter_high and idx == len(active_events) - 1 and len(active_events) < len(ordered):
            grow = max(4, int(((frame_idx - 65) % 4 + 1) / 4.0 * len(pts)))
            seg = pts[:grow]
        else:
            seg = pts

        if len(seg) >= 2:
            odraw.line(seg, fill=(*rgb, 60), width=6 if is_high else 4)
            odraw.line(seg, fill=(*rgb, 235), width=3 if is_high else 2)

        # Animated packet pulse flying from source -> destination
        phase = ((frame_idx * 2 + idx * 7) % 33) / 32.0
        p_idx = min(len(pts) - 1, int(phase * (len(pts) - 1)))
        px, py = pts[p_idx]
        odraw.ellipse([px - 5, py - 5, px + 5, py + 5], fill=(*rgb, 110))
        odraw.ellipse([px - 2.5, py - 2.5, px + 2.5, py + 2.5], fill=(255, 255, 255, 245))

        # Source & pulsing destination markers
        pulse = 5 + (frame_idx + idx * 3) % 6
        if is_high:
            odraw.ellipse([dx - pulse - 3, dy - pulse - 3, dx + pulse + 3, dy + pulse + 3], outline=(*rgb, 130), width=2)
        dr = 5 if is_high else 4
        odraw.ellipse([dx - dr, dy - dr, dx + dr, dy + dr], fill=(*rgb, 245), outline=(230, 237, 247, 220))
        odraw.ellipse([sx - 4, sy - 4, sx + 4, sy + 4], fill=(*ACCENT, 245), outline=(230, 237, 247, 240))

    # Scene 3 live threat popup inspection card (frames 95..124)
    if not filter_high and frame_idx >= 95:
        # Highlight Sydney high-threat event
        tx, ty = lonlat_to_xy(151.2093, -33.8688, mw, mh)
        bx, by = int(tx) - 255, int(ty) - 74
        odraw.rounded_rectangle([bx, by, bx + 245, by + 64], radius=7, fill=(17, 26, 46, 238), outline=(249, 115, 22, 240))
        odraw.text((bx + 10, by + 7), "cdn-update.duckdns.org (:9999)", font=font(11, True), fill=TEXT)
        odraw.text((bx + 10, by + 25), "172.16.0.5 (Manila) → Sydney, AU", font=font(10), fill=MUTED)
        odraw.text((bx + 10, by + 42), "Action: DENY · Threat: HIGH (65)", font=font(10, True), fill=THREAT_COLORS["high"])

    # Scene 4 IP Locate spotlight on New York (203.0.113.11)
    if locate_ip:
        nx, ny = lonlat_to_xy(-74.0060, 40.7128, mw, mh)
        ring = 10 + (frame_idx % 6) * 2
        odraw.ellipse([nx - ring, ny - ring, nx + ring, ny + ring], outline=(*ACCENT, 220), width=2)
        odraw.ellipse([nx - 6, ny - 6, nx + 6, ny + 6], fill=(*ACCENT, 255), outline=(255, 255, 255, 255))
        bx, by = int(nx) + 14, int(ny) - 34
        odraw.rounded_rectangle([bx, by, bx + 252, by + 64], radius=7, fill=(17, 26, 46, 242), outline=(*ACCENT, 245))
        odraw.text((bx + 10, by + 7), "Located IP: 203.0.113.11", font=font(11, True), fill=ACCENT)
        odraw.text((bx + 10, by + 25), "New York, United States · Demo ISP", font=font(10), fill=TEXT)
        odraw.text((bx + 10, by + 42), "Domain: login-verify.xyz · HIGH", font=font(10, True), fill=THREAT_COLORS["high"])

    composed_map = Image.alpha_composite(map_layer, overlay).convert("RGB")
    img.paste(composed_map, (map_x, map_y))
    draw.rounded_rectangle([map_x, map_y, map_x + mw, map_y + mh], radius=8, outline=LINE)

    # Map zoom & layer badges
    draw.rounded_rectangle([map_x + 10, map_y + 10, map_x + 34, map_y + 58], radius=5, fill=PANEL2, outline=LINE)
    draw.line([map_x + 10, map_y + 34, map_x + 34, map_y + 34], fill=LINE)
    draw.text((map_x + 17, map_y + 12), "+", font=font(14, True), fill=TEXT)
    draw.text((map_x + 18, map_y + 35), "−", font=font(14, True), fill=TEXT)
    draw.rounded_rectangle([map_x + mw - 178, map_y + 10, map_x + mw - 10, map_y + 34], radius=5, fill=PANEL2, outline=LINE)
    draw.text((map_x + mw - 168, map_y + 15), "Layer: SOC Vector World", font=font(10, True), fill=TEXT)

    # Filter & IP Search bar
    fy = map_y + mh + 8
    draw.text((22, fy + 6), "Firewall:", font=font(11, True), fill=MUTED)
    draw.rounded_rectangle([80, fy, 198, fy + 26], radius=5, fill=PANEL2, outline=LINE)
    draw.text((88, fy + 6), "All firewalls (2)", font=font(11), fill=TEXT)

    draw.text((212, fy + 6), "Threat:", font=font(11, True), fill=MUTED)
    draw.rounded_rectangle(
        [262, fy, 386, fy + 26],
        radius=5,
        fill=PANEL2,
        outline=THREAT_COLORS["high"] if filter_high else LINE,
        width=2 if filter_high else 1,
    )
    draw.text(
        (270, fy + 6),
        "High / Critical" if filter_high else "All levels",
        font=font(11, filter_high),
        fill=THREAT_COLORS["high"] if filter_high else TEXT,
    )

    draw.text((402, fy + 6), "Find IP:", font=font(11, True), fill=MUTED)
    draw.rounded_rectangle(
        [454, fy, 594, fy + 26],
        radius=5,
        fill=PANEL2,
        outline=ACCENT if locate_ip else LINE,
    )
    ip_txt = "203.0.113.11" if (filter_high and frame_idx >= 133) else "e.g. 203.0.113.10"
    draw.text((462, fy + 6), ip_txt, font=font(11), fill=TEXT if "11" in ip_txt else MUTED)

    draw.rounded_rectangle([602, fy, 666, fy + 26], radius=5, fill=ACCENT if locate_ip else PANEL2, outline=ACCENT if locate_ip else LINE)
    draw.text((613, fy + 6), "Locate", font=font(11, True), fill=(6, 32, 47) if locate_ip else TEXT)

    # Compact legend on right of filter bar
    lx = 686
    for key, label in (("critical", "Crit"), ("high", "High"), ("medium", "Med"), ("low", "Low")):
        draw.ellipse([lx, fy + 8, lx + 9, fy + 17], fill=THREAT_COLORS[key])
        draw.text((lx + 13, fy + 6), label, font=font(11), fill=MUTED)
        lx += 62

    # Recent visits live table (3 latest rows)
    ty = fy + 34
    draw.rounded_rectangle([18, ty, W - 18, ty + 104], radius=8, fill=PANEL, outline=LINE)
    cols = [30, 195, 405, 620, 775, 855]
    for i, h in enumerate(["SOURCE", "DESTINATION", "WEBSITE / DOMAIN", "PORT", "ACTION", "THREAT"]):
        draw.text((cols[i], ty + 7), h, font=font(10, True), fill=MUTED)

    latest_rows = list(reversed(active_events))[:3]
    for r_i, ev in enumerate(latest_rows):
        ry = ty + 27 + r_i * 25
        draw.line([18, ry - 2, W - 18, ry - 2], fill=LINE)
        t_col = THREAT_COLORS.get(ev["threat"], TEXT)
        vals = [
            f"{ev['src_ip']} ({ev['src_city']})",
            f"{ev['dst_ip']} ({ev['dst_city']})",
            ev["dst_domain"] or "—",
            str(ev["dst_port"]),
            ev["action"] or "—",
            ev["threat"].upper(),
        ]
        for c_i, val in enumerate(vals):
            draw.text((cols[c_i], ry + 3), val[:26], font=font(11, c_i == 5), fill=t_col if c_i == 5 else TEXT)

    # Cursor in Scene 4
    if filter_high:
        s4 = frame_idx - 125  # 0..24
        if s4 < 10:
            cx, cy = lerp(480, 324, s4 / 9.0), lerp(280, fy + 13, s4 / 9.0)
            draw_cursor(draw, cx, cy, click=s4 in (7, 8, 9))
        else:
            cx, cy = lerp(324, 634, min(1.0, (s4 - 10) / 8.0)), fy + 13
            draw_cursor(draw, cx, cy, click=s4 in (17, 18, 19))
        draw_step_footer(draw, frame_idx, "4/4 · Filter High/Critical Threats & Locate Any IP")
    else:
        draw_step_footer(draw, frame_idx, "3/4 · Live Firewall Stream & Real-Time World Threat Map")

    return img


def main() -> None:
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="accessmap-gif-")
    os.environ["DATABASE_URL"] = os.path.join(tmp, "gif.db")
    os.environ["SECRET_KEY"] = "gif-demo-secret"
    os.environ["GEO_LOOKUP_ENABLED"] = "0"

    from app import create_app
    from accessmap import auth, db, seed as seed_module

    app = create_app()
    with app.app_context():
        db.init_db()
        db.create_admin("admin", "admin@example.com", auth.hash_password("Admin12345"), is_super=True)
        seed_module.seed()
        events = [dict(r) for r in db.list_events(limit=100)]
        firewalls = [dict(r) for r in db.list_firewalls()]
        token = dict(db.get_firewall(firewalls[0]["id"]))["ingest_token"]

    base_world = build_base_world(W - 36, 310)

    rgb_frames: list[Image.Image] = []
    for f in range(TOTAL_FRAMES):
        if f < 30:
            rgb_frames.append(render_scene1_login(f))
        elif f < 65:
            rgb_frames.append(render_scene2_enroll(f, firewalls, token))
        elif f < 125:
            rgb_frames.append(render_map_scene(f, base_world, events, filter_high=False, locate_ip=False))
        else:
            rgb_frames.append(
                render_map_scene(f, base_world, events, filter_high=True, locate_ip=(f >= 141))
            )

    # Build a shared 256-color palette across representative frames + exact UI/threat swatches
    # so flat dark SOC panels and every threat badge colour stay crisp without dithering.
    sample_indices = [26, 52, 105, 145]
    mosaic = Image.new("RGB", (W * 2, H * 2 + 40))
    for i, idx in enumerate(sample_indices):
        mosaic.paste(rgb_frames[idx], ((i % 2) * W, (i // 2) * H))
    sw_draw = ImageDraw.Draw(mosaic)
    swatches = [
        BG, PANEL, PANEL2, OCEAN, LAND, LAND_BORDER, GRID, EQUATOR, LINE,
        TEXT, MUTED, ACCENT, OK, OK_BG, (255, 255, 255), *THREAT_COLORS.values(),
    ]
    sw_w = (W * 2) // len(swatches)
    for s_i, col in enumerate(swatches):
        sw_draw.rectangle([s_i * sw_w, H * 2, (s_i + 1) * sw_w, H * 2 + 40], fill=col)
    palette_img = mosaic.quantize(colors=256, method=Image.Quantize.FASTOCTREE)

    pal_frames = [
        fr.quantize(palette=palette_img, dither=Image.Dither.NONE) for fr in rgb_frames
    ]

    pal_frames[0].save(
        OUT_PATH,
        save_all=True,
        append_images=pal_frames[1:],
        duration=FRAME_MS,
        loop=0,
        optimize=True,
    )

    size_kb = os.path.getsize(OUT_PATH) / 1024.0
    print(
        f"Generated {OUT_PATH}: {len(pal_frames)} frames @ {FRAME_MS}ms = "
        f"{len(pal_frames) * FRAME_MS / 1000:.2f}s ({size_kb:.1f} KB)"
    )


if __name__ == "__main__":
    main()
