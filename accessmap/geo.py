"""IP -> location resolution.

Resolution order:
1. SQLite geo cache (previous lookups).
2. Online lookup via ip-api.com (free, no key) when enabled and the
   IP is public — results are cached.
3. Deterministic offline fallback: private/reserved IPs map to a
   labelled "internal" location; public IPs without an online result
   get a stable pseudo-location derived from the IP hash so the map
   still renders arcs in air-gapped deployments.

Every result records its ``source`` so the UI can show provenance.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass

from flask import current_app

# Well-known demo/test IPs used by the seeder and tests. These take
# precedence over the online lookup so demos are reproducible offline.
_DEMO_LOOKUP: dict[str, tuple[str, str, float, float, str]] = {
    # (country, city, lat, lon, isp)
    "203.0.113.10": ("Philippines", "Manila", 14.5995, 120.9842, "Demo ISP"),
    "203.0.113.11": ("United States", "New York", 40.7128, -74.0060, "Demo ISP"),
    "203.0.113.12": ("Singapore", "Singapore", 1.3521, 103.8198, "Demo ISP"),
    "198.51.100.20": ("Germany", "Frankfurt", 50.1109, 8.6821, "Demo ISP"),
    "198.51.100.21": ("United Kingdom", "London", 51.5074, -0.1278, "Demo ISP"),
    "198.51.100.22": ("Japan", "Tokyo", 35.6762, 139.6503, "Demo ISP"),
    "192.0.2.50": ("Australia", "Sydney", -33.8688, 151.2093, "Demo ISP"),
    "192.0.2.51": ("Brazil", "São Paulo", -23.5505, -46.6333, "Demo ISP"),
    "192.0.2.52": ("India", "Mumbai", 19.0760, 72.8777, "Demo ISP"),
    "10.0.0.5": ("Internal", "LAN", 14.5995, 120.9842, "Private network"),
    "10.0.0.6": ("Internal", "LAN", 14.5995, 120.9842, "Private network"),
    "172.16.0.5": ("Internal", "LAN", 14.5995, 120.9842, "Private network"),
    "192.168.1.10": ("Internal", "LAN", 14.5995, 120.9842, "Private network"),
}


@dataclass(frozen=True)
class GeoResult:
    """Resolved location for one IP address."""

    ip: str
    country: str
    city: str
    lat: float
    lon: float
    isp: str
    source: str  # "cache" | "online" | "demo" | "fallback" | "internal"


def is_routable(ip: str) -> bool:
    """Return True if the IP is a valid, globally routable address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def _fallback(ip: str) -> GeoResult:
    """Deterministic pseudo-location for unresolvable public IPs."""
    digest = hashlib.sha256(ip.encode()).digest()
    lat = (int.from_bytes(digest[0:2], "big") / 65535.0) * 140.0 - 70.0
    lon = (int.from_bytes(digest[2:4], "big") / 65535.0) * 360.0 - 180.0
    return GeoResult(ip, "Unknown", "Unknown", round(lat, 4), round(lon, 4),
                     "Unresolved", "fallback")


def _online_lookup(ip: str) -> GeoResult | None:
    """Query ip-api.com; return None on any failure (offline, timeout…)."""
    try:
        import requests  # local import: geo works without requests installed

        url = current_app.config["GEO_LOOKUP_URL"].format(ip=ip)
        resp = requests.get(url, timeout=current_app.config["GEO_LOOKUP_TIMEOUT"])
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            return None
        return GeoResult(
            ip=ip,
            country=str(data.get("country", "")),
            city=str(data.get("city", "")),
            lat=float(data.get("lat", 0.0)),
            lon=float(data.get("lon", 0.0)),
            isp=str(data.get("isp", "")),
            source="online",
        )
    except Exception:
        return None


def resolve(ip: str) -> GeoResult:
    """Resolve an IP to a location, using cache -> demo -> online -> fallback."""
    ip = (ip or "").strip()
    if not ip:
        return GeoResult("", "Unknown", "Unknown", 0.0, 0.0, "", "fallback")

    from accessmap import db

    cached = db.get_geo(ip)
    if cached is not None:
        return GeoResult(ip, cached["country"], cached["city"], float(cached["lat"]),
                         float(cached["lon"]), cached["isp"], "cache")

    if ip in _DEMO_LOOKUP:
        country, city, lat, lon, isp = _DEMO_LOOKUP[ip]
        db.put_geo(ip, country, city, lat, lon, isp, "demo")
        return GeoResult(ip, country, city, lat, lon, isp, "demo")

    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            db.put_geo(ip, "Internal", "LAN", 14.5995, 120.9842, "Private network", "internal")
            return GeoResult(ip, "Internal", "LAN", 14.5995, 120.9842,
                             "Private network", "internal")
    except ValueError:
        return _fallback(ip)

    result = _online_lookup(ip) if current_app.config["GEO_LOOKUP_ENABLED"] else None
    if result is None:
        result = _fallback(ip)
    db.put_geo(ip, result.country, result.city, result.lat, result.lon,
               result.isp, result.source)
    return result
