"""Firewall log ingestion and normalization.

Supported inputs
----------------
1. **JSON** (preferred): ``{"events": [{...}, ...]}`` or a single
   object. Fields: ``src_ip``, ``dst_ip``, ``dst_domain``,
   ``dst_port``, ``protocol``, ``action``, ``bytes_out``,
   ``user_name``, ``ts``. Vendor aliases (``src``, ``dst``,
   ``srcip``, ``dstip``, ``dport``, ``service``…) are mapped to the
   canonical names so FortiGate/PAN JSON forwarders work unchanged.
2. **FortiGate syslog** ``key=value`` lines, e.g.
   ``date=2026-11-20 time=10:00:00 devname=FG1 srcip=10.0.0.5 dstip=…``
3. **PAN-OS syslog** lines with ``SRC=`` / ``DST=`` / ``DPORT=`` /
   ``PROTO=`` / ``ACTION=`` tokens.

Every accepted event is geo-resolved (source + destination) and
threat-scored before storage, so the map never has to enrich data.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable

from accessmap import geo, threat

# Canonical field -> accepted aliases (lower-cased keys).
_ALIASES: dict[str, tuple[str, ...]] = {
    "src_ip": ("src_ip", "srcip", "src", "source_ip", "src_addr"),
    "dst_ip": ("dst_ip", "dstip", "dst", "dest_ip", "destination_ip", "dst_addr"),
    "dst_domain": ("dst_domain", "domain", "hostname", "dst_host", "dsthost", "host"),
    "dst_port": ("dst_port", "dport", "dstport", "dest_port", "port"),
    "protocol": ("protocol", "proto", "service", "app"),
    "action": ("action", "act", "disposition"),
    "bytes_out": ("bytes_out", "bytes", "sent_bytes", "out_bytes", "bytecount"),
    "user_name": ("user_name", "user", "src_user", "username"),
    "ts": ("ts", "timestamp", "date_time", "time", "date"),
}
_KV_RE = re.compile(r"(\w+)=([^\s]+)")


def _canonical(raw: dict[str, Any]) -> dict[str, Any]:
    """Map vendor-specific keys to canonical event fields."""
    lowered = {str(k).lower(): v for k, v in raw.items()}
    out: dict[str, Any] = {}
    for canonical, aliases in _ALIASES.items():
        for alias in aliases:
            if alias in lowered and lowered[alias] not in (None, ""):
                out[canonical] = lowered[alias]
                break
    return out


def parse_syslog_line(line: str) -> dict[str, Any]:
    """Parse one FortiGate/PAN syslog line into canonical fields."""
    pairs = dict(_KV_RE.findall(line))
    # PAN-OS also emits SRC=/DST= style tokens already covered by the
    # alias table; FortiGate emits srcip=/dstip= etc.
    return _canonical(pairs)


def _valid_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def normalize_event(raw: dict[str, Any], firewall_id: int) -> dict[str, Any] | None:
    """Validate + enrich one raw event; return None if it must be dropped."""
    event = _canonical(raw)
    src_ip = str(event.get("src_ip", "")).strip()
    dst_ip = str(event.get("dst_ip", "")).strip()
    if not (_valid_ip(src_ip) and _valid_ip(dst_ip)):
        return None

    try:
        dst_port = int(event.get("dst_port") or 0)
    except (TypeError, ValueError):
        dst_port = 0
    try:
        bytes_out = int(event.get("bytes_out") or 0)
    except (TypeError, ValueError):
        bytes_out = 0

    normalized: dict[str, Any] = {
        "firewall_id": firewall_id,
        "ts": str(event.get("ts", "")).strip() or None,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_domain": str(event.get("dst_domain", "")).strip()[:253],
        "dst_port": max(0, min(dst_port, 65535)),
        "protocol": str(event.get("protocol", "")).strip()[:32],
        "action": str(event.get("action", "")).strip()[:32],
        "bytes_out": max(0, bytes_out),
        "user_name": str(event.get("user_name", "")).strip()[:128],
    }

    src_geo = geo.resolve(src_ip)
    dst_geo = geo.resolve(dst_ip)
    normalized.update({
        "src_country": src_geo.country, "src_city": src_geo.city,
        "src_lat": src_geo.lat, "src_lon": src_geo.lon,
        "dst_country": dst_geo.country, "dst_city": dst_geo.city,
        "dst_lat": dst_geo.lat, "dst_lon": dst_geo.lon,
    })
    level, score, _reasons = threat.score_event(normalized)
    normalized["threat"] = level
    normalized["threat_score"] = score
    return normalized


def normalize_batch(payload: Any, firewall_id: int) -> tuple[list[dict[str, Any]], int]:
    """Normalize a JSON payload; return ``(events, dropped_count)``."""
    if isinstance(payload, dict):
        items: Iterable[Any] = payload.get("events", [payload])
    elif isinstance(payload, list):
        items = payload
    else:
        items = []

    events: list[dict[str, Any]] = []
    dropped = 0
    for item in items:
        if not isinstance(item, dict):
            dropped += 1
            continue
        normalized = normalize_event(item, firewall_id)
        if normalized is None:
            dropped += 1
        else:
            events.append(normalized)
    return events, dropped
