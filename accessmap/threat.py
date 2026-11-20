"""Rule-based threat scoring for normalized firewall events.

The scorer is intentionally transparent: every point is attributable
to a named rule, which makes the map's colour coding auditable.
Scores map to levels: 0-19 low, 20-49 medium, 50-79 high, 80+ critical.
"""

from __future__ import annotations

import ipaddress
from typing import Any

# Ports commonly abused for command-and-control / exfiltration.
_SUSPICIOUS_PORTS = {4444, 5555, 6666, 6667, 6668, 6669, 7777, 8888, 9999,
                     31337, 27015, 12345, 31335}
# Destination domains that are frequently used for phishing / malware.
_SUSPICIOUS_SUFFIXES = (".xyz", ".top", ".club", ".buzz", ".online", ".tk",
                        ".ml", ".ga", ".cf", ".gq", ".duckdns.org", ".ngrok.io")


def score_event(event: dict[str, Any]) -> tuple[str, int, list[str]]:
    """Return ``(level, score, reasons)`` for a normalized event."""
    score = 0
    reasons: list[str] = []

    action = (event.get("action") or "").lower()
    if action in {"deny", "denied", "blocked", "drop", "dropped", "reset"}:
        score += 25
        reasons.append("firewall blocked the session")

    port = int(event.get("dst_port") or 0)
    if port in _SUSPICIOUS_PORTS:
        score += 30
        reasons.append(f"suspicious destination port {port}")

    domain = (event.get("dst_domain") or "").lower()
    if any(domain.endswith(suffix) for suffix in _SUSPICIOUS_SUFFIXES):
        score += 20
        reasons.append("destination domain uses a high-abuse TLD/service")

    try:
        src = ipaddress.ip_address(event.get("src_ip", ""))
        if src.is_private and action in {"allow", "allowed", "accept"}:
            score += 10
            reasons.append("internal host allowed outbound session")
    except ValueError:
        score += 15
        reasons.append("unparseable source IP")

    if int(event.get("bytes_out") or 0) > 50_000_000:
        score += 15
        reasons.append("large outbound transfer (>50 MB)")

    if score >= 80:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 20:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "unknown"
    return level, score, reasons
