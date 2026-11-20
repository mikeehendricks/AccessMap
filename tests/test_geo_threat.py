"""Geo + threat-scoring unit tests (offline, deterministic)."""

from accessmap import geo, threat


def test_demo_ip_resolves_to_manila(app):
    with app.app_context():
        result = geo.resolve("203.0.113.10")
        assert result.country == "Philippines"
        assert result.city == "Manila"
        assert result.source in {"demo", "cache"}


def test_private_ip_is_internal(app):
    with app.app_context():
        result = geo.resolve("10.0.0.5")
        assert result.country == "Internal"
        assert result.source in {"demo", "internal", "cache"}


def test_unknown_public_ip_gets_stable_fallback(app):
    with app.app_context():
        first = geo.resolve("8.8.8.8")
        second = geo.resolve("8.8.8.8")
        assert first.lat == second.lat and first.lon == second.lon
        assert first.source in {"fallback", "cache", "online"}


def test_invalid_ip_falls_back(app):
    with app.app_context():
        result = geo.resolve("not-an-ip")
        assert result.country == "Unknown"


def test_threat_scoring_levels():
    benign = {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.10",
              "dst_domain": "news.example.com", "dst_port": 443,
              "protocol": "tcp", "action": "allow", "bytes_out": 1000}
    level, score, _ = threat.score_event(benign)
    assert level in {"low", "unknown"} and score < 20

    malicious = {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.11",
                 "dst_domain": "login-verify.xyz", "dst_port": 4444,
                 "protocol": "tcp", "action": "deny", "bytes_out": 0}
    level, score, reasons = threat.score_event(malicious)
    assert level in {"high", "critical"} and score >= 50
    assert reasons  # every point is attributable

    large = dict(benign, bytes_out=99_000_000)
    _level, score, _ = threat.score_event(large)
    assert score >= 15
