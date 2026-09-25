"""
test_forensic_engine.py - Unit tests for WHOIS lookup exception safety, forensic report generation, and map figure building.
"""

from forensic_engine import whois_lookup, generate_forensic_report
from geo_engine import build_geolocation_map_figure, generate_map_data


def test_whois_lookup_handles_exceptions_gracefully():
    # Should not raise AttributeError or crash on unknown / invalid domain
    res = whois_lookup("invalid-domain-name-999999999999.invalid")
    assert isinstance(res, dict)
    assert "error" in res
    assert res["domain"] == "invalid-domain-name-999999999999.invalid"


def test_generate_forensic_report_with_whois_failure():
    # Full forensic report should run smoothly even if WHOIS fails
    raw_email = (
        "From: Security Team <security@secure-banking-verify.tk>\n"
        "To: victim@example.com\n"
        "Subject: Urgent Account Notice\n\n"
        "Please click http://secure-banking-verify.tk/login"
    )
    report = generate_forensic_report(email_text=raw_email)
    assert isinstance(report, dict)
    assert report.get("sender_domain") == "secure-banking-verify.tk"
    assert "email_forensics" in report
    assert "findings" in report


def test_build_geolocation_map_figure():
    dummy_points = [
        {"ip": "203.0.113.1", "lat": 37.7749, "lon": -122.4194, "city": "San Francisco", "country": "United States", "isp": "Test ISP", "threat": "high", "color": "#FF4444", "is_proxy": False},
        {"ip": "198.51.100.2", "lat": 51.5074, "lon": -0.1278, "city": "London", "country": "United Kingdom", "isp": "Test ISP 2", "threat": "low", "color": "#00ff88", "is_proxy": True},
    ]
    fig = build_geolocation_map_figure(dummy_points)
    assert fig is not None
    assert len(fig.data) > 0
