"""Tests for services/ip_analyzer.py - validation, risk analysis and
forensic explanations. All GeoIP data is mocked (never real network)."""

import pytest

from services.ip_analyzer import assess_ip_risk, build_forensic_explanation, run_ip_intelligence
from services.geoip_service import GeoIPService
from services.ip_extractor import extract_ips_from_email
from utils.ip_utils import classify_ip


class FakeHTTP:
    """Simulated provider endpoint. Mock only - used exclusively in tests."""

    def __init__(self, payload=None, fail=None):
        self.payload = payload or {}
        self.fail = fail

    def __call__(self, url, params=None, headers=None, timeout=10):
        payload = self.payload

        class Response:
            status_code = 200

            def json(self):
                if isinstance(payload, dict):
                    return payload
                raise ValueError("bad json")

        if self.fail:
            raise self.fail
        return Response()


def _mock_service(payload):
    return GeoIPService(url="https://test-provider/{ip}/json",
                        api_key="test-key", http_get=FakeHTTP(payload=payload))


def test_private_and_documentation_ips_never_queried():
    # An extractor-only pipeline (no GeoIP service calls for non-public IPs).
    email = ("From: a@example.com\nMessage-ID: <x@example.com>\n"
             "X-Originating-IP: 10.0.0.5\n"
             "Received: from h ([203.0.113.2]) by mx; Sat, 05 Sep 2026 10:00:00 +0000\n\nbody")
    ext = extract_ips_from_email(email)

    called = []
    service = GeoIPService(url="https://test-provider/{ip}/json", api_key="k",
                           http_get=FakeHTTP(payload={"country": "X"}))

    # Monkey-patch lookup to record calls.
    original = service.lookup_ip
    def spy_lookup(ip):
        called.append(ip)
        return original(ip)
    service.lookup_ip = spy_lookup

    result = run_ip_intelligence(ext, geoip_service=service)
    assert called == []  # nothing public -> no API calls
    assert result["summary"]["public_ips"] == 0


def test_risk_high_for_hosting_suspicious_reputation():
    email = ("From: a@evil.tk\nMessage-ID: <r1@evil.tk>\n"
             "X-Originating-IP: 185.220.101.34\n"
             "Received: from h (h [185.220.101.34]) by mx; Sat, 05 Sep 2026 10:00:00 +0000\n\nbody")
    ext = extract_ips_from_email(email)
    service = _mock_service({
        "query": "185.220.101.34", "country": "Russia", "countryCode": "RU",
        "regionName": "Moscow", "city": "Moscow", "lat": 55.75, "lon": 37.61,
        "isp": "TORexit", "org": "Tor exit hosting", "as": "AS58061 TORexit",
        "hosting": True, "proxy": True, "fraud_score": 90,
    })
    result = run_ip_intelligence(ext, geoip_service=service)
    rec = result["ip_results"][0]
    assert rec["is_public"] is True
    assert rec["risk_level"] in ("high", "moderate")
    assert rec["score"] >= 45
    assert any("hosting" in i.lower() for i in rec["indicators"])


def test_geoip_not_configured_does_not_crash():
    email = ("From: a@evil.tk\nMessage-ID: <nc@evil.tk>\n"
             "X-Originating-IP: 8.8.8.8\n"
             "Received: from h (h [8.8.8.8]) by mx; Sat, 05 Sep 2026 10:00:00 +0000\n\nbody")
    ext = extract_ips_from_email(email)
    service = GeoIPService(url="")  # unconfigured
    result = run_ip_intelligence(ext, geoip_service=service)
    assert result["ip_results"][0]["is_public"] is True
    geo = result["ip_results"][0]["geo"]
    assert geo["ok"] is False
    assert geo["category"] == "not_configured"


def test_header_correlation_rows_built():
    email = ("From: a@evil.tk\nMessage-ID: <corr@evil.tk>\n"
             "X-Originating-IP: 185.220.101.34\n"
             "Received: from h (h [185.220.101.34]) by mx; Sat, 05 Sep 2026 10:00:00 +0000\n\nbody")
    ext = extract_ips_from_email(email)
    service = _mock_service({
        "query": "185.220.101.34", "country": "Russia", "regionName": "MO",
        "city": "Moscow", "isp": "TORexit", "as": "ASX",
        "hosting": True, "fraud_score": 88,
    })
    result = run_ip_intelligence(ext, geoip_service=service)
    assert len(result["correlations"]) == 2  # X-Originating-IP + Received
    for row in result["correlations"]:
        assert row["email_id"] == "<corr@evil.tk>"
        assert row["ip"] == "185.220.101.34"
        assert row["country"] == "Russia"
        assert row["asn"] == "ASX"
        assert row["risk_level"] in ("high", "moderate", "low", "clean")


def test_explanation_says_supporting_evidence_not_definitive():
    explanation = build_forensic_explanation(
        "185.220.101.34",
        {"is_public": True, "type": "public", "sources": [{"header": "Received"}]},
        {"ok": True, "country": "Russia", "region": "MO", "city": "Moscow",
         "isp": "X", "asn": "AS1", "hosting": True},
        ["Public IP observed in email headers", "IP associated with a hosting/datacenter provider",
         "Provider reputation reports the IP as HIGH risk"],
    )
    assert "supporting evidence" in explanation
    assert "Probable geographic/network context" in explanation
    assert "hosting provider" in explanation
    # Geographic context must never be framed as exact physical location.
    assert "exact physical location" not in explanation


def test_reputation_alone_does_not_classify_email_as_phishing():
    # Per requirements: IP reputation must be supporting evidence only.
    email = ("From: a@evil.tk\nMessage-ID: <phish@evil.tk>\n"
             "X-Originating-IP: 1.2.3.4\n"
             "Received: from h (h [1.2.3.4]) by mx; Sat, 05 Sep 2026 10:00:00 +0000\n\nbody")
    ext = extract_ips_from_email(email)
    service = _mock_service({"query": "1.2.3.4", "hosting": True, "fraud_score": 95})
    result = run_ip_intelligence(ext, geoip_service=service)
    # The module reports IP risk but never labels the *email* as phishing.
    assert "email" not in result
    for rec in result["ip_results"]:
        assert "supporting evidence" in rec["explanation"]


def test_assess_ip_risk_non_public_is_low():
    cls = classify_ip("192.168.1.1")
    out = assess_ip_risk("192.168.1.1", cls, geo=None)
    assert out["risk_level"] == "low"
    assert out["score"] == 0


def test_context_sender_country_mismatch_adds_indicator():
    cls = classify_ip("1.2.3.4")
    out = assess_ip_risk("1.2.3.4", cls,
                         geo={"ok": True, "country": "Russia", "city": "Moscow"},
                         context={"sender_country": "United States"})
    assert any("does not match" in i for i in out["indicators"])
    assert out["score"] >= 10


def test_run_ip_intelligence_uses_threat_intel_service():
    from services.threat_intel import ThreatIntelService
    class MockThreatIntelHTTP:
        def __call__(self, url, params=None, headers=None, timeout=10):
            class Response:
                status_code = 200
                def json(self):
                    return {"data": {
                        "ipAddress": "185.220.101.34",
                        "abuseConfidenceScore": 90,
                        "usageType": "Tor Node",
                        "isTor": True,
                        "totalReports": 50,
                    }}
            return Response()

    email = ("From: a@test.com\nMessage-ID: <ti@test.com>\n"
             "Received: from h ([185.220.101.34]) by mx; Sat, 05 Sep 2026 10:00:00 +0000\n\nbody")
    ext = extract_ips_from_email(email)
    ti_service = ThreatIntelService(api_key="test-key", http_get=MockThreatIntelHTTP())
    result = run_ip_intelligence(ext, threat_intel_service=ti_service)
    rec = result["ip_results"][0]
    assert rec["threat_intel"]["ok"] is True
    assert rec["threat_intel"]["infrastructure"] == "tor"
    assert rec["risk_level"] == "high"
    assert any("Tor" in i for i in rec["indicators"])