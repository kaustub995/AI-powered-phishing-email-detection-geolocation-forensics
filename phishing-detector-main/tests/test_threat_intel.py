"""Tests for services/threat_intel.py - AbuseIPDB layer (all mocked)."""

import pytest

from services.threat_intel import (
    ThreatIntelService, enrich_ip_results, infrastructure_type,
    get_threat_intel_config,
)


class _Response:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.body = body

    def json(self):
        return self.body


class FakeHTTP:
    def __init__(self, status_code=200, data=None, raises=None):
        self.status_code = status_code
        self.data = data
        self.raises = raises

    def __call__(self, url, params=None, headers=None, timeout=10):
        if self.raises:
            raise self.raises
        return _Response(self.status_code, {"data": self.data} if self.data else {})


def _service(http, key="test-key"):
    return ThreatIntelService(api_key=key, url="https://abuse.test/api/v2/check",
                              http_get=http)


def test_not_configured_without_key(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    service = ThreatIntelService(api_key="")
    result = service.lookup_ip("1.2.3.4")
    assert result["ok"] is False
    assert result["category"] == "not_configured"


def test_config_reflects_key(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    assert get_threat_intel_config()["enabled"] is False
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "secret")
    assert get_threat_intel_config()["enabled"] is True


def test_success_populates_signals():
    service = _service(FakeHTTP(data={
        "ipAddress": "185.220.101.34",
        "abuseConfidenceScore": 90,
        "usageType": "Tor Node",
        "isTor": True,
        "isProxy": False,
        "totalReports": 42,
        "lastReportedAt": "2026-08-01T00:00:00Z",
        "countryCode": "DE",
        "isp": "AS58061",
        "domain": "tor-exit.example.org",
    }))
    result = service.lookup_ip("185.220.101.34")
    assert result["ok"] is True
    assert result["infrastructure"] == "tor"
    assert result["is_tor"] is True
    assert result["abuse_confidence_score"] == 90
    assert result["risk_level"] == "high"


def test_http_401_invalid_key():
    service = _service(FakeHTTP(status_code=401), key="bad")
    result = service.lookup_ip("1.2.3.4")
    assert result["ok"] is False
    assert result["category"] == "invalid_key"


def test_http_429_rate_limit():
    service = _service(FakeHTTP(status_code=429))
    result = service.lookup_ip("1.2.3.4")
    assert result["category"] == "rate_limit"


def test_http_exception_mapped_to_api_error():
    service = _service(FakeHTTP(raises=RuntimeError("boom")))
    result = service.lookup_ip("1.2.3.4")
    assert result["ok"] is False
    assert result["category"] == "api_error"


def test_duplicate_lookup_cached():
    calls = []

    class CountingHTTP(FakeHTTP):
        def __call__(self, url, params=None, headers=None, timeout=10):
            calls.append(url)
            return super().__call__(url, params=params, headers=headers,
                                    timeout=timeout)

    service = _service(CountingHTTP(data={"ipAddress": "1.2.3.4"}))
    service.lookup_ip("1.2.3.4")
    service.lookup_ip("1.2.3.4")
    assert len(calls) == 1


def test_infrastructure_type_mapping():
    assert infrastructure_type("Tor Node") == "tor"
    assert infrastructure_type("Data Center Hosting") == "datacenter"
    assert infrastructure_type("VPS Hosting") == "vps"
    assert infrastructure_type("Open Proxy") == "proxy"
    assert infrastructure_type("") == "unknown"


def test_enrich_ip_results_tor_flag_adds_indicator():
    ip_results = [
        {"ip": "185.220.101.34", "is_public": True, "risk_level": "low",
         "score": 0.0, "indicators": [], "explanation": "base"},
    ]
    service = _service(FakeHTTP(data={
        "ipAddress": "185.220.101.34", "abuseConfidenceScore": 95,
        "usageType": "Tor Node", "isTor": True, "totalReports": 10,
    }))
    out = enrich_ip_results(ip_results, threat_intel_service=service)
    assert out[0]["threat_intel"]["ok"] is True
    assert any("Tor" in i for i in out[0]["indicators"])
    assert out[0]["risk_level"] == "high"


def test_enrich_ip_results_unconfigured_is_graceful():
    ip_results = [
        {"ip": "8.8.8.8", "is_public": True, "risk_level": "low", "score": 0.0,
         "indicators": [], "explanation": "base"},
    ]
    out = enrich_ip_results(ip_results, threat_intel_service=ThreatIntelService(api_key=""))
    assert out[0]["threat_intel"]["ok"] is False
    assert out[0]["indicators"] == []


def test_enrich_ip_results_skips_non_public():
    out = enrich_ip_results(
        [{"ip": "10.0.0.1", "is_public": False, "indicators": []}],
        threat_intel_service=ThreatIntelService(api_key=""))
    assert out[0]["threat_intel"] is None