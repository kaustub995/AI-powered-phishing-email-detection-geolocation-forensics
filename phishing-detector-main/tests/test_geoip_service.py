"""Tests for services/geoip_service.py - configurable GeoIP service layer.

G. API failure scenarios - the service must never raise; it returns
   structured {"ok": False, "category", "error"} responses.
"""

import os
import pytest

from services.geoip_service import GeoIPService, get_geoip_config
from services.geoip_service import _extract_reputation, _risk_from_reputation


class _Response:
    def __init__(self, status_code, body=None, raises=None):
        self.status_code = status_code
        self._body = body
        self._raises = raises

    def json(self):
        if self._raises:
            raise self._raises
        return self._body


class FakeHTTP:
    """Simulated HTTP endpoint - returns the configured body/status/error."""

    def __init__(self, status_code=200, payload=None, raw=None, raises=None):
        self.status_code = status_code
        self.body = payload if raw is None else raw
        self.raises = raises

    def __call__(self, url, params=None, headers=None, timeout=10):
        if self.raises:
            raise self.raises
        return _Response(self.status_code, self.body)


def _service(http):
    return GeoIPService(url="https://test-provider.example/{ip}/json",
                        api_key="k", http_get=http)


# ── Configuration ────────────────────────────────────────────────────────────

def test_config_not_configured_when_no_env(monkeypatch):
    monkeypatch.delenv("GEOIP_API_URL", raising=False)
    monkeypatch.delenv("GEOIP_API_KEY", raising=False)
    cfg = get_geoip_config()
    assert cfg["enabled"] is False
    assert "GEOIP_API_URL" in cfg["message"]


def test_config_configured_from_env(monkeypatch):
    monkeypatch.setenv("GEOIP_API_URL", "https://provider.example/{ip}/json")
    monkeypatch.setenv("GEOIP_API_KEY", "secret")
    cfg = get_geoip_config()
    assert cfg["enabled"] is True
    assert cfg["has_key"] is True
    assert cfg["url"].startswith("https://")


def test_lookup_not_configured():
    service = GeoIPService(url="")
    result = service.lookup_ip("8.8.8.8")
    assert result["ok"] is False
    assert result["category"] == "not_configured"
    assert result["error"]


# ── Success with canonical normalization ─────────────────────────────────────

def test_success_normalizes_common_provider_fields():
    service = _service(FakeHTTP(payload={
        "query": "8.8.8.8",
        "country": "United States",
        "countryCode": "US",
        "regionName": "California",
        "city": "Mountain View",
        "lat": 37.386, "lon": -122.0838,
        "isp": "Google LLC",
        "org": "Google",
        "as": "AS15169 Google LLC",
        "timezone": "America/Los_Angeles",
        "hosting": True,
        "fraud_score": 85,
    }))
    result = service.lookup_ip("8.8.8.8")
    assert result["ok"] is True
    assert result["country"] == "United States"
    assert result["latitude"] == pytest.approx(37.386)
    assert result["isp"] == "Google LLC"
    assert result["asn"] == "AS15169 Google LLC"
    assert result["hosting"] is True
    assert result["reputation"]["score"] == 85
    assert result["risk_level"] == "high"


def test_success_omits_missing_fields():
    service = _service(FakeHTTP(payload={"query": "8.8.8.8", "country": "US"}))
    result = service.lookup_ip("8.8.8.8")
    assert result["ok"] is True
    assert result["city"] is None
    assert result["isp"] is None
    assert result["reputation"] is None
    assert result["risk_level"] is None


def test_success_ipv4_mapped_and_alternate_keys():
    service = _service(FakeHTTP(payload={
        "ip": "2606:4700:4700::1111",
        "country_name": "United States",
        "time_zone": "America/Chicago",
        "autonomous_system_asn": "AS13335",
        "is_datacenter": True,
        "abuseConfidenceScore": 60,
    }))
    result = service.lookup_ip("2606:4700:4700::1111")
    assert result["ok"] is True
    assert result["asn"] == "AS13335"
    assert result["hosting"] is True
    assert result["risk_level"] == "moderate"


# ── Error handling (never raises) ────────────────────────────────────────────

def test_api_timeout_returns_structured_failure():
    import requests
    service = _service(FakeHTTP(raises=requests.Timeout("timed out")))
    result = service.lookup_ip("8.8.8.8")
    assert result["ok"] is False
    assert result["category"] == "timeout"
    assert result["ip"] == "8.8.8.8"
    assert result["country"] is None


def test_api_connection_error():
    import requests
    service = _service(FakeHTTP(raises=requests.ConnectionError("down")))
    result = service.lookup_ip("8.8.8.8")
    assert result["ok"] is False
    assert result["category"] in ("unavailable", "api_error")


def test_http_500_unavailable():
    service = _service(FakeHTTP(status_code=500))
    result = service.lookup_ip("8.8.8.8")
    assert result["ok"] is False
    assert result["category"] == "unavailable"


def test_http_401_invalid_key():
    service = _service(FakeHTTP(status_code=401))
    result = service.lookup_ip("8.8.8.8")
    assert result["ok"] is False
    assert result["category"] == "invalid_key"


def test_http_429_rate_limit():
    service = _service(FakeHTTP(status_code=429))
    result = service.lookup_ip("8.8.8.8")
    assert result["ok"] is False
    assert result["category"] == "rate_limit"


def test_invalid_json_body():
    service = _service(FakeHTTP(status_code=200, raw="not-a-dict"))
    result = service.lookup_ip("8.8.8.8")
    assert result["ok"] is False
    assert result["category"] == "invalid_json"


# ── Caching ──────────────────────────────────────────────────────────────────

def test_duplicate_ips_are_cached():
    calls = []
    class CountingHTTP(FakeHTTP):
        def __call__(self, url, params=None, headers=None, timeout=10):
            calls.append(url)
            return super().__call__(url, params=params, headers=headers, timeout=timeout)
    service = _service(CountingHTTP(payload={"query": "8.8.8.8", "country": "US"}))
    service.lookup_ip("8.8.8.8")
    service.lookup_ip("8.8.8.8")
    assert len(calls) == 1


# ── Reputation helpers ───────────────────────────────────────────────────────

def test_reputation_extraction_and_risk_level():
    rep = _extract_reputation({"fraud_score": 92})
    assert rep["score"] == 92
    assert _risk_from_reputation(rep) == "high"

    rep2 = _extract_reputation({"reputation": "malicious"})
    assert rep2["markers"] == ["malicious"]
    assert _risk_from_reputation(rep2) == "high"

    assert _extract_reputation({"country": "US"}) is None