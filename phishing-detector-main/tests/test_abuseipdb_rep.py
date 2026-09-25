"""
tests/test_abuseipdb_rep.py - Tests for AbuseIPDB reputation UI binding and Threat Graph edge safety.
"""

from app import format_ip_reputation_display
from graph.threat_graph import ThreatGraph
from services.threat_intel import ThreatIntelService, enrich_ip_results


def test_format_ip_reputation_display_abuseipdb():
    rec = {
        "ip": "8.8.8.8",
        "threat_intel": {
            "ok": True,
            "abuse_confidence_score": 0,
            "total_reports": 5,
            "is_tor": False,
            "is_proxy": False,
        },
        "geo": {"ok": True, "country": "United States"}
    }
    rep_str = format_ip_reputation_display(rec)
    assert rep_str is not None
    assert "0% confidence" in rep_str
    assert "(5 reports)" in rep_str


def test_format_ip_reputation_display_suspicious():
    rec = {
        "ip": "1.2.3.4",
        "threat_intel": {
            "ok": True,
            "abuse_confidence_score": 85,
            "total_reports": 120,
            "is_tor": True,
            "is_proxy": True,
        },
        "geo": {"ok": True}
    }
    rep_str = format_ip_reputation_display(rec)
    assert rep_str is not None
    assert "85% confidence" in rep_str
    assert "(120 reports)" in rep_str
    assert "[Tor]" in rep_str
    assert "[Proxy]" in rep_str


def test_format_ip_reputation_display_unconfigured():
    rec = {
        "ip": "8.8.8.8",
        "threat_intel": {"ok": False, "category": "not_configured"},
        "geo": {"ok": True}
    }
    rep_str = format_ip_reputation_display(rec)
    assert rep_str is None


def test_no_duplicate_abuseipdb_calls():
    calls = []
    def dummy_http_get(url, params=None, headers=None, timeout=10):
        calls.append(params.get("ipAddress"))
        class MockResp:
            status_code = 200
            def json(self):
                return {
                    "data": {
                        "ipAddress": params.get("ipAddress"),
                        "abuseConfidenceScore": 0,
                        "totalReports": 2,
                        "usageType": "Data Center",
                    }
                }
        return MockResp()

    service = ThreatIntelService(api_key="test-key", http_get=dummy_http_get)
    ip_results = [
        {"ip": "8.8.8.8", "is_public": True, "type_label": "Public IPv4"},
        {"ip": "8.8.8.8", "is_public": True, "type_label": "Public IPv4"},
    ]
    enriched = enrich_ip_results(ip_results, threat_intel_service=service)
    assert len(enriched) == 2
    # Caching in ThreatIntelService ensures only 1 API call is made for duplicate IP 8.8.8.8
    assert calls == ["8.8.8.8"]
    assert enriched[0]["threat_intel"]["abuse_confidence_score"] == 0
    assert format_ip_reputation_display(enriched[0]) == "0% confidence (2 reports)"


def test_threat_graph_edge_iteration_safety():
    tg = ThreatGraph()
    tg.add_email_contains_url("email_1", "https://example.com")
    tg.add_domain_resolves_to_ip("example.com", "93.184.216.34")
    
    G = tg.graph
    # Verify NetworkX edge iteration used in app.py produces tuples safely
    edge_count = 0
    for edge in G.edges():
        u, v = edge[:2]
        assert u is not None
        assert v is not None
        edge_count += 1
    assert edge_count >= 2
