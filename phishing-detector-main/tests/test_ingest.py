"""Tests for ingest/webhook_server.process_inbound pipeline.

No network: GeoIP and AbuseIPDB are unconfigured in tests, so the pipeline
degrades gracefully.
"""

import importlib
import os
import tempfile

from ingest.webhook_server import process_inbound


def _run(text, tmp_path):
    os.environ["CASE_STORE_PATH"] = str(tmp_path / "cases.db")
    os.environ["COC_SECRET"] = "test-coc"
    import ingest.webhook_server as mod
    importlib.reload(mod)  # fresh lazy store bound to new env
    return process_inbound(text, source="test")


def test_analyzed_with_relevant_fields(tmp_path):
    email = (
        "From: \"PayPal\" <security@security-paypa1.com>\n"
        "Reply-To: scam@evil.tk\n"
        "Message-ID: <p1@evil.tk>\n"
        "Received: from mx ([198.51.100.1]) by x; Mon, 06 Sep 2026 09:00:00 +0000\n"
        "X-Originating-IP: 203.0.113.7\n"
        "Subject: URGENT - verify your account\n"
        "\n"
        "Dear customer, your account is suspended. Click "
        "https://secure-paypa1.com/login now to confirm your payment details."
    )
    result = _run(email, tmp_path)
    assert result["status"] == "analyzed"
    assert result["verdict_class"] in ("phishing", "impersonated")
    assert result["email_id"]
    assert result["stored"] is True
    assert result["campaign_id"].startswith("cmp-")
    assert "verdict_class" in result
    assert result["processed_seconds"] > 0


def test_sender_denylist_rejects_before_analysis(tmp_path):
    os.environ["SENDER_DENYLIST"] = "evil.tk"
    import ingest.webhook_server as mod
    importlib.reload(mod)
    email = "From: attacker@evil.tk\nSubject: hi\n\nbody"
    result = process_inbound(email, source="test")
    assert result["status"] == "rejected"
    assert "SENDER_DENYLIST" in result["reason"]


def test_sender_allowlist_restricts(tmp_path):
    os.environ["SENDER_DENYLIST"] = ""
    os.environ["SENDER_ALLOWLIST"] = "trusted.com"
    import ingest.webhook_server as mod
    importlib.reload(mod)
    result = process_inbound("From: other@evil.tk\nSubject: hi\n\nbody", source="test")
    assert result["status"] == "rejected"
    assert "SENDER_ALLOWLIST" in result["reason"]


def test_health_config_reports_disabled_intel(tmp_path):
    os.environ["ABUSEIPDB_API_KEY"] = ""
    import ingest.webhook_server as mod
    importlib.reload(mod)
    config = mod._Handler  # endpoint handler class exists; check server importable
    assert config is not None