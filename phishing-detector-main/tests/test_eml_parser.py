"""
test_eml_parser.py - Tests for RFC 822 / MIME eml parsing and normalization utilities.
"""

from utils import normalize_url_or_domain
from utils.eml_parser import parse_eml_file

SAMPLE_EML_BYTES = b"""From: Sender <sender@phishing.test>
To: Victim <victim@example.com>
Subject: Security Verification Required
Date: Mon, 07 Sep 2026 00:00:00 +0000
Content-Type: text/plain; charset="utf-8"

Please update your account at http://secure-portal.phishing.test/login.
"""

def test_parse_eml_file_basic():
    parsed = parse_eml_file(SAMPLE_EML_BYTES)
    assert parsed["from_email"] == "sender@phishing.test"
    assert parsed["subject"] == "Security Verification Required"
    assert "http://secure-portal.phishing.test/login" in parsed["urls"]
    assert "http://secure-portal.phishing.test/login" in parsed["body_text"]

def test_normalize_url_or_domain():
    res1 = normalize_url_or_domain("https://www.google.com/search?q=test#top")
    assert res1["hostname"] == "www.google.com"

    res2 = normalize_url_or_domain("http://192.168.1.1:8080/path")
    assert res2["hostname"] == "192.168.1.1"

    res3 = normalize_url_or_domain("example.com")
    assert res3["hostname"] == "example.com"

    res4 = normalize_url_or_domain("user:pass@domain.com/path")
    assert res4["hostname"] == "domain.com"
