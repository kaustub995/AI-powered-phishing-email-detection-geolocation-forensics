"""
tests/test_eml_workflows.py - Regression tests for .eml acceptance across forensic workflows:
GeoLocation & Forensics, Live Authentication, and Tracking / IP Intelligence.
"""

from utils.eml_parser import parse_eml_file
from forensic_engine import parse_email_headers, generate_forensic_report
from services.auth_validation import authenticate_email
from services.ip_extractor import extract_ips_from_email

SAMPLE_FULL_EML_BYTES = b"""Received: from mail.attacker-domain.org (mail.attacker-domain.org [185.220.101.5])
\tby mx.google.com with ESMTPS id abc123xyz
\tfor <target@company.com>; Mon, 22 Sep 2026 12:00:00 -0700
Received: from internal.workstation.local (10.0.4.15)
\tby mail.attacker-domain.org (8.14.4/8.14.4) with ESMTP id u8MD123;
\tMon, 22 Sep 2026 11:59:50 -0700
From: "Security Alert" <alert@attacker-domain.org>
To: Target User <target@company.com>
Subject: Immediate Password Verification Required
Date: Mon, 22 Sep 2026 12:00:00 -0700
Message-ID: <20260922120000.12345@attacker-domain.org>
Return-Path: <bounces@attacker-domain.org>
Content-Type: text/plain; charset="utf-8"

Please reset your credentials immediately at http://attacker-domain.org/verify.
"""

def test_eml_parser_extracts_full_structure():
    """Verify that parse_eml_file extracts raw headers, received chain, body, and IPs."""
    parsed = parse_eml_file(SAMPLE_FULL_EML_BYTES)
    assert parsed["from_email"] == "alert@attacker-domain.org"
    assert parsed["subject"] == "Immediate Password Verification Required"
    assert len(parsed["received_chain"]) == 2
    assert "http://attacker-domain.org/verify" in parsed["urls"]
    assert parsed["has_headers"] is True
    
    # Check IP extraction inside parsed EML
    ip_ext = parsed["ip_extraction"]
    assert ip_ext["total_ips"] >= 1
    found_ips = [ip["ip"] for ip in ip_ext["ips"]]
    assert "185.220.101.5" in found_ips


def test_eml_data_flow_to_geolocation_and_forensics():
    """Verify that parsed .eml raw text provides full header forensics and IP data."""
    raw_text = SAMPLE_FULL_EML_BYTES.decode("utf-8")
    
    # Header parsing for forensics
    parsed_headers = parse_email_headers(raw_text)
    assert parsed_headers["_has_headers"] is True
    assert len(parsed_headers["Received_All"]) == 2
    assert "alert@attacker-domain.org" in parsed_headers.get("From", "")
    
    # Full forensic report generation
    report = generate_forensic_report(email_text=raw_text)
    assert report["email_forensics"]["has_headers"] is True
    assert report["risk_level"] in ("critical", "high", "moderate", "low", "safe")


def test_eml_data_flow_to_authentication():
    """Verify that .eml raw text/bytes provide SPF/DKIM/DMARC input and client IP."""
    raw_text = SAMPLE_FULL_EML_BYTES.decode("utf-8")
    auth_res = authenticate_email(raw=raw_text, bytes_raw=SAMPLE_FULL_EML_BYTES)
    
    assert auth_res["from_domain"] == "attacker-domain.org"
    assert auth_res["envelope_domain"] == "attacker-domain.org"
    assert auth_res["client_ip"] == "185.220.101.5"
    assert "spf" in auth_res
    assert "dkim" in auth_res
    assert "dmarc" in auth_res


def test_eml_data_flow_to_tracking_and_ip_extraction():
    """Verify that .eml Received headers and candidate IPs are extracted for tracking/routing."""
    raw_text = SAMPLE_FULL_EML_BYTES.decode("utf-8")
    extraction = extract_ips_from_email(raw_text)
    
    assert extraction["no_ip"] is False
    assert extraction["total_ips"] >= 1
    
    # Verify public IP sorting and source preservation
    public_ips = [ip for ip in extraction["ips"] if ip["is_public"]]
    assert len(public_ips) > 0
    assert public_ips[0]["ip"] == "185.220.101.5"
    assert public_ips[0]["sources"][0]["header"] == "Received"


def test_plain_text_input_fallback():
    """Verify that plain text without headers falls back gracefully across all workflows."""
    plain_text = "Hello, please click here: http://example.com"
    
    parsed = parse_eml_file(plain_text)
    assert parsed["from_email"] == ""
    assert "http://example.com" in parsed["urls"]
    
    report = generate_forensic_report(email_text=plain_text)
    assert report["email_forensics"]["has_headers"] is False
    
    auth_res = authenticate_email(raw=plain_text)
    assert auth_res["from_domain"] == ""
