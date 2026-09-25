"""Tests for services/ip_extractor.py - email IP extraction.

Covers scenarios:
  A. Email with public IP
  B. Email with private IP
  C. Email with multiple Received headers
  D. Email with IPv6
  E. Email with no IP
  F. Invalid IP
  H. Duplicate IP addresses
"""

from services.ip_extractor import extract_ips_from_email


def _email(headers: str, body: str = "hello world") -> str:
    return f"""{headers}

{body}"""


# A ── Email with public IP ────────────────────────────────────────────────────

def test_email_with_public_ip():
    email = _email(
        "From: a@evil.tk\n"
        "To: v@example.com\n"
        "Message-ID: <pub1@evil.tk>\n"
        "X-Originating-IP: 8.8.8.8\n"
        "Received: from host (host [8.8.8.8]) by mx with ESMTP; Sat, 05 Sep 2026 10:00:00 +0000"
    )
    result = extract_ips_from_email(email)
    assert result["no_ip"] is False
    assert result["total_ips"] == 1
    assert result["ips"][0]["ip"] == "8.8.8.8"
    assert result["ips"][0]["is_public"] is True
    assert result["ips"][0]["type"] == "public"
    assert result["ips"][0]["version"] == 4


# B ── Email with private IP ───────────────────────────────────────────────────

def test_email_with_private_ip():
    email = _email(
        "From: a@example.com\n"
        "Message-ID: <priv1@example.com>\n"
        "Received: from relay (relay [192.168.1.10]) by mx with ESMTP; Sat, 05 Sep 2026 10:00:00 +0000"
    )
    result = extract_ips_from_email(email)
    assert result["total_ips"] == 1
    assert result["ips"][0]["ip"] == "192.168.1.10"
    assert result["ips"][0]["is_public"] is False
    assert result["ips"][0]["type"] == "private"


# C ── Multiple Received headers ───────────────────────────────────────────────

def test_email_with_multiple_received_headers():
    email = _email(
        "From: a@evil.tk\n"
        "Message-ID: <multi1@evil.tk>\n"
        "Received: from hop3 ([8.8.8.8]) by mx with ESMTP; Sat, 05 Sep 2026 10:02:00 +0000\n"
        "Received: from hop2 ([172.16.0.5]) by relay2 with ESMTP; Sat, 05 Sep 2026 10:01:00 +0000\n"
        "Received: from hop1 ([203.0.113.9]) by relay1 with ESMTP; Sat, 05 Sep 2026 10:00:00 +0000"
    )
    result = extract_ips_from_email(email)
    assert result["total_ips"] == 3

    ips = {r["ip"]: r for r in result["ips"]}
    assert set(ips) == {"8.8.8.8", "172.16.0.5", "203.0.113.9"}

    received_sources = [s for s in ips["8.8.8.8"]["sources"] if s["header"] == "Received"]
    assert received_sources[0]["hop"] == 0  # first Received header
    # The documentation IP (203.0.113.9) must be usable and non-public.
    assert ips["203.0.113.9"]["is_public"] is False
    assert ips["172.16.0.5"]["is_public"] is False


# D ── IPv6 ────────────────────────────────────────────────────────────────────

def test_email_with_ipv6():
    email = _email(
        "From: a@example.net\n"
        "Message-ID: <v6@example.net>\n"
        "Received: from host (host [2001:db8:85a3::8a2e:370:7334]) by mx with ESMTP; Sat, 05 Sep 2026 10:00:00 +0000"
    )
    result = extract_ips_from_email(email)
    assert result["total_ips"] == 1
    assert result["ips"][0]["ip"] == "2001:db8:85a3::8a2e:370:7334"
    assert result["ips"][0]["version"] == 6


def test_email_with_public_ipv6():
    email = _email(
        "From: a@example.net\n"
        "Message-ID: <v6b@example.net>\n"
        "Received: from host (host [2606:4700:4700::1111]) by mx with ESMTP; Sat, 05 Sep 2026 10:00:00 +0000"
    )
    result = extract_ips_from_email(email)
    assert result["total_ips"] == 1
    assert result["ips"][0]["version"] == 6
    assert result["ips"][0]["is_public"] is True


# E ── No IP ───────────────────────────────────────────────────────────────────

def test_email_with_no_ip():
    email = _email(
        "From: a@example.com\nTo: v@example.com\nSubject: hi\nMessage-ID: <noip@example.com>",
        body="This message has no headers with IP addresses at all.",
    )
    result = extract_ips_from_email(email)
    assert result["no_ip"] is True
    assert result["total_ips"] == 0


# F ── Invalid IP ──────────────────────────────────────────────────────────────

def test_email_with_invalid_ip():
    email = _email(
        "From: a@example.com\n"
        "Message-ID: <bad1@example.com>\n"
        "X-Originating-IP: 999.999.999.999\n"
        "Received: from host ([not-an-ip]) by mx; Sat, 05 Sep 2026 10:00:00 +0000"
    )
    result = extract_ips_from_email(email)
    # Every extracted candidate must survive ipaddress validation.
    assert result["total_ips"] == 0
    assert result["no_ip"] is True


# H ── Duplicate IP addresses ─────────────────────────────────────────────────

def test_duplicate_ip_deduplicated_preserving_sources():
    email = _email(
        "From: a@evil.tk\n"
        "Message-ID: <dup1@evil.tk>\n"
        "X-Originating-IP: 8.8.8.8\n"
        "X-Sender-IP: 8.8.8.8\n"
        "Received: from host (host [8.8.8.8]) by mx with ESMTP; Sat, 05 Sep 2026 10:00:00 +0000"
    )
    result = extract_ips_from_email(email)
    assert result["total_ips"] == 1
    record = result["ips"][0]
    headers = {s["header"] for s in record["sources"]}
    assert headers == {"Received", "X-Originating-IP", "X-Sender-IP"}
    assert len(record["sources"]) == 3


# ── Raw .eml bytes and Message objects ───────────────────────────────────────

def test_extraction_from_bytes_and_email_message():
    email = _email("From: a@example.com\nMessage-ID: <bytes1@example.com>\n"
                   "X-Originating-IP: 203.0.113.1")
    from_bytes = extract_ips_from_email(email.encode("utf-8"))
    assert from_bytes["total_ips"] == 1

    from email import policy
    from email.parser import Parser
    msg = Parser(policy=policy.default).parsestr(email)
    from_msg = extract_ips_from_email(msg)
    assert from_msg["total_ips"] == 1
    assert from_msg["ips"][0]["ip"] == "203.0.113.1"
    assert from_msg["ips"][0]["is_public"] is False  # documentation range


import os
from services.ip_extractor import extract_ips_from_email


def test_email_id_stable():
    email = _email("From: a@example.com\nMessage-ID: <id-stable@example.com>\n"
                   "X-Originating-IP: 8.8.8.8")
    a = extract_ips_from_email(email)
    b = extract_ips_from_email(email)
    assert a["email_id"] == b["email_id"] == "<id-stable@example.com>"


# I ── 3 Public IPs from Received headers & suspicious_phishing_3ip.eml ────────

def test_extract_at_least_3_public_ips_from_received_headers():
    email = (
        "From: test@example.com\n"
        "Subject: Test 3 Public IPs\n"
        "Received: from mail-gateway-03.example.net (8.8.8.8) by mx.example.com; Mon, 07 Sep 2026 10:15:30 +0530\n"
        "Received: from relay-node.example.net (1.1.1.1) by mail-gateway-03.example.net; Mon, 07 Sep 2026 10:15:28 +0530\n"
        "Received: from smtp-origin.example.net (9.9.9.9) by relay-node.example.net; Mon, 07 Sep 2026 10:15:25 +0530\n\n"
        "Body content"
    )
    result = extract_ips_from_email(email)
    assert result["no_ip"] is False
    public_received_ips = [
        r["ip"] for r in result["ips"]
        if r["is_public"] and any(s["header"] == "Received" for s in r.get("sources", []))
    ]
    assert len(public_received_ips) >= 3
    assert set(public_received_ips) == {"8.8.8.8", "1.1.1.1", "9.9.9.9"}


def test_suspicious_phishing_3ip_eml():
    eml_path = r"d:\Downloads\suspicious_phishing_3ip.eml"
    if not os.path.exists(eml_path):
        eml_path = os.path.join(os.path.dirname(__file__), "..", "..", "suspicious_phishing_3ip.eml")
    assert os.path.exists(eml_path), f"Test eml file not found at {eml_path}"
    with open(eml_path, "rb") as f:
        content = f.read()
    result = extract_ips_from_email(content)
    assert result["no_ip"] is False
    public_ips = [r["ip"] for r in result["ips"] if r["is_public"]]
    assert len(public_ips) == 3
    assert set(public_ips) == {"8.8.8.8", "1.1.1.1", "9.9.9.9"}