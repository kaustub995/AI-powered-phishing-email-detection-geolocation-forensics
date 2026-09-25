"""Tests for header-centric email forensics (From/To/Cc/Bcc + envelope)."""

from forensic_engine import analyze_email_headers, parse_email_headers


def _analyze(raw):
    return analyze_email_headers(parse_email_headers(raw))


def test_parses_envelope_fields():
    raw = ("From: A <a@ex.com>\nTo: b@ex.com\nCc: c@ex.com\nBcc: d@ex.com\n"
           "Subject: t\nMessage-ID: <x@ex.com>\n\nbody")
    h = parse_email_headers(raw)
    assert h["_has_headers"] is True
    assert h["To"] == "b@ex.com"
    assert h["Cc"] == "c@ex.com"
    assert h["Bcc"] == "d@ex.com"
    assert ("From", "A <a@ex.com>") in h["_all_headers"]


def test_body_only_input_is_flagged_as_headerless():
    h = parse_email_headers("Dear customer, click here now")
    assert h["_has_headers"] is False
    r = analyze_email_headers(h)
    assert any("body-only input" in f for f in r["findings"])
    assert r["score"] >= 20


def test_bcc_present_is_flagged():
    r = _analyze("From: a@ex.com\nTo: b@ex.com\nBcc: secret@g.com\n\nx")
    assert any("Bcc" in f and "stripped" in f for f in r["findings"])


def test_missing_to_is_flagged():
    r = _analyze("From: a@ex.com\nSubject: t\n\nx")
    assert any("No To recipients" in f for f in r["findings"])


def test_envelope_recipient_mismatch():
    r = _analyze("From: a@spoofed.tk\nTo: vict@corp.example\n"
                 "Envelope-To: helpdesk@corp.example\n\nx")
    assert any("Envelope recipient domain" in f for f in r["findings"])
    assert r["forensic_data"].get("envelope_recipient_mismatch") is True


def test_self_addressed_from_flagged():
    r = _analyze("From: a@ex.com\nTo: a@ex.com\n\nx")
    assert any("own From address" in f for f in r["findings"])


def test_sender_header_mismatch():
    r = _analyze("From: a@ex.com\nSender: b@other.net\nTo: c@ex.com\n\nx")
    assert any("'Sender' header" in f for f in r["findings"])


def test_duplicate_from_headers_detected():
    r = _analyze("From: a@ex.com\nFrom: b@evil.tk\nTo: c@ex.com\n\nx")
    assert any("Multiple From headers" in f for f in r["findings"])


def test_crlf_header_injection():
    headers = {
        "From": "a@ex.com\nTo: b@ex.com",
        "To": "b@ex.com",
        "Subject": "hi",
    }
    r = analyze_email_headers(headers)
    assert any("CRLF" in f or "line-break" in f for f in r["findings"])
    assert r["forensic_data"].get("header_injection") is True


def test_clean_email_low_score():
    r = _analyze("From: a@ex.com\nTo: b@ex.com\nReply-To: a@ex.com\n"
                 "Return-Path: <a@ex.com>\nMessage-ID: <x@ex.com>\n"
                 "Authentication-Results: spf=pass; dkim=pass; dmarc=pass\n\nx")
    assert r["score"] <= 10


def test_message_id_subdomain_not_flagged():
    r = _analyze("From: a@example.com\nTo: b@example.com\n"
                 "Message-ID: <x@mail.example.com>\n\nx")
    assert not any("Message-ID domain" in f for f in r["findings"])