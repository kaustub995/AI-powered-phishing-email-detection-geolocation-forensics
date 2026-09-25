"""Tests for live SPF/DKIM/DMARC verification (all DNS mocked - no network)."""

from services import auth_validation as av


# ─── Organizational-domain alignment ─────────────────────────────────────────

def test_organizational_domain_default_two_labels():
    assert av.organizational_domain("mail.example.com") == "example.com"


def test_organizational_domain_multi_label_tld():
    assert av.organizational_domain("a.b.example.co.uk") == "example.co.uk"


def test_organizational_domain_idempotent():
    assert av.organizational_domain("example.org") == "example.org"


# ─── DMARC parsing ───────────────────────────────────────────────────────────

def test_parse_dmarc_record():
    rec = av._parse_dmarc_record("v=DMARC1; p=reject; rua=mailto:dmarc@ex.com;")
    assert rec["policy"] == "reject"
    assert rec["report_uri"] == "mailto:dmarc@ex.com"


def test_parse_dmarc_record_defaults():
    rec = av._parse_dmarc_record("v=DMARC1; p=none")
    assert rec["pct"] == 100
    assert rec["alignment_spf"] == "r"


# ─── SPF ─────────────────────────────────────────────────────────────────────

class _FakeSPF:
    def __init__(self, outcome):
        self._outcome = outcome

    def check2(self, i=None, s=None, h=None):
        return self._outcome


def test_validate_spf_pass(monkeypatch):
    monkeypatch.setattr(av, "_spf", _FakeSPF(("pass", "mx")))
    res = av.validate_spf("203.0.113.9", "mailer@example.com")
    assert res["ok"] and res["verified"] is True and res["result"] == "pass"


def test_validate_spf_fail(monkeypatch):
    monkeypatch.setattr(av, "_spf", _FakeSPF(("fail", "-all")))
    res = av.validate_spf("203.0.113.9", "attacker@evil.tk")
    assert res["ok"] and res["verified"] is False and res["result"] == "fail"


def test_validate_spf_unavailable_when_missing_client():
    res = av.validate_spf("", "a@example.com")
    assert res["ok"] is False and res["verified"] is None


def test_validate_spf_error_tolerated(monkeypatch):
    class Boom:
        def check2(self, **kwargs):
            raise RuntimeError("dns down")
    monkeypatch.setattr(av, "_spf", Boom())
    res = av.validate_spf("203.0.113.9", "a@example.com")
    assert res["ok"] is False and res["result"] == "temperror"


# ─── DKIM ────────────────────────────────────────────────────────────────────

def test_dkim_signature_parsing():
    raw = (
        b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel1; c=relaxed/simple;\r\n"
        b"\t b=abc;\r\n"
        b"From: a@example.com\r\n\r\nbody")
    sigs = av._dkim_signatures(raw)
    assert sigs and sigs[0]["domain"] == "example.com"
    assert sigs[0]["selector"] == "sel1"


def test_dkim_verify_fails_for_unsigned_message():
    res = av.validate_dkim(b"From: x@y.z\r\n\r\nno signature at all")
    assert res["ok"]
    assert res["verified"] is False


def test_dkim_unavailable_when_no_bytes():
    res = av.validate_dkim(b"")
    assert res["ok"] is False


# ─── DMARC evaluation ────────────────────────────────────────────────────────

def test_dmarc_no_record(monkeypatch):
    monkeypatch.setattr(av, "resolve_txt", lambda d: ["v=spf1 -all"])
    res = av.validate_dmarc("example.com")
    assert res["outcome"] == "no_record" and res["pass"] is None


def test_dmarc_reject_with_aligned_spf(monkeypatch):
    monkeypatch.setattr(av, "resolve_txt", lambda d: [
        "v=DMARC1; p=reject; aspf=r"])
    spf = {"verified": True, "result": "pass"}
    res = av.validate_dmarc("victim.com", spf_result=spf,
                            spf_envelope_domain="victim.com")
    assert res["pass"] is True and res["outcome"] == "pass"


def test_dmarc_reject_with_unaligned_dkim(monkeypatch):
    monkeypatch.setattr(av, "resolve_txt", lambda d: [
        "v=DMARC1; p=reject"])
    spf = {"verified": False, "result": "fail"}
    res = av.validate_dmarc("victim.com", spf_result=spf,
                            dkim_verified=False,
                            dkim_domain="attacker.io",
                            spf_envelope_domain="attacker.io")
    assert res["pass"] is False and res["outcome"] == "fail_reject"


def test_dmarc_monitor_when_policy_none(monkeypatch):
    monkeypatch.setattr(av, "resolve_txt", lambda d: ["v=DMARC1; p=none"])
    spf = {"verified": False, "result": "fail"}
    res = av.validate_dmarc("victim.com", spf_result=spf,
                            spf_envelope_domain="spoofed.io")
    assert res["outcome"] == "fail_monitor"


# ─── End-to-end aggregate ────────────────────────────────────────────────────

def test_authenticate_full_pass(monkeypatch):
    monkeypatch.setattr(av, "validate_spf", lambda ip, s: {
        "verified": True, "result": "pass", "ok": True})
    monkeypatch.setattr(av, "validate_dkim", lambda raw: {
        "verified": True, "ok": True, "signatures": [
            {"domain": "example.com", "selector": "s1", "raw": ""}]})
    monkeypatch.setattr(av, "validate_dmarc",
                        lambda *a, **k: {"pass": True, "outcome": "pass",
                                         "policy": "reject",
                                         "explanation": "ok", "ok": True})
    res = av.authenticate_email(
        raw="From: CEO <ceo@example.com>\nReturn-Path: b@example.com\n\nhi",
        client_ip="203.0.113.7")
    assert res["overall"] == "pass"
    assert res["passed"]["spf"] and res["passed"]["dmarc"]


def test_authenticate_spoofed_fails(monkeypatch):
    monkeypatch.setattr(av, "validate_spf", lambda ip, s: {
        "verified": False, "result": "fail", "ok": True})
    monkeypatch.setattr(av, "validate_dkim", lambda raw: {
        "verified": False, "ok": True, "signatures": [
            {"domain": "evil.tk", "selector": "s", "raw": ""}]})
    monkeypatch.setattr(av, "validate_dmarc",
                        lambda *a, **k: {"pass": False,
                                         "outcome": "fail_quarantine",
                                         "policy": "quarantine",
                                         "explanation": "x", "ok": True})
    res = av.authenticate_email(
        raw="From: CEO <ceo@victim.com>\nReturn-Path: b@evil.tk\n\nhi",
        client_ip="203.0.113.7")
    assert res["overall"] == "fail"
    assert res["from_domain"] == "victim.com"
    assert res["envelope_domain"] == "evil.tk"
    assert res["dmarc"]["outcome"] == "fail_quarantine"


def test_authenticate_library_missing_degrades():
    library_status = av.library_status()
    assert set(library_status) >= {"spf", "dkim", "dns"}
    assert isinstance(library_status["spf"], bool)