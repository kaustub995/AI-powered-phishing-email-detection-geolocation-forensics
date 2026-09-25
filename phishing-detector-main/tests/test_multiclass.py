"""Tests for utils/multiclass.py and utils/lookalike.py."""

from utils.lookalike import (
    extract_domain_name, flag_lookalike_domains, lookalike_risk,
)
from utils.multiclass import classify_email


# ── Lookalike ────────────────────────────────────────────────────────────────

def test_lookalike_paypal():
    r = lookalike_risk("paypa1.com")
    assert r["is_lookalike"] is True
    assert r["matched_brand"] == "paypal"


def test_lookalike_digit_substitution():
    r = lookalike_risk("micr0s0ft-login.co")
    assert r["is_lookalike"] is True
    assert r["homoglyph_detected"] is True or r["edit_distance_detected"] is True


def test_legitimate_domain_not_flagged():
    r = lookalike_risk("paypal.com")
    assert r["is_lookalike"] is False


def test_extract_domain_name():
    assert extract_domain_name("http://www.evil.tk/login") == "evil"
    assert extract_domain_name("paypa1.com") == "paypa1"
    assert extract_domain_name("") == ""


def test_flag_lookalike_domains_filters():
    hits = flag_lookalike_domains(
        ["https://paypa1.com/login", "https://amazon.com/prime"])
    assert len(hits) == 1
    assert hits[0]["brand"] == "paypal"


# ── Five-class classifier ────────────────────────────────────────────────────

def test_legitimate_when_clean():
    out = classify_email(rule_score=5,
                         ml_result={"label": "safe", "confidence": 0.9},
                         soceng={"overall_risk": 5, "primary_attack": None})
    assert out["class"] == "legitimate"


def test_phishing_on_high_rule_score():
    out = classify_email(rule_score=80,
                         ml_result={"label": "phishing", "confidence": 0.9},
                         soceng={"primary_attack": {"id": "phishing", "name": "Phishing"},
                                 "overall_risk": 85})
    assert out["class"] == "phishing"
    assert out["priority"] == "high"


def test_fraud_for_ceo_fraud_bec():
    soceng = {"primary_attack": {"id": "ceo_fraud", "name": "CEO Fraud"},
              "overall_risk": 70}
    out = classify_email(rule_score=40, soceng=soceng,
                         forensic={"findings": [], "forensic_data": {}})
    assert out["class"] == "fraud"
    assert out["priority"] == "critical"


def test_impersonated_on_spoofing():
    soceng = {"primary_attack": {"id": "pretexting", "name": "Pretexting"},
              "overall_risk": 50}
    forensic = {"findings": ["🔴 Display name contains 'paypal' but sender "
                             "domain is 'x.com' — possible spoofing"]}
    out = classify_email(rule_score=45, soceng=soceng, forensic=forensic)
    assert out["class"] == "impersonated"


def test_impersonated_on_lookalike_link():
    out = classify_email(
        rule_score=50,
        soceng={"primary_attack": {"id": "spear_phishing", "name": "Spear"},
                "overall_risk": 40},
        urls=["https://secure-paypa1.com/login"],
    )
    assert out["class"] == "impersonated"


def test_suspicious_on_ambiguous():
    out = classify_email(rule_score=30, ml_result=None, soceng={"overall_risk": 15})
    assert out["class"] == "suspicious"


def test_from_and_domain_extracted_from_forensic():
    forensic = {"forensic_data": {"from_email": "bob@company.com",
                                  "sender_domain": "company.com"}}
    out = classify_email(rule_score=5, soceng={"overall_risk": 5}, forensic=forensic)
    assert out["from_email"] == "bob@company.com"
    assert out["sender_domain"] == "company.com"


def test_reasons_are_present_for_phishing():
    out = classify_email(rule_score=75,
                         ml_result={"label": "phishing", "confidence": 0.85},
                         soceng={"primary_attack": {"id": "phishing", "name": "Phishing"},
                                 "overall_risk": 90})
    assert len(out["reasons"]) >= 1