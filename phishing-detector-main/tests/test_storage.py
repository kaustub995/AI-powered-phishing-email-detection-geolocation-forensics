"""Tests for storage case/campaign store and compliance layer (SQLite temp files)."""

import tempfile

from storage.case_store import CaseStore, extract_indicators, sha256_hex
from storage.compliance import (
    ChainOfCustodyLogger, mask_pii, purge_older_than,
)


def test_sha256_deterministic():
    assert sha256_hex("abc") == sha256_hex("abc")
    assert sha256_hex("abc") != sha256_hex("abd")


def test_extract_indicators():
    inds = extract_indicators(from_email="bob@evil.tk",
                              sender_domain="evil.tk",
                              urls=["https://evil.tk/login"],
                              ips=["1.2.3.4", "185.220.101.34"])
    kinds = [i[0] for i in inds]
    assert "email" in kinds and "domain" in kinds and "ip" in kinds and "url" in kinds


def test_store_and_retrieve(tmp_path):
    store = CaseStore(str(tmp_path / "cases.db"))
    rec = store.store_email(
        email_id="<x@test>",
        verdict_class="phishing",
        verdict_priority="high",
        combined_score=87,
        ip_risk="high",
        from_email="attacker@evil.tk",
        sender_domain="evil.tk",
        subject="URGENT invoice",
        urls=["https://paypa1.com/login"],
        ips=["185.220.101.34"],
        raw_headers="Received: from x",
        body_text="click here: victim@corp.com call 555-123-4567",
    )
    assert rec["campaign_id"].startswith("cmp-")
    emails = store.list_emails()
    assert len(emails) == 1
    # PII must have been masked in the stored body.
    row = store._conn_checked().execute(
        "SELECT body_masked FROM emails WHERE email_id = ?", ("<x@test>",)).fetchone()
    assert "[REDACTED_EMAIL]" in row["body_masked"]
    assert "victim@corp.com" not in row["body_masked"]


def test_campaign_grouping_shared_domain(tmp_path):
    store = CaseStore(str(tmp_path / "cases.db"))
    store.store_email(email_id="e1", from_email="a@evil.tk", sender_domain="evil.tk",
                      urls=["https://evil.tk/1"])
    store.store_email(email_id="e2", from_email="b@evil.tk", sender_domain="evil.tk",
                      urls=["https://evil.tk/2"])
    store.store_email(email_id="e3", from_email="c@good.com", sender_domain="good.com",
                      urls=["https://good.com"])
    campaigns = store.get_campaigns()
    assert len(campaigns) >= 1
    top = max(campaigns, key=lambda c: c["email_count"])
    assert top["email_count"] >= 2  # e1 + e2 grouped, e3 separate


def test_search(tmp_path):
    store = CaseStore(str(tmp_path / "cases.db"))
    store.store_email(email_id="e1", from_email="nobody@evil.tk",
                      sender_domain="evil.tk", subject="Invoice #12")
    hits = store.search("Invoice")
    assert len(hits) >= 1
    assert "Invoice" in hits[0]["subject"]


def test_chain_of_custody_verify_intact_and_tamper(tmp_path):
    db = str(tmp_path / "coc.db")
    coc = ChainOfCustodyLogger(db, secret="test-secret")
    coc.log("analyst-1", "analyzed", "email=<a>")
    coc.log("analyst-1", "alerted", "email=<a>")
    assert coc.verify()["intact"] is True

    # Tamper with a historical detail -> verify must flag it.
    coc._conn.execute("UPDATE custody_chain SET detail='tampered' WHERE id=1")
    coc._conn.commit()
    report = coc.verify()
    assert report["intact"] is False
    assert any(issue[1] in ("hash_mismatch", "sig_mismatch") for issue in report["issues"])


def test_mask_pii():
    out = mask_pii("Call john.doe@corp.com at 555-123-4567 card 4111111111111111 ssn 123-45-6789")
    assert "[REDACTED_EMAIL]" in out
    assert "[REDACTED_PHONE]" in out
    assert "[REDACTED_CARD]" in out
    assert "[REDACTED_SSN]" in out
    assert "john.doe@corp.com" not in out


def test_purge_older_than_dry_run(tmp_path):
    import time
    store = CaseStore(str(tmp_path / "cases.db"))
    store.store_email(email_id="old", from_email="a@b.tk", sender_domain="b.tk")
    # Backdate the stored_at column.
    old_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 400 * 86400))
    store._conn_checked().execute("UPDATE emails SET stored_at = ? WHERE email_id = 'old'",
                                  (old_ts,))
    store._conn_checked().commit()
    report = purge_older_than(str(tmp_path / "cases.db"), days=90, dry_run=True)
    assert report["purged"] == 1
    report2 = purge_older_than(str(tmp_path / "cases.db"), days=90, dry_run=False)
    assert report2["purged"] == 1
    assert store.list_emails() == []