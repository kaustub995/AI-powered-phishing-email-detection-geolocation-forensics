"""Tests for services/header_trust.py - origin trust model.

All GeoIP data is mocked; no real network calls.
"""

from services.header_trust import (
    assess_origin, classify_node, detect_header_anomalies, provider_from_text,
)

_GMAIL_GEO = {"ok": True, "isp": "Google LLC", "organization": "Google LLC",
              "asn": "AS15169 Google LLC", "hosting": True}
_HOSTING_GEO = {"ok": True, "isp": "OVH Hosting", "organization": "OVH SAS",
                "asn": "AS16276 OVH", "hosting": True}
_PUBLIC_GEO = {"ok": True, "isp": "Local ISP Co", "organization": "LocalNet",
               "asn": "AS64500 LocalNet", "hosting": False}


def test_provider_detected_from_isp_text():
    assert provider_from_text("Google LLC") == "Google/Gmail"
    assert provider_from_text("Outlook / Microsoft Corporation") == "Microsoft Outlook"
    assert provider_from_text("Yahoo!") == "Yahoo"
    assert provider_from_text("Random Residential ISP") is None


def test_public_non_provider_node_usable_for_origin():
    node = classify_node(_PUBLIC_GEO, {"is_public": True})
    assert node["usable_for_origin"] is True
    assert node["node_class"] == "public_other"


def test_provider_node_masks_origin():
    node = classify_node(_GMAIL_GEO, {"is_public": True})
    assert node["usable_for_origin"] is False
    assert node["node_class"] == "provider"
    assert "masks origin" in node["reason"] or "masked" in node["reason"]


def test_hosting_node_not_usable_for_origin():
    node = classify_node(_HOSTING_GEO, {"is_public": True})
    assert node["usable_for_origin"] is False
    assert node["node_class"] == "hosting"


def test_non_public_node_never_usable():
    node = classify_node(None, {"is_public": False})
    assert node["usable_for_origin"] is False


def test_assess_origin_attributed_to_earliest_reliable():
    extraction = {"ips": []}
    ip_results = [
        {"ip": "74.6.131.82", "is_public": True,
         "geo": _GMAIL_GEO, "sources": [{"header": "Received", "hop": 0}]},
        {"ip": "203.0.113.9", "is_public": True,
         "geo": _PUBLIC_GEO, "sources": [{"header": "Received", "hop": 2}]},
    ]
    out = assess_origin(extraction, ip_results)
    assert out["assessment"] == "attributed"
    assert out["earliest_reliable_ip"] == "203.0.113.9"


def test_assess_origin_provider_masked():
    extraction = {"ips": []}
    ip_results = [
        {"ip": "74.6.131.82", "is_public": True,
         "geo": _GMAIL_GEO, "sources": [{"header": "Received", "hop": 0}]},
    ]
    out = assess_origin(extraction, ip_results)
    assert out["assessment"] == "provider_masked"
    assert out["provider_masked"] is True
    assert "n't the sender's location" in out["summary"] or "NOT the sender's location" in out["summary"]


def test_assess_origin_hosting_only():
    extraction = {"ips": []}
    ip_results = [
        {"ip": "51.91.1.1", "is_public": True, "geo": _HOSTING_GEO,
         "sources": [{"header": "Received", "hop": 0}]},
    ]
    out = assess_origin(extraction, ip_results)
    assert out["assessment"] == "hosting_only"


def test_assess_origin_no_public_ip():
    out = assess_origin({"ips": []}, [
        {"ip": "10.0.0.5", "is_public": False, "sources": []}])
    assert out["assessment"] == "no_public_ip"


def test_detect_forged_chronology():
    # Invalid: the lower (older-origin) hop carries a LATER timestamp than the
    # hop above it - a fabricated relay line.
    email = (
        "Received: from mx-out-1 (mx [198.51.100.1]) by mx-in; "
        "Mon, 06 Sep 2026 09:00:00 +0000\n"
        "Received: from attacker (a [203.0.113.7]) by mx; "
        "Mon, 06 Sep 2026 09:30:00 +0000\n\nbody"
    )
    from services.ip_extractor import extract_ips_from_email
    extraction = extract_ips_from_email(email)
    findings = detect_header_anomalies(extraction)
    assert any("not chronological" in f for f in findings)


def test_detect_duplicate_received():
    line = ("Received: from fake (f [203.0.113.7]) by mx; "
            "Mon, 06 Sep 2026 08:00:00 +0000")
    email = line + "\n" + line + "\n\nbody"
    from services.ip_extractor import extract_ips_from_email
    extraction = extract_ips_from_email(email)
    findings = detect_header_anomalies(extraction)
    assert any("Duplicate Received" in f for f in findings)


def test_no_anomalies_for_clean_chain():
    email = (
        "Received: from mx-out-1 (mx [198.51.100.1]) by mx-in; "
        "Mon, 06 Sep 2026 09:00:00 +0000\n"
        "Received: from sender (s [203.0.113.7]) by mx; "
        "Mon, 06 Sep 2026 08:00:00 +0000\n\nbody"
    )
    from services.ip_extractor import extract_ips_from_email
    extraction = extract_ips_from_email(email)
    assert detect_header_anomalies(extraction) == []