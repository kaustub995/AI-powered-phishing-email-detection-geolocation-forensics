"""Tests for graph/threat_graph.py - NetworkX threat graph model."""

import networkx as nx

from graph.threat_graph import ThreatGraph, extract_domain


def test_typed_nodes_and_no_duplicates():
    g = ThreatGraph()
    g.add_email("e1")
    g.add_email("e1")  # duplicate - must not add
    g.add_ip("8.8.8.8", country="US")
    g.add_ip("8.8.8.8")  # duplicate
    assert g.node_count("EMAIL") == 1
    assert g.node_count("IP") == 1
    assert g.node_count() == 2


def test_relations():
    g = ThreatGraph()
    g.add_email_contains_url("e1", "http://evil.tk/login")
    g.add_url_belongs_to_domain("http://evil.tk/login", "evil.tk")
    g.add_domain_resolves_to_ip("evil.tk", "1.2.3.4")
    g.add_email_received_from_ip("e1", "1.2.3.4", risk_level="high")

    attrs = {
        (u, v, d["rel"]) for u, v, d in g.graph.edges(data=True)
    }
    assert ("EMAIL:e1", "URL:http://evil.tk/login", "contains") in attrs
    assert ("URL:http://evil.tk/login", "DOMAIN:evil.tk", "belongs_to") in attrs
    assert ("DOMAIN:evil.tk", "IP:1.2.3.4", "resolves_to") in attrs
    assert ("EMAIL:e1", "IP:1.2.3.4", "received_from") in attrs

    # IP node carries geo/risk attributes.
    assert g.graph.nodes["IP:1.2.3.4"]["risk_level"] == "high"


def test_relation_edges_are_not_duplicated():
    g = ThreatGraph()
    g.add_email_received_from_ip("e1", "1.2.3.4")
    g.add_email_received_from_ip("e1", "1.2.3.4")
    assert g.graph.number_of_edges() == 1


def test_build_from_ip_intel():
    g = ThreatGraph()
    ip_results = [
        {"ip": "1.2.3.4", "is_public": True, "risk_level": "high",
         "geo": {"country": "Russia", "city": "Moscow", "isp": "X",
                 "asn": "AS1", "reputation": {"score": 90, "markers": ["malicious"]}}},
    ]
    g.build_from_ip_intel("e1", ip_results, urls=["http://evil.tk/login"])
    summary = g.summary()
    assert summary["by_type"]["EMAIL"] == 1
    assert summary["by_type"]["URL"] == 1
    assert summary["by_type"]["DOMAIN"] == 1
    assert summary["by_type"]["IP"] == 1
    assert summary["relations"]["contains"] == 1
    assert summary["relations"]["belongs_to"] == 1
    assert summary["relations"]["received_from"] == 1
    assert g.graph.nodes["IP:1.2.3.4"]["country"] == "Russia"
    assert g.graph.nodes["IP:1.2.3.4"]["reputation"] == 90


def test_cytoscape_serialization():
    g = ThreatGraph()
    g.add_email("e1")
    g.add_ip("1.2.3.4", risk_level="high")
    g.add_email_received_from_ip("e1", "1.2.3.4")
    elements = g.to_cytoscape_elements()
    ids = [el["data"]["id"] for el in elements if "id" in el["data"]]
    assert "EMAIL:e1" in ids
    assert "IP:1.2.3.4" in ids
    assert any(el["data"].get("relation") == "received_from" for el in elements)


def test_extract_domain():
    assert extract_domain("http://www.evil.tk/login") == "evil.tk"
    assert extract_domain("https://secure-banking.com/a?x=1") == "secure-banking.com"
    assert extract_domain("mail.example.com") == "mail.example.com"
    assert extract_domain("") == ""