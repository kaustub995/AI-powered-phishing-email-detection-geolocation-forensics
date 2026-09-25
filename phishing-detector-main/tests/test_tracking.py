"""Tests for the active-tracking module (store + URL building, no network)."""

import os

from tracking.tracker import (PIXEL_GIF, TrackerStore, base_url,
                              embed_html, mint_email_token, open_url,
                              redirect_url)


def test_store_mint_and_get(tmp_path):
    store = TrackerStore(path=str(tmp_path / "track.db"))
    tok = store.mint("e1", "c1")
    meta = store.get(tok)
    assert meta["email_id"] == "e1" and meta["campaign_id"] == "c1"


def test_store_roundtrip_events(tmp_path):
    store = TrackerStore(path=str(tmp_path / "track.db"))
    tok = store.mint("e1", "c1")
    store.log_event(tok, "open", ip="203.0.113.5",
                    user_agent="Chrome", enrichment={"reverse": "x.example"})
    store.log_event(tok, "click", ip="203.0.113.5")
    events = store.events(tok)
    assert len(events) == 2
    assert events[0]["kind"] == "open"
    assert events[0]["enrichment"].startswith("{")

    hits = store.hits()
    assert len(hits) == 2
    assert hits[0]["email_id"] == "e1"


def test_unknown_token_returns_none(tmp_path):
    store = TrackerStore(path=str(tmp_path / "track.db"))
    assert store.get("deadbeef") is None


def test_pixel_bytes_are_valid_gif():
    assert PIXEL_GIF.startswith(b"GIF89a")
    assert len(PIXEL_GIF) > 30


def test_open_url_and_redirect_url(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACKING_BASE_URL", "http://trk.example")
    assert base_url() == "http://trk.example"
    url = open_url("a" * 32)
    assert url == "http://trk.example/track/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/pixel.gif"
    click = redirect_url("a" * 32, "https://evil.io/x?a=1")
    assert click.startswith("http://trk.example/redir/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?u=")
    assert "evil.io%2Fx%3Fa%3D1" in click


def test_embed_html_uses_absolute_urls():
    html = embed_html("b" * 32, "https://c.example")
    assert "&lt;img" not in html and "<img src=" in html
    assert "/track/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/pixel.gif" in html
    assert "/redir/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" in html


def test_mint_helper_default_store(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACKING_DB_PATH", str(tmp_path / "t.db"))
    tok = mint_email_token("e1", "c1")
    assert len(tok) == 32
    assert os.path.exists(str(tmp_path / "t.db"))