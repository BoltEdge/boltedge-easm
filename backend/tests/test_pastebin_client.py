"""Tests for app.services.pastebin_client.

Mocks the HTTP layer (requests.get) and the DB layer
(PasteCache.query + db.session) so the tests run without a Flask app
context or a live database. Focus is on the failure modes:

  - PASTEBIN_FETCHER_ENABLED unset → no work
  - IP-not-whitelisted text response → return 0 with warning
  - HTTP timeout / 5xx → return 0
  - Malformed JSON → return 0
  - Body truncation at 64 KB
  - Dedupe via existing-keys lookup
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.services import pastebin_client as pc


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────


def _enabled():
    """Context manager that sets PASTEBIN_FETCHER_ENABLED=true."""
    return patch.dict("os.environ", {"PASTEBIN_FETCHER_ENABLED": "true"})


def _resp(*, status=200, text=None, json_payload=None):
    r = MagicMock()
    r.status_code = status
    r.text = text or ""
    if json_payload is not None:
        r.json.return_value = json_payload
    else:
        r.json.side_effect = ValueError("not json")
    return r


# ─────────────────────────────────────────────────────────────────────
# fetch_recent_pastes_and_upsert
# ─────────────────────────────────────────────────────────────────────


def test_fetcher_skips_when_flag_unset():
    # No PASTEBIN_FETCHER_ENABLED in env → short-circuit
    with patch.dict("os.environ", {}, clear=False):
        # Make sure the flag really isn't set during this test
        import os
        os.environ.pop("PASTEBIN_FETCHER_ENABLED", None)
        assert pc.fetch_recent_pastes_and_upsert() == 0


def test_fetcher_ip_not_whitelisted_returns_zero():
    """The non-PRO / non-whitelisted response is a plain-text body
    containing 'DOES NOT HAVE ACCESS'."""
    with _enabled(), \
         patch.object(pc.requests, "get") as mock_get:
        mock_get.return_value = _resp(
            status=200,
            text="YOUR IP: 1.2.3.4 DOES NOT HAVE ACCESS. Visit https://pastebin.com/pro to upgrade.",
        )
        n = pc.fetch_recent_pastes_and_upsert()
    assert n == 0


def test_fetcher_returns_zero_on_http_failure():
    with _enabled(), patch.object(pc.requests, "get") as mock_get:
        mock_get.side_effect = pc.requests.RequestException("connection refused")
        n = pc.fetch_recent_pastes_and_upsert()
    assert n == 0


def test_fetcher_returns_zero_on_non_200():
    with _enabled(), patch.object(pc.requests, "get") as mock_get:
        mock_get.return_value = _resp(status=503, text="bad gateway")
        n = pc.fetch_recent_pastes_and_upsert()
    assert n == 0


def test_fetcher_returns_zero_on_non_array_payload():
    with _enabled(), patch.object(pc.requests, "get") as mock_get:
        mock_get.return_value = _resp(status=200, json_payload={"unexpected": "shape"})
        n = pc.fetch_recent_pastes_and_upsert()
    assert n == 0


def test_fetcher_returns_zero_on_malformed_json():
    with _enabled(), patch.object(pc.requests, "get") as mock_get:
        mock_get.return_value = _resp(status=200, text="not json")
        n = pc.fetch_recent_pastes_and_upsert()
    assert n == 0


def test_fetcher_upserts_new_pastes():
    """Two pastes returned by the list endpoint; one is already known
    so we only ingest the new one."""
    listing = [
        {"key": "AAA111", "title": "first", "user": "alice",
         "syntax": "text", "size": 100, "date": "1700000000",
         "scrape_url": "https://scrape.pastebin.com/AAA111",
         "full_url": "https://pastebin.com/AAA111"},
        {"key": "BBB222", "title": "second", "user": "bob",
         "syntax": "python", "size": 200, "date": "1700000001"},
    ]
    list_response = _resp(status=200, json_payload=listing)
    body_response_aaa = _resp(status=200, text="hello world AAA")
    body_response_bbb = _resp(status=200, text="goodbye BBB")

    def fake_get(url, **kwargs):
        if url == pc.PASTEBIN_SCRAPE_URL:
            return list_response
        params = kwargs.get("params") or {}
        key = params.get("i")
        if key == "AAA111":
            return body_response_aaa
        if key == "BBB222":
            return body_response_bbb
        return _resp(status=404, text="missing")

    saved_rows = []

    def fake_save(row):
        saved_rows.append(row)
        return True

    with _enabled(), \
         patch.object(pc.requests, "get", side_effect=fake_get), \
         patch.object(pc, "_query_existing_keys", return_value={"AAA111"}), \
         patch.object(pc, "_save_paste", side_effect=fake_save):
        n = pc.fetch_recent_pastes_and_upsert()

    assert n == 1  # only BBB222 was new
    assert len(saved_rows) == 1
    assert saved_rows[0].paste_key == "BBB222"
    assert saved_rows[0].author == "bob"
    assert saved_rows[0].body == "goodbye BBB"


def test_fetcher_truncates_oversized_body():
    listing = [{"key": "BIG001", "title": "huge", "user": "x",
                "syntax": "text", "size": 999999, "date": "1700000000"}]
    huge_body = "A" * (pc.MAX_BODY_BYTES + 5000)

    def fake_get(url, **kwargs):
        if url == pc.PASTEBIN_SCRAPE_URL:
            return _resp(status=200, json_payload=listing)
        return _resp(status=200, text=huge_body)

    saved_rows = []

    with _enabled(), \
         patch.object(pc.requests, "get", side_effect=fake_get), \
         patch.object(pc, "_query_existing_keys", return_value=set()), \
         patch.object(pc, "_save_paste", side_effect=lambda r: saved_rows.append(r) or True):
        n = pc.fetch_recent_pastes_and_upsert()

    assert n == 1
    # Body truncated to MAX_BODY_BYTES chars
    assert len(saved_rows[0].body) == pc.MAX_BODY_BYTES


def test_fetcher_skips_paste_when_body_fetch_fails():
    listing = [{"key": "FAIL01", "title": "x", "user": "y",
                "syntax": "text", "size": 10, "date": "1700000000"}]

    def fake_get(url, **kwargs):
        if url == pc.PASTEBIN_SCRAPE_URL:
            return _resp(status=200, json_payload=listing)
        raise pc.requests.RequestException("body timeout")

    saved_rows = []

    with _enabled(), \
         patch.object(pc.requests, "get", side_effect=fake_get), \
         patch.object(pc, "_query_existing_keys", return_value=set()), \
         patch.object(pc, "_save_paste", side_effect=lambda r: saved_rows.append(r) or True):
        n = pc.fetch_recent_pastes_and_upsert()

    assert n == 0
    assert saved_rows == []


# ─────────────────────────────────────────────────────────────────────
# match_pastes_for_domain
# ─────────────────────────────────────────────────────────────────────


def test_match_returns_empty_on_blank_domain():
    assert pc.match_pastes_for_domain("") == []


def test_match_returns_empty_on_db_error():
    with patch.object(pc, "_query_pastes_by_domain", side_effect=RuntimeError("db down")):
        assert pc.match_pastes_for_domain("example.com") == []


def test_match_returns_payload_shape():
    row = MagicMock(
        paste_key="ZZZ999",
        paste_url="https://pastebin.com/ZZZ999",
        title="creds",
        author="leaker",
        syntax="text",
        size_bytes=200,
        body=(
            "preamble " * 20
            + "credentials leaked for example.com here "
            + "trailing " * 30
        ),
        date_pasted=datetime(2026, 5, 13, tzinfo=timezone.utc),
    )
    with patch.object(pc, "_query_pastes_by_domain", return_value=[row]):
        results = pc.match_pastes_for_domain("example.com")
    assert len(results) == 1
    r = results[0]
    assert r["paste_key"] == "ZZZ999"
    assert "example.com" in r["snippet"]
    assert r["date_pasted"].startswith("2026-05-13")


# ─────────────────────────────────────────────────────────────────────
# _extract_snippet
# ─────────────────────────────────────────────────────────────────────


def test_snippet_centred_on_match():
    body = "x" * 200 + "FOUND" + "y" * 200
    out = pc._extract_snippet(body, "FOUND", window=100)
    assert "FOUND" in out
    # Should include ellipses since we trimmed both ends
    assert "…" in out


def test_snippet_no_match_returns_prefix():
    body = "no match here"
    out = pc._extract_snippet(body, "MISSING", window=100)
    assert out == "no match here"


def test_snippet_empty_body():
    assert pc._extract_snippet("", "anything") == ""
