"""Tests for app.services.ct_log_monitor.

Mocks the requests.get layer and the DB indirection helpers. No app
context or live DB needed.
"""
from unittest.mock import MagicMock, patch

import pytest

from app.services import ct_log_monitor as ctlm


def _resp(*, status=200, json_payload=None):
    r = MagicMock()
    r.status_code = status
    if json_payload is not None:
        r.json.return_value = json_payload
    else:
        r.json.side_effect = ValueError("not json")
    return r


# ─────────────────────────────────────────────────────────────────────
# Brand keyword extraction
# ─────────────────────────────────────────────────────────────────────


def test_extract_brand_keyword_simple():
    assert ctlm.extract_brand_keyword("nanoeasm.com") == "nanoeasm"


def test_extract_brand_keyword_with_hyphen():
    assert ctlm.extract_brand_keyword("my-company.io") == "my-company"


def test_extract_brand_keyword_strips_wildcard():
    assert ctlm.extract_brand_keyword("*.nanoeasm.com") == "nanoeasm"


def test_extract_brand_keyword_empty_input():
    assert ctlm.extract_brand_keyword("") is None
    assert ctlm.extract_brand_keyword(None) is None


# ─────────────────────────────────────────────────────────────────────
# Hostname sanitisation
# ─────────────────────────────────────────────────────────────────────


def test_sanitize_hostname_strips_wildcard():
    assert ctlm._sanitize_hostname("*.nanoeasm.com") == "nanoeasm.com"


def test_sanitize_hostname_lowercases():
    assert ctlm._sanitize_hostname("NanoEASM.COM") == "nanoeasm.com"


def test_sanitize_hostname_rejects_garbage():
    assert ctlm._sanitize_hostname("") is None
    assert ctlm._sanitize_hostname("not a hostname") is None


# ─────────────────────────────────────────────────────────────────────
# crt.sh fetch
# ─────────────────────────────────────────────────────────────────────


def test_fetch_returns_empty_on_http_failure():
    with patch.object(ctlm.requests, "get") as mock_get:
        mock_get.side_effect = ctlm.requests.RequestException("timeout")
        rows = ctlm._fetch_crtsh("nanoeasm")
    assert rows == []


def test_fetch_returns_empty_on_non_200():
    with patch.object(ctlm.requests, "get") as mock_get:
        mock_get.return_value = _resp(status=503)
        rows = ctlm._fetch_crtsh("nanoeasm")
    assert rows == []


def test_fetch_returns_empty_on_malformed_json():
    with patch.object(ctlm.requests, "get") as mock_get:
        mock_get.return_value = _resp(status=200, json_payload=None)
        rows = ctlm._fetch_crtsh("nanoeasm")
    assert rows == []


def test_fetch_returns_rows_on_success():
    payload = [
        {"id": 1, "name_value": "nanoeasm.co\nfoo.nanoeasm.co"},
        {"id": 2, "name_value": "completely-unrelated.com"},
    ]
    with patch.object(ctlm.requests, "get") as mock_get:
        mock_get.return_value = _resp(status=200, json_payload=payload)
        rows = ctlm._fetch_crtsh("nanoeasm")
    assert len(rows) == 2


# ─────────────────────────────────────────────────────────────────────
# Polling logic — full path through filter / dedup / insert
# ─────────────────────────────────────────────────────────────────────


def test_poll_only_inserts_hostnames_matching_keyword():
    """A response containing both keyword-matching and non-matching SANs
    should only insert the matching hostnames into the queue."""
    payload = [
        {
            "id": "100",
            "name_value": "nanoeasm.co\nnanoeasm.io",
            "entry_timestamp": "2026-05-14T12:00:00",
        },
        {
            "id": "101",
            "name_value": "completely-unrelated.com",  # no 'nanoeasm' substring
            "entry_timestamp": "2026-05-14T12:01:00",
        },
    ]
    captured_batches = []

    def fake_insert(batch, *, now, expires_at):
        captured_batches.append(batch)
        return len(batch)

    with patch.object(ctlm.requests, "get") as mock_get, \
         patch.object(ctlm, "_insert_candidates", side_effect=fake_insert):
        mock_get.return_value = _resp(status=200, json_payload=payload)
        n = ctlm.poll_brand_keywords(["nanoeasm"])

    assert n == 2
    assert len(captured_batches) == 1
    inserted_hosts = {row[1] for row in captured_batches[0]}
    assert inserted_hosts == {"nanoeasm.co", "nanoeasm.io"}
    assert "completely-unrelated.com" not in inserted_hosts


def test_poll_dedupes_within_cycle():
    """The same (cert_id, hostname) pair appearing twice in one response
    should only be inserted once."""
    payload = [
        {"id": "100", "name_value": "nanoeasm.co\nnanoeasm.co"},
    ]
    captured_batches = []

    def fake_insert(batch, *, now, expires_at):
        captured_batches.append(batch)
        return len(batch)

    with patch.object(ctlm.requests, "get") as mock_get, \
         patch.object(ctlm, "_insert_candidates", side_effect=fake_insert):
        mock_get.return_value = _resp(status=200, json_payload=payload)
        ctlm.poll_brand_keywords(["nanoeasm"])

    assert len(captured_batches[0]) == 1


def test_poll_caps_at_per_keyword_limit():
    """A response with 1000 matching certs should only insert up to
    PER_KEYWORD_CANDIDATE_CAP (50)."""
    payload = [
        {"id": str(i), "name_value": f"nanoeasm{i}.com"}
        for i in range(1000)
    ]
    captured_batches = []

    def fake_insert(batch, *, now, expires_at):
        captured_batches.append(batch)
        return len(batch)

    with patch.object(ctlm.requests, "get") as mock_get, \
         patch.object(ctlm, "_insert_candidates", side_effect=fake_insert):
        mock_get.return_value = _resp(status=200, json_payload=payload)
        ctlm.poll_brand_keywords(["nanoeasm"])

    assert len(captured_batches[0]) == ctlm.PER_KEYWORD_CANDIDATE_CAP


def test_poll_empty_keywords_returns_zero():
    assert ctlm.poll_brand_keywords([]) == 0
    assert ctlm.poll_brand_keywords([""]) == 0


def test_poll_handles_keyword_with_zero_matches():
    with patch.object(ctlm.requests, "get") as mock_get, \
         patch.object(ctlm, "_insert_candidates") as mock_insert:
        mock_get.return_value = _resp(status=200, json_payload=[])
        n = ctlm.poll_brand_keywords(["nonexistent"])
    assert n == 0
    mock_insert.assert_not_called()
