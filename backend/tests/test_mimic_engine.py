"""Tests for app.scanner.engines.mimic_engine.

The engine orchestrates the matcher: gate checks, candidate gathering
from two sources, dedupe, per-candidate matcher dispatch, processed-row
bookkeeping. Signal computation (page_signals) and rendering
(page_renderer) are covered separately — those are mocked here.

What's covered:
  - MIMIC_ENABLED off → skipped_reason='mimic_disabled', no work
  - asset not found → success=False, skipped_reason='asset_not_found'
  - lookalike_watch off → skipped_reason='lookalike_watch_off'
  - missing baseline → skipped_reason='no_baseline', needs_baseline=True
  - empty brand keyword → skipped_reason='no_brand_keyword'
  - empty candidates → skipped_reason='no_candidates'
  - lookalike hits filtered to live HTTP only
  - dedupe by hostname (lookalike + ct_log candidates merged)
  - self-match guard (candidate hostname == asset.value)
  - per-candidate matcher crash → mark_processed='matcher_crash', continue
  - CT log queue read failure → ct_rows=[], continue with lookalike-only
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.engines import mimic_engine as me


def _ctx(asset_id=1, asset_value="example.com", org_id=1):
    """Build a minimal ScanContext stand-in."""
    ctx = SimpleNamespace(
        asset_id=asset_id,
        asset_value=asset_value,
        organization_id=org_id,
    )
    ctx.get_engine_data = MagicMock(return_value={})
    return ctx


def _config():
    return {}


def _enabled():
    import os
    return patch.dict(os.environ, {"MIMIC_ENABLED": "true"}, clear=False)


# ─────────────────────────────────────────────────────────────────────
# Gate checks
# ─────────────────────────────────────────────────────────────────────


def test_engine_skips_when_mimic_disabled(monkeypatch):
    monkeypatch.delenv("MIMIC_ENABLED", raising=False)
    engine = me.MimicEngine()
    result = engine.execute(_ctx(), _config())
    assert result.data["skipped_reason"] == "mimic_disabled"
    assert result.data["matches"] == []


def test_engine_marks_failure_when_asset_not_found():
    with _enabled(), patch("app.extensions.db") as mock_db:
        mock_db.session.get.return_value = None
        engine = me.MimicEngine()
        result = engine.execute(_ctx(), _config())
    assert result.success is False
    assert result.data["skipped_reason"] == "asset_not_found"


def test_engine_skips_when_lookalike_watch_off():
    asset = SimpleNamespace(id=1, value="example.com", lookalike_watch=False)
    with _enabled(), patch("app.extensions.db") as mock_db:
        mock_db.session.get.return_value = asset
        engine = me.MimicEngine()
        result = engine.execute(_ctx(), _config())
    assert result.data["skipped_reason"] == "lookalike_watch_off"


def test_engine_skips_when_no_brand_keyword():
    """An empty asset.value (or one tldextract can't parse) → no keyword."""
    asset = SimpleNamespace(id=1, value="", lookalike_watch=True)
    with _enabled(), \
         patch("app.extensions.db") as mock_db, \
         patch("app.services.ct_log_monitor.extract_brand_keyword", return_value=""):
        mock_db.session.get.return_value = asset
        engine = me.MimicEngine()
        result = engine.execute(_ctx(asset_value=""), _config())
    assert result.data["skipped_reason"] == "no_brand_keyword"


def test_engine_skips_with_needs_baseline_when_baseline_missing():
    asset = SimpleNamespace(id=1, value="example.com", lookalike_watch=True)
    with _enabled(), \
         patch("app.extensions.db") as mock_db, \
         patch("app.services.ct_log_monitor.extract_brand_keyword", return_value="example"), \
         patch.object(me, "_load_baseline", return_value=None):
        mock_db.session.get.return_value = asset
        engine = me.MimicEngine()
        result = engine.execute(_ctx(), _config())
    assert result.data["skipped_reason"] == "no_baseline"
    assert result.data["needs_baseline"] is True


# ─────────────────────────────────────────────────────────────────────
# Candidate gathering
# ─────────────────────────────────────────────────────────────────────


def _setup_runnable_engine(monkeypatch, lookalike_data=None, ct_rows=None):
    """Common setup for engine tests that need to reach the matcher
    dispatch path. Returns the ctx, matcher mock, and mark_processed mock."""
    monkeypatch.setenv("MIMIC_ENABLED", "true")
    asset = SimpleNamespace(id=1, value="example.com", lookalike_watch=True)
    baseline = {
        "structural_hash": "h1", "favicon_phash": "h2",
        "visual_phash": "h3", "key_strings": {"tokens": ["a", "b"]},
        "baseline_image_key": None, "captured_at": None,
    }

    ctx = _ctx()
    ctx.get_engine_data = MagicMock(return_value=lookalike_data or {})

    db_patch = patch("app.extensions.db")
    keyword_patch = patch("app.services.ct_log_monitor.extract_brand_keyword",
                          return_value="example")
    baseline_patch = patch.object(me, "_load_baseline", return_value=baseline)
    matcher_patch = patch.object(me, "_match_candidate")
    mark_patch = patch.object(me, "_mark_processed")
    ctlog_patch = patch("app.models.CtLogCandidate")

    mock_db = db_patch.start()
    mock_db.session.get.return_value = asset

    mock_keyword = keyword_patch.start()
    mock_baseline = baseline_patch.start()
    mock_matcher = matcher_patch.start()
    mock_matcher.return_value = None  # default: no match
    mock_mark = mark_patch.start()
    mock_ctlog = ctlog_patch.start()
    if ct_rows is None:
        ct_rows = []
    mock_ctlog.query.filter.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = ct_rows

    def _cleanup():
        for p in (db_patch, keyword_patch, baseline_patch, matcher_patch, mark_patch, ctlog_patch):
            p.stop()

    return ctx, mock_matcher, mock_mark, _cleanup


def test_engine_filters_lookalike_hits_to_live_only(monkeypatch):
    """Lookalike hits where neither HTTP probe responded should be skipped."""
    lookalike_data = {"verified_hits": [
        {"variant_domain": "live.com", "http_443_status": 200, "http_80_status": None},
        {"variant_domain": "cold.com", "http_443_status": None, "http_80_status": None},
        {"variant_domain": "fivexx.com", "http_443_status": 500, "http_80_status": 500},
    ]}
    ctx, mock_matcher, _mark, cleanup = _setup_runnable_engine(
        monkeypatch, lookalike_data=lookalike_data,
    )
    try:
        engine = me.MimicEngine()
        result = engine.execute(ctx, _config())
    finally:
        cleanup()

    hostnames_passed = [c.kwargs["candidate"]["hostname"]
                        for c in mock_matcher.call_args_list]
    assert "live.com" in hostnames_passed
    assert "cold.com" not in hostnames_passed
    assert "fivexx.com" not in hostnames_passed


def test_engine_dedupes_when_candidate_appears_in_both_sources(monkeypatch):
    """A hostname returned by both lookalike and CT log should be processed
    once (lookalike-source preferred since it appears first)."""
    lookalike_data = {"verified_hits": [
        {"variant_domain": "same.com", "http_443_status": 200},
    ]}
    ct_rows = [SimpleNamespace(
        id=99, hostname="same.com", cert_logged_at=None,
    )]
    ctx, mock_matcher, mock_mark, cleanup = _setup_runnable_engine(
        monkeypatch, lookalike_data=lookalike_data, ct_rows=ct_rows,
    )
    try:
        engine = me.MimicEngine()
        engine.execute(ctx, _config())
    finally:
        cleanup()
    # Matcher called once
    assert mock_matcher.call_count == 1
    # And on the lookalike-source candidate, not the CT one
    candidate = mock_matcher.call_args.kwargs["candidate"]
    assert candidate["source"] == "lookalike_hit"


def test_engine_skips_self_match_from_ct_log(monkeypatch):
    """A CT log row whose hostname equals the asset value must be marked
    self_skip and never fed to the matcher."""
    ct_rows = [
        SimpleNamespace(id=1, hostname="example.com", cert_logged_at=None),
        SimpleNamespace(id=2, hostname="phishy.com", cert_logged_at=None),
    ]
    ctx, mock_matcher, mock_mark, cleanup = _setup_runnable_engine(
        monkeypatch, ct_rows=ct_rows,
    )
    try:
        engine = me.MimicEngine()
        engine.execute(ctx, _config())
    finally:
        cleanup()
    # self_skip marked for row 1
    mock_mark.assert_any_call(1, "self_skip")
    # Matcher only got the non-self candidate
    assert mock_matcher.call_count == 1
    assert mock_matcher.call_args.kwargs["candidate"]["hostname"] == "phishy.com"


def test_engine_skips_self_match_from_lookalike(monkeypatch):
    """A lookalike verified-hit whose variant_domain == asset.value is
    filtered out before reaching the matcher."""
    lookalike_data = {"verified_hits": [
        {"variant_domain": "example.com", "http_443_status": 200},
        {"variant_domain": "phish.com", "http_443_status": 200},
    ]}
    ctx, mock_matcher, _, cleanup = _setup_runnable_engine(
        monkeypatch, lookalike_data=lookalike_data,
    )
    try:
        engine = me.MimicEngine()
        engine.execute(ctx, _config())
    finally:
        cleanup()
    hostnames = [c.kwargs["candidate"]["hostname"]
                 for c in mock_matcher.call_args_list]
    assert "example.com" not in hostnames
    assert "phish.com" in hostnames


def test_engine_skips_when_no_candidates(monkeypatch):
    ctx, mock_matcher, _, cleanup = _setup_runnable_engine(monkeypatch)
    try:
        engine = me.MimicEngine()
        result = engine.execute(ctx, _config())
    finally:
        cleanup()
    assert result.data["skipped_reason"] == "no_candidates"
    mock_matcher.assert_not_called()


# ─────────────────────────────────────────────────────────────────────
# Matcher dispatch behaviour
# ─────────────────────────────────────────────────────────────────────


def test_engine_continues_when_candidate_matcher_crashes(monkeypatch):
    """One candidate crashing the matcher must not stop the rest."""
    ct_rows = [
        SimpleNamespace(id=10, hostname="bad.com", cert_logged_at=None),
        SimpleNamespace(id=11, hostname="good.com", cert_logged_at=None),
    ]
    ctx, mock_matcher, mock_mark, cleanup = _setup_runnable_engine(
        monkeypatch, ct_rows=ct_rows,
    )
    # First candidate crashes, second returns no match
    mock_matcher.side_effect = [RuntimeError("renderer exploded"), None]
    try:
        engine = me.MimicEngine()
        result = engine.execute(ctx, _config())
    finally:
        cleanup()
    # Crashing candidate marked as such
    mock_mark.assert_any_call(10, "matcher_crash")
    # Other candidate marked as no_match
    mock_mark.assert_any_call(11, "no_match")
    # Engine didn't bubble the exception
    assert result.success is True


def test_engine_marks_match_when_score_above_threshold(monkeypatch):
    ct_rows = [SimpleNamespace(id=50, hostname="evil.com", cert_logged_at=None)]
    ctx, mock_matcher, mock_mark, cleanup = _setup_runnable_engine(
        monkeypatch, ct_rows=ct_rows,
    )
    mock_matcher.return_value = {
        "hostname": "evil.com", "url": "https://evil.com/",
        "source": "ct_log_candidate", "composite_score": 0.92,
        "signal_scores": {}, "severity": "critical",
        "screenshot_bytes": b"", "screenshot_size": 0, "render_ms": 100,
    }
    try:
        engine = me.MimicEngine()
        result = engine.execute(ctx, _config())
    finally:
        cleanup()
    mock_mark.assert_any_call(50, "match")
    assert len(result.data["matches"]) == 1
    assert result.data["matches"][0]["hostname"] == "evil.com"


def test_engine_continues_when_ct_queue_read_fails(monkeypatch):
    """A failure reading the CT log queue must not break the engine
    — fall back to lookalike-only candidates."""
    lookalike_data = {"verified_hits": [
        {"variant_domain": "ok.com", "http_443_status": 200},
    ]}
    # Don't use the helper here because we need to make the query raise
    monkeypatch.setenv("MIMIC_ENABLED", "true")
    asset = SimpleNamespace(id=1, value="example.com", lookalike_watch=True)
    baseline = {
        "structural_hash": "h", "favicon_phash": None, "visual_phash": "v",
        "key_strings": {"tokens": []}, "baseline_image_key": None,
        "captured_at": None,
    }
    ctx = _ctx()
    ctx.get_engine_data = MagicMock(return_value=lookalike_data)

    with patch("app.extensions.db") as mock_db, \
         patch("app.services.ct_log_monitor.extract_brand_keyword", return_value="example"), \
         patch.object(me, "_load_baseline", return_value=baseline), \
         patch.object(me, "_match_candidate", return_value=None) as mock_matcher, \
         patch.object(me, "_mark_processed"), \
         patch("app.models.CtLogCandidate") as mock_ctlog:
        mock_db.session.get.return_value = asset
        mock_ctlog.query.filter.side_effect = RuntimeError("db gone")

        engine = me.MimicEngine()
        result = engine.execute(ctx, _config())

    # Lookalike candidate still processed
    assert mock_matcher.call_count == 1
    assert mock_matcher.call_args.kwargs["candidate"]["hostname"] == "ok.com"
    assert result.success is True
