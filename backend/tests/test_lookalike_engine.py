"""Tests for app.scanner.engines.lookalike_engine.

Focus: the guards (watch flag, rate-limit), the candidate filter
(included families + homoglyph sub-cap), and aggregator behaviour.
DNS / HTTP / crt.sh and the DB session are mocked.
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.engines import lookalike_engine as le
from app.scanner.base import ScanContext


def _ctx(asset_id=1):
    return ScanContext(
        asset_id=asset_id,
        asset_type="domain",
        asset_value="example.com",
        organization_id=1,
        scan_job_id=99,
    )


def _watched_asset(value="example.com", last_scan=None, watch=True):
    a = MagicMock()
    a.id = 1
    a.value = value
    a.asset_type = "domain"
    a.lookalike_watch = watch
    a.last_lookalike_scan_at = last_scan
    return a


# ─────────────────────────────────────────────────────────────────────
# Guards
# ─────────────────────────────────────────────────────────────────────


def test_engine_skips_when_not_watched():
    asset = _watched_asset(watch=False)
    with patch.object(le.db.session, "get", return_value=asset):
        result = le.LookalikeEngine().execute(_ctx(), {})
    assert result.success is True
    assert result.data["skipped_reason"] == "not_watched"
    assert result.data["verified_hits"] == []


def test_engine_skips_when_rate_limited():
    asset = _watched_asset(last_scan=datetime.now(timezone.utc) - timedelta(days=2))
    with patch.object(le.db.session, "get", return_value=asset):
        result = le.LookalikeEngine().execute(_ctx(), {})
    assert result.data["rate_limited"] is True
    assert result.data["verified_hits"] == []


def test_engine_runs_when_rate_limit_expired():
    asset = _watched_asset(last_scan=datetime.now(timezone.utc) - timedelta(days=10))

    fake_fuzzer = MagicMock()
    fake_fuzzer.domains = [
        {"domain-name": "example.com", "fuzzer": "*original"},  # filtered
        {"domain-name": "exampe.com", "fuzzer": "omission"},
    ]

    with patch.object(le.db.session, "get", return_value=asset), \
         patch.object(le.db.session, "commit"), \
         patch("dnstwist.Fuzzer", return_value=fake_fuzzer), \
         patch.object(le, "_verify_candidate", return_value={
             "variant_domain": "exampe.com",
             "variant_family": "omission",
             "dns_a_records": ["1.2.3.4"],
             "http_80_status": 200,
             "http_443_status": 200,
             "cert_seen_count": 1,
             "cert_first_seen": "2026-04-01T00:00:00+00:00",
         }):
        result = le.LookalikeEngine().execute(_ctx(), {})

    assert result.success is True
    assert result.data["rate_limited"] is False
    assert len(result.data["verified_hits"]) == 1
    assert result.data["verified_hits"][0]["variant_domain"] == "exampe.com"
    # last_lookalike_scan_at should have been bumped
    assert asset.last_lookalike_scan_at is not None


def test_engine_skips_asset_not_found():
    with patch.object(le.db.session, "get", return_value=None):
        result = le.LookalikeEngine().execute(_ctx(), {})
    assert result.success is False
    assert "asset not found" in result.errors[0]


# ─────────────────────────────────────────────────────────────────────
# Candidate filtering
# ─────────────────────────────────────────────────────────────────────


def test_filter_drops_original_and_excluded_families():
    asset = _watched_asset()
    fake_fuzzer = MagicMock()
    fake_fuzzer.domains = [
        {"domain-name": "example.com", "fuzzer": "*original"},          # drop (original)
        {"domain-name": "exámple.com", "fuzzer": "homoglyph"},          # keep
        {"domain-name": "examples.com", "fuzzer": "plural"},            # drop (excluded family)
        {"domain-name": "ex-ample.com", "fuzzer": "hyphenation"},       # drop (excluded family)
        {"domain-name": "exampe.com", "fuzzer": "omission"},            # keep
        {"domain-name": "exsmple.com", "fuzzer": "bitsquatting"},       # drop
        {"domain-name": "www.example.com", "fuzzer": "subdomain"},      # drop
    ]

    captured_candidates = []

    def fake_verify(domain, family):
        captured_candidates.append((domain, family))
        return None  # no hits — just check what got passed

    with patch.object(le.db.session, "get", return_value=asset), \
         patch.object(le.db.session, "commit"), \
         patch("dnstwist.Fuzzer", return_value=fake_fuzzer), \
         patch.object(le, "_verify_candidate", side_effect=fake_verify):
        le.LookalikeEngine().execute(_ctx(), {})

    domains = {d for d, _ in captured_candidates}
    assert domains == {"exámple.com", "exampe.com"}


def test_homoglyph_cap_caps_high_volume_family():
    """Homoglyph alone can produce thousands of candidates. Verify the
    sub-cap kicks in once we've kept MAX_HOMOGLYPH_VARIANTS of them."""
    asset = _watched_asset()
    fake_fuzzer = MagicMock()
    # 500 homoglyph variants + 1 omission
    fake_fuzzer.domains = (
        [{"domain-name": f"hg{i}.com", "fuzzer": "homoglyph"} for i in range(500)]
        + [{"domain-name": "ommit.com", "fuzzer": "omission"}]
    )

    captured = []

    def fake_verify(domain, family):
        captured.append(family)
        return None

    with patch.object(le.db.session, "get", return_value=asset), \
         patch.object(le.db.session, "commit"), \
         patch("dnstwist.Fuzzer", return_value=fake_fuzzer), \
         patch.object(le, "MAX_HOMOGLYPH_VARIANTS", 10), \
         patch.object(le, "_verify_candidate", side_effect=fake_verify):
        le.LookalikeEngine().execute(_ctx(), {})

    homoglyph_count = sum(1 for f in captured if f == "homoglyph")
    omission_count = sum(1 for f in captured if f == "omission")
    assert homoglyph_count == 10  # capped
    assert omission_count == 1   # not capped (different family)


def test_max_candidates_per_run_cap():
    asset = _watched_asset()
    fake_fuzzer = MagicMock()
    # 50 omissions, MAX_CANDIDATES_PER_RUN patched to 10
    fake_fuzzer.domains = [
        {"domain-name": f"om{i}.com", "fuzzer": "omission"} for i in range(50)
    ]

    captured = []

    with patch.object(le.db.session, "get", return_value=asset), \
         patch.object(le.db.session, "commit"), \
         patch("dnstwist.Fuzzer", return_value=fake_fuzzer), \
         patch.object(le, "MAX_CANDIDATES_PER_RUN", 10), \
         patch.object(le, "_verify_candidate", side_effect=lambda d, f: captured.append((d, f)) or None):
        le.LookalikeEngine().execute(_ctx(), {})

    assert len(captured) == 10


# ─────────────────────────────────────────────────────────────────────
# Per-candidate verification helpers
# ─────────────────────────────────────────────────────────────────────


def test_verify_candidate_returns_none_when_no_signals():
    with patch.object(le, "_resolve_dns", return_value=[]), \
         patch.object(le, "_http_head", return_value=None), \
         patch.object(le, "_ct_log_search", return_value=(0, None)):
        assert le._verify_candidate("nope.com", "omission") is None


def test_verify_candidate_returns_hit_on_dns_only():
    with patch.object(le, "_resolve_dns", return_value=["1.2.3.4"]), \
         patch.object(le, "_http_head", return_value=None), \
         patch.object(le, "_ct_log_search", return_value=(0, None)):
        hit = le._verify_candidate("park.com", "omission")
    assert hit is not None
    assert hit["dns_a_records"] == ["1.2.3.4"]
    assert hit["http_443_status"] is None
    assert hit["cert_seen_count"] == 0


def test_verify_candidate_returns_hit_on_cert_only():
    """Cert observed but no DNS still indicates someone is preparing
    infrastructure — flag for awareness."""
    with patch.object(le, "_resolve_dns", return_value=[]), \
         patch.object(le, "_http_head", return_value=None), \
         patch.object(le, "_ct_log_search", return_value=(2, "2026-04-01T00:00:00+00:00")):
        hit = le._verify_candidate("prep.com", "omission")
    assert hit is not None
    assert hit["cert_seen_count"] == 2
