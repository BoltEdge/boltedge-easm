"""Tests for app.scanner.analyzers.mimic_analyzer.

The analyzer takes engine matches and turns them into FindingDraft rows.
Covers:
  - No matches → no drafts
  - One draft per match
  - Severity propagated from match
  - tags include site-mimic + source
  - details_json shape (composite_score, signal_scores, screenshot meta)
  - Storage cap exhaustion → finding still emitted, no URL, storage_full flag
  - Confidence threshold (high at ≥0.85, medium otherwise)
  - Per-batch storage accounting accumulates so later uploads see updated usage
  - Missing template → returns no drafts (logs warning)
"""
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.analyzers import mimic_analyzer as ma


def _ctx(asset_id=1, asset_value="example.com", org_id=1, engine_data=None):
    ctx = SimpleNamespace(
        asset_id=asset_id,
        asset_value=asset_value,
        organization_id=org_id,
    )
    ctx.get_engine_data = MagicMock(return_value=engine_data or {"matches": []})
    return ctx


def _match(
    *,
    hostname="evil.com",
    composite=0.92,
    severity="critical",
    source="ct_log_candidate",
    screenshot=b"\xff\xd8" + b"x" * 800,
):
    return {
        "hostname": hostname,
        "url": f"https://{hostname}/",
        "source": source,
        "composite_score": composite,
        "signal_scores": {
            "structural": 0.9, "favicon": 1.0,
            "text": 0.7, "visual": 0.93,
        },
        "severity": severity,
        "screenshot_bytes": screenshot,
        "screenshot_size": len(screenshot),
        "render_ms": 200,
        "cert_logged_at": None,
        "title": "Login",
        "brand_mentions": ["acme"],
    }


def _stub_template():
    """Return a minimal FindingTemplate stand-in."""
    return SimpleNamespace(
        title="Site mimic detected on {asset}",
        description="A clone of {asset} was found at {candidate}.",
        remediation="Issue a takedown request for {candidate}.",
        severity="high",
        category="lookalike",
        cwe="CWE-1021",
        references=("https://example.com/ref",),
        tags=("lookalike",),
    )


def _stub_upload_result(s3_key="findings/1/1/x.jpg", refused_reason=None, size=800):
    return SimpleNamespace(
        s3_key=s3_key,
        public_url=(f"https://bucket.s3.amazonaws.com/{s3_key}" if s3_key else None),
        size_bytes=size,
        refused_reason=refused_reason,
    )


# ─────────────────────────────────────────────────────────────────────
# Empty-state behaviour
# ─────────────────────────────────────────────────────────────────────


def test_analyzer_returns_empty_when_no_matches():
    analyzer = ma.MimicAnalyzer()
    drafts = analyzer.analyze(_ctx(engine_data={"matches": []}))
    assert drafts == []


def test_analyzer_returns_empty_when_engine_data_missing_matches_key():
    analyzer = ma.MimicAnalyzer()
    drafts = analyzer.analyze(_ctx(engine_data={}))
    assert drafts == []


# ─────────────────────────────────────────────────────────────────────
# Happy path — one finding per match, correct shape
# ─────────────────────────────────────────────────────────────────────


def test_analyzer_produces_one_finding_per_match():
    matches = [_match(hostname="a.com"), _match(hostname="b.com"), _match(hostname="c.com")]
    with patch("app.scanner.templates.get_template", return_value=_stub_template()), \
         patch("app.services.mimic_storage.upload_screenshot",
               return_value=_stub_upload_result()), \
         patch.object(ma, "_plan_cap_bytes", return_value=-1), \
         patch.object(ma, "_current_storage_bytes", return_value=0):
        analyzer = ma.MimicAnalyzer()
        drafts = analyzer.analyze(_ctx(engine_data={"matches": matches}))
    assert len(drafts) == 3
    hostnames = [d.details["hostname"] for d in drafts]
    assert hostnames == ["a.com", "b.com", "c.com"]


def test_analyzer_propagates_severity_from_match():
    matches = [_match(severity="high")]
    with patch("app.scanner.templates.get_template", return_value=_stub_template()), \
         patch("app.services.mimic_storage.upload_screenshot",
               return_value=_stub_upload_result()), \
         patch.object(ma, "_plan_cap_bytes", return_value=-1), \
         patch.object(ma, "_current_storage_bytes", return_value=0):
        analyzer = ma.MimicAnalyzer()
        drafts = analyzer.analyze(_ctx(engine_data={"matches": matches}))
    assert drafts[0].severity == "high"


def test_analyzer_tags_finding_with_site_mimic_and_source():
    matches = [_match(source="lookalike_hit")]
    with patch("app.scanner.templates.get_template", return_value=_stub_template()), \
         patch("app.services.mimic_storage.upload_screenshot",
               return_value=_stub_upload_result()), \
         patch.object(ma, "_plan_cap_bytes", return_value=-1), \
         patch.object(ma, "_current_storage_bytes", return_value=0):
        analyzer = ma.MimicAnalyzer()
        drafts = analyzer.analyze(_ctx(engine_data={"matches": matches}))
    tags = drafts[0].tags
    assert "site-mimic" in tags
    assert "lookalike_hit" in tags
    # Template tags also carried through
    assert "lookalike" in tags


def test_analyzer_details_json_contains_per_signal_scores_and_metadata():
    matches = [_match()]
    with patch("app.scanner.templates.get_template", return_value=_stub_template()), \
         patch("app.services.mimic_storage.upload_screenshot",
               return_value=_stub_upload_result(s3_key="findings/1/1/42.jpg")), \
         patch.object(ma, "_plan_cap_bytes", return_value=-1), \
         patch.object(ma, "_current_storage_bytes", return_value=0):
        analyzer = ma.MimicAnalyzer()
        details = analyzer.analyze(_ctx(engine_data={"matches": matches}))[0].details
    # Spec-required details_json keys
    assert details["composite_score"] == 0.92
    assert details["signal_scores"] == {
        "structural": 0.9, "favicon": 1.0, "text": 0.7, "visual": 0.93,
    }
    assert details["input_source"] == "ct_log_candidate"
    assert details["hostname"] == "evil.com"
    assert details["candidate_url"] == "https://evil.com/"
    assert details["mimic_screenshot_url"].endswith("findings/1/1/42.jpg")
    assert details["mimic_screenshot_key"] == "findings/1/1/42.jpg"
    assert details["mimic_screenshot_size"] == 800
    assert details["mimic_storage_full"] is False


def test_analyzer_finding_type_is_mimic_and_engine_is_mimic():
    matches = [_match()]
    with patch("app.scanner.templates.get_template", return_value=_stub_template()), \
         patch("app.services.mimic_storage.upload_screenshot",
               return_value=_stub_upload_result()), \
         patch.object(ma, "_plan_cap_bytes", return_value=-1), \
         patch.object(ma, "_current_storage_bytes", return_value=0):
        analyzer = ma.MimicAnalyzer()
        draft = analyzer.analyze(_ctx(engine_data={"matches": matches}))[0]
    assert draft.finding_type == "mimic"
    assert draft.engine == "mimic"
    assert draft.template_id == "mimic-detected"


# ─────────────────────────────────────────────────────────────────────
# Storage cap behaviour
# ─────────────────────────────────────────────────────────────────────


def test_analyzer_flags_storage_full_when_upload_refused_for_cap():
    matches = [_match()]
    with patch("app.scanner.templates.get_template", return_value=_stub_template()), \
         patch("app.services.mimic_storage.upload_screenshot",
               return_value=_stub_upload_result(s3_key=None, refused_reason="plan_cap_exceeded", size=0)), \
         patch.object(ma, "_plan_cap_bytes", return_value=100), \
         patch.object(ma, "_current_storage_bytes", return_value=100):
        analyzer = ma.MimicAnalyzer()
        draft = analyzer.analyze(_ctx(engine_data={"matches": matches}))[0]
    # Finding still emitted (this is the whole point — don't drop alerts
    # because the customer is over their screenshot quota)
    assert draft is not None
    assert draft.details["mimic_storage_full"] is True
    assert draft.details["mimic_screenshot_url"] is None
    assert draft.details["mimic_screenshot_key"] is None


def test_analyzer_finding_emitted_without_url_on_s3_error():
    """S3 outage → upload refused with refused_reason='s3_error'. Finding
    still produced, just no URL. storage_full flag stays False (the cap
    isn't the problem here)."""
    matches = [_match()]
    with patch("app.scanner.templates.get_template", return_value=_stub_template()), \
         patch("app.services.mimic_storage.upload_screenshot",
               return_value=_stub_upload_result(s3_key=None, refused_reason="s3_error", size=0)), \
         patch.object(ma, "_plan_cap_bytes", return_value=-1), \
         patch.object(ma, "_current_storage_bytes", return_value=0):
        analyzer = ma.MimicAnalyzer()
        draft = analyzer.analyze(_ctx(engine_data={"matches": matches}))[0]
    assert draft.details["mimic_screenshot_url"] is None
    assert draft.details["mimic_storage_full"] is False
    assert draft.details["mimic_storage_refused_reason"] == "s3_error"


def test_analyzer_storage_accounting_updates_within_batch():
    """When the first finding's upload consumes part of the cap, subsequent
    findings in the same batch should see updated current_usage."""
    matches = [_match(hostname=f"sub{i}.com") for i in range(3)]
    seen_usage = []

    def fake_upload(*args, **kwargs):
        seen_usage.append(kwargs.get("current_usage_bytes"))
        return _stub_upload_result(s3_key=f"findings/1/1/{len(seen_usage)}.jpg", size=500)

    with patch("app.scanner.templates.get_template", return_value=_stub_template()), \
         patch("app.services.mimic_storage.upload_screenshot",
               side_effect=fake_upload), \
         patch.object(ma, "_plan_cap_bytes", return_value=10_000), \
         patch.object(ma, "_current_storage_bytes", return_value=1_000):
        analyzer = ma.MimicAnalyzer()
        analyzer.analyze(_ctx(engine_data={"matches": matches}))

    # First call sees 1000, second sees 1500 (1000 + 500), third sees 2000
    assert seen_usage == [1_000, 1_500, 2_000]


# ─────────────────────────────────────────────────────────────────────
# Confidence threshold
# ─────────────────────────────────────────────────────────────────────


def test_analyzer_marks_confidence_high_at_or_above_85_composite():
    matches = [_match(composite=0.85)]
    with patch("app.scanner.templates.get_template", return_value=_stub_template()), \
         patch("app.services.mimic_storage.upload_screenshot",
               return_value=_stub_upload_result()), \
         patch.object(ma, "_plan_cap_bytes", return_value=-1), \
         patch.object(ma, "_current_storage_bytes", return_value=0):
        analyzer = ma.MimicAnalyzer()
        draft = analyzer.analyze(_ctx(engine_data={"matches": matches}))[0]
    assert draft.confidence == "high"


def test_analyzer_marks_confidence_medium_below_85_composite():
    matches = [_match(composite=0.70)]
    with patch("app.scanner.templates.get_template", return_value=_stub_template()), \
         patch("app.services.mimic_storage.upload_screenshot",
               return_value=_stub_upload_result()), \
         patch.object(ma, "_plan_cap_bytes", return_value=-1), \
         patch.object(ma, "_current_storage_bytes", return_value=0):
        analyzer = ma.MimicAnalyzer()
        draft = analyzer.analyze(_ctx(engine_data={"matches": matches}))[0]
    assert draft.confidence == "medium"


# ─────────────────────────────────────────────────────────────────────
# Edge cases
# ─────────────────────────────────────────────────────────────────────


def test_analyzer_skips_match_with_missing_hostname():
    matches = [_match(hostname=""), _match(hostname="good.com")]
    with patch("app.scanner.templates.get_template", return_value=_stub_template()), \
         patch("app.services.mimic_storage.upload_screenshot",
               return_value=_stub_upload_result()), \
         patch.object(ma, "_plan_cap_bytes", return_value=-1), \
         patch.object(ma, "_current_storage_bytes", return_value=0):
        analyzer = ma.MimicAnalyzer()
        drafts = analyzer.analyze(_ctx(engine_data={"matches": matches}))
    # Only the good one produces a draft
    assert len(drafts) == 1
    assert drafts[0].details["hostname"] == "good.com"


def test_analyzer_returns_empty_when_template_missing():
    """Defensive: if mimic-detected template isn't registered, we log
    and skip. Should never happen in practice since templates.py is the
    source of truth."""
    matches = [_match()]
    with patch("app.scanner.templates.get_template", return_value=None), \
         patch("app.services.mimic_storage.upload_screenshot",
               return_value=_stub_upload_result()), \
         patch.object(ma, "_plan_cap_bytes", return_value=-1), \
         patch.object(ma, "_current_storage_bytes", return_value=0):
        analyzer = ma.MimicAnalyzer()
        drafts = analyzer.analyze(_ctx(engine_data={"matches": matches}))
    assert drafts == []
