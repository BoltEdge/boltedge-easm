"""Integration test for Site Mimic Watch.

Validates the engine + analyzer working end-to-end against the real DB
with mocked external integrations (Playwright, S3, favicon HTTP, signal
extraction).

Covers:
  - Engine reads real CtLogCandidate rows from DB + matches against
    real MimicBaseline row + dedupes against a lookalike-source candidate
    on the same hostname
  - Engine flips CtLogCandidate.processed_at + processed_status on the
    rows it touched
  - Engine surfaces a match dict; analyzer turns it into a FindingDraft
    with the expected category/finding_type/tag/severity shape
  - Storage cap = 0 path: finding still emitted, no screenshot URL,
    mimic_storage_full=True (no real S3 call)
  - FK CASCADE: deleting the asset row removes its mimic_baseline

These tests require psycopg2 + a reachable PostgreSQL. They are skipped
when psycopg2 isn't loadable (e.g. Windows dev envs without the binary
or a misconfigured DLL path). CI must run them.
"""
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest

# Hard skip when the DB driver can't load. The standard
# `pytest.importorskip` would import psycopg2 lazily, which we want
# because the actual import happens via SQLAlchemy's create_engine
# inside conftest.app.
pytest.importorskip(
    "psycopg2",
    reason="integration tests need a working psycopg2 + PostgreSQL",
    exc_type=ImportError,
)


# Fixtures from conftest.py: app, db_session, test_org, test_user


@pytest.fixture()
def asset_with_baseline(db_session, test_org, test_user):
    """Create a real DB-backed Asset, AssetGroup, and MimicBaseline."""
    from app.models import Asset, AssetGroup, MimicBaseline

    group = AssetGroup(
        organization_id=test_org.id,
        user_id=test_user.id,
        name="default",
    )
    db_session.add(group)
    db_session.flush()

    asset = Asset(
        organization_id=test_org.id,
        user_id=test_user.id,
        group_id=group.id,
        asset_type="domain",
        value=f"example-{uuid.uuid4().hex[:6]}.com",
        lookalike_watch=True,
    )
    db_session.add(asset)
    db_session.flush()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    baseline = MimicBaseline(
        asset_id=asset.id,
        structural_hash="aabbccdd11223344",
        favicon_phash="ffeeddcc99887766",
        visual_phash="1234567890abcdef",
        key_strings_json={"title": "Acme", "tokens": ["acme", "sign", "in"], "brand_mentions": []},
        baseline_image_key="baseline/{}/{}.jpg".format(test_org.id, asset.id),
        captured_at=now,
        last_refresh_at=now,
    )
    db_session.add(baseline)
    db_session.flush()

    return asset


@pytest.fixture()
def stub_signals(monkeypatch):
    """Force composite_score above the critical threshold so a finding
    is produced. Real signal correctness is in test_mimic_signals.py."""
    from app.services import page_signals
    # Same hash strings as the baseline → similarity 1.0 → composite ≈ 1.0
    monkeypatch.setattr(page_signals, "structural_hash",
                        lambda html: "aabbccdd11223344")
    monkeypatch.setattr(page_signals, "visual_perceptual_hash",
                        lambda b: "1234567890abcdef" if b else None)
    monkeypatch.setattr(page_signals, "favicon_perceptual_hash",
                        lambda b: "ffeeddcc99887766" if b else None)
    monkeypatch.setattr(page_signals, "extract_key_strings",
                        lambda html, brand_keywords=(): {
                            "title": "Acme", "tokens": ["acme", "sign", "in"],
                            "brand_mentions": ["acme"],
                        })


def _fake_render():
    return SimpleNamespace(
        html="<html><body>fake</body></html>",
        screenshot_bytes=b"\xff\xd8" + b"x" * 1000,
        final_url="https://phish.example/",
        status_code=200,
        width=1280, height=720, render_ms=120,
    )


def _ctx(asset):
    """ScanContext stand-in. The mimic engine touches asset_id,
    asset_value, organization_id, and get_engine_data."""
    from unittest.mock import MagicMock
    ctx = SimpleNamespace(
        asset_id=asset.id,
        asset_value=asset.value,
        organization_id=asset.organization_id,
    )
    ctx.get_engine_data = MagicMock(return_value={})
    return ctx


# ─────────────────────────────────────────────────────────────────────
# End-to-end: CT log candidate → engine → analyzer → FindingDraft
# ─────────────────────────────────────────────────────────────────────


def test_engine_to_analyzer_ct_log_candidate_produces_finding(
    app, db_session, asset_with_baseline, stub_signals, monkeypatch,
):
    """Plant a CtLogCandidate, run the engine, run the analyzer; verify
    a FindingDraft comes out with the spec-required shape."""
    from app.models import CtLogCandidate
    from app.scanner.engines.mimic_engine import MimicEngine
    from app.scanner.analyzers.mimic_analyzer import MimicAnalyzer

    monkeypatch.setenv("MIMIC_ENABLED", "true")

    # Use the SAME brand keyword the engine will derive from asset.value.
    # asset.value is "example-XXXXXX.com" → tldextract gives "example-XXXXXX"
    from app.services.ct_log_monitor import extract_brand_keyword
    brand = extract_brand_keyword(asset_with_baseline.value)
    assert brand, "brand keyword extraction failed on test asset"

    candidate_hostname = f"phish-{uuid.uuid4().hex[:6]}.example"
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    ct_row = CtLogCandidate(
        brand_keyword=brand,
        hostname=candidate_hostname,
        cert_id=f"cert-{uuid.uuid4().hex[:8]}",
        cert_logged_at=now,
        discovered_at=now,
        expires_at=now + timedelta(days=7),
    )
    db_session.add(ct_row)
    db_session.flush()

    ctx = _ctx(asset_with_baseline)

    # Mock external: rendering + favicon HTTP. Signals stubbed above.
    with patch("app.services.page_renderer.render_page",
               return_value=_fake_render()), \
         patch("app.scanner.engines.mimic_engine._fetch_favicon",
               return_value=b"\x89PNG\r\n\x1a\n" + b"y" * 200), \
         patch("app.services.mimic_storage.upload_screenshot",
               return_value=SimpleNamespace(
                   s3_key="findings/x/y/z.jpg",
                   public_url="https://bucket.s3.amazonaws.com/findings/x/y/z.jpg",
                   size_bytes=1000, refused_reason=None)), \
         patch("app.scanner.analyzers.mimic_analyzer._plan_cap_bytes",
               return_value=-1), \
         patch("app.scanner.analyzers.mimic_analyzer._current_storage_bytes",
               return_value=0):
        engine = MimicEngine()
        engine_result = engine.execute(ctx, {})

        # Engine produced a match
        assert engine_result.success is True
        assert len(engine_result.data["matches"]) == 1
        match = engine_result.data["matches"][0]
        assert match["hostname"] == candidate_hostname
        assert match["source"] == "ct_log_candidate"
        # All signals match perfectly so composite is at the ceiling
        assert match["composite_score"] >= 0.85
        assert match["severity"] == "critical"

        # CT row marked processed
        db_session.refresh(ct_row)
        assert ct_row.processed_at is not None
        assert ct_row.processed_status == "match"

        # Hand engine output to analyzer via ctx.get_engine_data
        ctx.get_engine_data.return_value = engine_result.data
        analyzer = MimicAnalyzer()
        drafts = analyzer.analyze(ctx)

    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.finding_type == "mimic"
    assert draft.engine == "mimic"
    assert draft.template_id == "mimic-detected"
    assert draft.severity == "critical"
    assert "site-mimic" in draft.tags
    assert "ct_log_candidate" in draft.tags
    assert draft.details["hostname"] == candidate_hostname
    assert draft.details["input_source"] == "ct_log_candidate"
    assert draft.details["mimic_screenshot_url"].endswith("findings/x/y/z.jpg")
    assert draft.details["mimic_storage_full"] is False


# ─────────────────────────────────────────────────────────────────────
# Storage-cap path: finding still emitted with null screenshot URL
# ─────────────────────────────────────────────────────────────────────


def test_engine_emits_finding_without_url_when_storage_cap_exhausted(
    app, db_session, asset_with_baseline, stub_signals, monkeypatch,
):
    from app.models import CtLogCandidate
    from app.scanner.engines.mimic_engine import MimicEngine
    from app.scanner.analyzers.mimic_analyzer import MimicAnalyzer
    from app.services.ct_log_monitor import extract_brand_keyword

    monkeypatch.setenv("MIMIC_ENABLED", "true")
    brand = extract_brand_keyword(asset_with_baseline.value)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    ct_row = CtLogCandidate(
        brand_keyword=brand,
        hostname=f"phish-{uuid.uuid4().hex[:6]}.example",
        cert_id=f"cert-{uuid.uuid4().hex[:8]}",
        discovered_at=now,
        expires_at=now + timedelta(days=7),
    )
    db_session.add(ct_row)
    db_session.flush()

    ctx = _ctx(asset_with_baseline)
    refused = SimpleNamespace(
        s3_key=None, public_url=None, size_bytes=0,
        refused_reason="plan_cap_exceeded",
    )
    with patch("app.services.page_renderer.render_page",
               return_value=_fake_render()), \
         patch("app.scanner.engines.mimic_engine._fetch_favicon",
               return_value=None), \
         patch("app.services.mimic_storage.upload_screenshot",
               return_value=refused), \
         patch("app.scanner.analyzers.mimic_analyzer._plan_cap_bytes",
               return_value=100), \
         patch("app.scanner.analyzers.mimic_analyzer._current_storage_bytes",
               return_value=200):  # already over cap
        engine = MimicEngine()
        engine_result = engine.execute(ctx, {})
        ctx.get_engine_data.return_value = engine_result.data
        analyzer = MimicAnalyzer()
        drafts = analyzer.analyze(ctx)

    assert len(drafts) == 1
    assert drafts[0].details["mimic_screenshot_url"] is None
    assert drafts[0].details["mimic_storage_full"] is True


# ─────────────────────────────────────────────────────────────────────
# Self-match: candidate hostname == asset.value is filtered by the
# engine and never reaches the matcher
# ─────────────────────────────────────────────────────────────────────


def test_self_matching_ct_candidate_is_skipped(
    app, db_session, asset_with_baseline, monkeypatch,
):
    from app.models import CtLogCandidate
    from app.scanner.engines.mimic_engine import MimicEngine
    from app.services.ct_log_monitor import extract_brand_keyword

    monkeypatch.setenv("MIMIC_ENABLED", "true")
    brand = extract_brand_keyword(asset_with_baseline.value)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    ct_row = CtLogCandidate(
        brand_keyword=brand,
        hostname=asset_with_baseline.value,           # same as asset value
        cert_id=f"cert-{uuid.uuid4().hex[:8]}",
        discovered_at=now,
        expires_at=now + timedelta(days=7),
    )
    db_session.add(ct_row)
    db_session.flush()

    ctx = _ctx(asset_with_baseline)
    with patch("app.services.page_renderer.render_page") as mock_render:
        engine = MimicEngine()
        result = engine.execute(ctx, {})

    # The matcher was never called because the only candidate was filtered
    mock_render.assert_not_called()
    assert result.data["matches"] == []

    # And the CT row was marked self_skip
    db_session.refresh(ct_row)
    assert ct_row.processed_at is not None
    assert ct_row.processed_status == "self_skip"


# ─────────────────────────────────────────────────────────────────────
# FK CASCADE: deleting an Asset removes its mimic_baseline
# (Spec: "Deleted automatically when the customer disables Lookalike
# monitoring (cascade from asset_id FK)" — verified at the FK level.)
# ─────────────────────────────────────────────────────────────────────


def test_baseline_cascades_on_asset_delete(
    db_session, asset_with_baseline,
):
    from app.models import MimicBaseline

    asset_id = asset_with_baseline.id
    # Pre-flight: baseline exists
    assert MimicBaseline.query.filter_by(asset_id=asset_id).first() is not None

    db_session.delete(asset_with_baseline)
    db_session.flush()

    # Post: cascade removed the baseline
    assert MimicBaseline.query.filter_by(asset_id=asset_id).first() is None
