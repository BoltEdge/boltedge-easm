"""Tests for app.services.mimic_baseline.

Baseline capture is the gateway to the matcher — without a baseline,
mimic_engine short-circuits. These tests cover:

  - Feature-flag gating (MIMIC_ENABLED off → refused_disabled)
  - Invalid input (None asset, non-domain asset → refused_no_asset)
  - Staleness check (is_baseline_stale boundary behaviour)
  - Render failure path (render_page → None propagates as refused_render)
  - Signal-extraction failure path
  - Persist path: new row + update-existing-row branches
  - force=True bypasses staleness skip

DB layer is mocked. Tests run without PostgreSQL.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.services import mimic_baseline as mb


def _enabled_env():
    """MIMIC_ENABLED=true so capture doesn't short-circuit."""
    import os
    return patch.dict(os.environ, {"MIMIC_ENABLED": "true"}, clear=False)


def _fake_asset(asset_id=1, value="example.com", asset_type="domain", org_id=1):
    """Lightweight stand-in for an Asset row. Has only the attributes
    capture_baseline accesses."""
    return SimpleNamespace(
        id=asset_id,
        value=value,
        asset_type=asset_type,
        organization_id=org_id,
    )


# ─────────────────────────────────────────────────────────────────────
# Feature flag + input validation
# ─────────────────────────────────────────────────────────────────────


def test_capture_refused_when_mimic_disabled(monkeypatch):
    monkeypatch.delenv("MIMIC_ENABLED", raising=False)
    asset = _fake_asset()
    result = mb.capture_baseline(asset)
    assert result.status == "refused_disabled"
    assert result.asset_id == 1


def test_capture_refused_when_asset_is_none():
    with _enabled_env():
        result = mb.capture_baseline(None)
    assert result.status == "refused_no_asset"
    assert result.asset_id is None


def test_capture_refused_when_asset_value_empty():
    """An asset with no .value can't produce a URL → refused_no_asset."""
    asset = _fake_asset(value="")
    with _enabled_env():
        result = mb.capture_baseline(asset, force=True)
    assert result.status == "refused_no_asset"


def test_capture_refused_when_asset_is_not_domain():
    """Non-domain asset types (ip, cidr, etc.) aren't supported here."""
    asset = _fake_asset(value="10.0.0.1", asset_type="ip")
    with _enabled_env():
        result = mb.capture_baseline(asset, force=True)
    assert result.status == "refused_no_asset"


# ─────────────────────────────────────────────────────────────────────
# Staleness check (is_baseline_stale)
# ─────────────────────────────────────────────────────────────────────


def test_is_baseline_stale_true_when_no_row():
    with patch("app.models.MimicBaseline") as mock_model:
        mock_model.query.filter_by.return_value.first.return_value = None
        assert mb.is_baseline_stale(asset_id=1) is True


def test_is_baseline_stale_true_when_row_older_than_max_age():
    old_ts = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=10)
    fake_row = SimpleNamespace(last_refresh_at=old_ts, captured_at=old_ts)
    with patch("app.models.MimicBaseline") as mock_model:
        mock_model.query.filter_by.return_value.first.return_value = fake_row
        assert mb.is_baseline_stale(asset_id=1, max_age_days=7) is True


def test_is_baseline_stale_false_when_row_fresh():
    fresh_ts = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=2)
    fake_row = SimpleNamespace(last_refresh_at=fresh_ts, captured_at=fresh_ts)
    with patch("app.models.MimicBaseline") as mock_model:
        mock_model.query.filter_by.return_value.first.return_value = fake_row
        assert mb.is_baseline_stale(asset_id=1, max_age_days=7) is False


def test_is_baseline_stale_falls_back_to_not_stale_on_db_error():
    """We can't tell — be conservative, return False (don't burn render
    budget for nothing). This matches the comment in the source."""
    with patch("app.models.MimicBaseline") as mock_model:
        mock_model.query.filter_by.side_effect = RuntimeError("db down")
        assert mb.is_baseline_stale(asset_id=1) is False


# ─────────────────────────────────────────────────────────────────────
# Capture path — render / signals / persist
# ─────────────────────────────────────────────────────────────────────


def _fake_render(html="<html><head><title>Example</title></head><body>Hi</body></html>",
                 screenshot=b"\xff\xd8" + b"x" * 500,
                 final_url="https://example.com/"):
    """Return a RenderResult-like object."""
    return SimpleNamespace(
        html=html,
        screenshot_bytes=screenshot,
        final_url=final_url,
        status_code=200,
        width=1280,
        height=720,
        render_ms=100,
    )


def test_capture_returns_refused_render_when_render_fails():
    """render_page returns None → propagate as refused_render."""
    asset = _fake_asset()
    with _enabled_env(), \
         patch.object(mb, "is_baseline_stale", return_value=True), \
         patch("app.services.page_renderer.render_page", return_value=None):
        result = mb.capture_baseline(asset, force=True)
    assert result.status == "refused_render"


def test_capture_returns_refused_render_when_render_returns_empty_html():
    asset = _fake_asset()
    empty_render = _fake_render(html="")
    with _enabled_env(), \
         patch.object(mb, "is_baseline_stale", return_value=True), \
         patch("app.services.page_renderer.render_page", return_value=empty_render):
        result = mb.capture_baseline(asset, force=True)
    assert result.status == "refused_render"


def test_capture_skips_when_not_stale_and_not_forced():
    """The scheduler-path call (force=False) with a fresh baseline does
    NOT re-render. Return captured-status to signal 'nothing to do'."""
    asset = _fake_asset()
    with _enabled_env(), \
         patch.object(mb, "is_baseline_stale", return_value=False), \
         patch("app.services.page_renderer.render_page") as mock_render:
        result = mb.capture_baseline(asset, force=False)
    assert result.status == "captured"
    mock_render.assert_not_called()


@pytest.fixture()
def stub_signals(monkeypatch):
    """Stub the four page_signals functions used in capture_baseline so
    a fake JPEG byte string doesn't trip the 'visual hash failed' guard.
    The actual signal correctness is covered by test_mimic_signals.py."""
    from app.services import page_signals
    monkeypatch.setattr(page_signals, "visual_perceptual_hash",
                        lambda b: "ffeeddcc11223344" if b else None)
    monkeypatch.setattr(page_signals, "structural_hash",
                        lambda html: "aabbccddeeff0011")
    monkeypatch.setattr(page_signals, "favicon_perceptual_hash",
                        lambda b: None)
    monkeypatch.setattr(page_signals, "extract_key_strings",
                        lambda html, brand_keywords=(): {
                            "title": "Example",
                            "tokens": ["a", "b"],
                            "brand_mentions": [],
                        })


def test_capture_recaptures_when_force_true_even_if_fresh(stub_signals):
    """Manual refresh path: force=True must bypass the staleness check."""
    asset = _fake_asset()
    fake_baseline_row = MagicMock()
    fake_baseline_row.baseline_image_key = None
    with _enabled_env(), \
         patch.object(mb, "is_baseline_stale", return_value=False), \
         patch("app.services.page_renderer.render_page", return_value=_fake_render()), \
         patch("app.services.mimic_storage.upload_screenshot") as mock_upload, \
         patch("app.services.mimic_storage.delete_object"), \
         patch.object(mb, "_fetch_favicon", return_value=None), \
         patch("app.models.MimicBaseline") as mock_model, \
         patch("app.extensions.db") as mock_db:
        mock_upload.return_value = SimpleNamespace(s3_key="baseline/1/1.jpg", public_url=None, size_bytes=500, refused_reason=None)
        mock_model.query.filter_by.return_value.first.return_value = fake_baseline_row
        result = mb.capture_baseline(asset, force=True)
    assert result.status == "captured"


def test_capture_persists_new_baseline_when_no_existing_row(stub_signals):
    """First-time capture path: db.session.add called with a new
    MimicBaseline row."""
    asset = _fake_asset(asset_id=42, value="acme.com", org_id=7)
    with _enabled_env(), \
         patch.object(mb, "is_baseline_stale", return_value=True), \
         patch("app.services.page_renderer.render_page", return_value=_fake_render()), \
         patch("app.services.mimic_storage.upload_screenshot") as mock_upload, \
         patch.object(mb, "_fetch_favicon", return_value=None), \
         patch("app.models.MimicBaseline") as mock_model, \
         patch("app.extensions.db") as mock_db:
        mock_upload.return_value = SimpleNamespace(s3_key="baseline/7/42.jpg", public_url=None, size_bytes=500, refused_reason=None)
        # No existing row → engine creates one
        mock_model.query.filter_by.return_value.first.return_value = None

        # Make the MimicBaseline constructor return a sentinel we can assert on
        new_row = MagicMock()
        mock_model.return_value = new_row

        result = mb.capture_baseline(asset, force=False)

    assert result.status == "captured"
    assert result.baseline_image_key == "baseline/7/42.jpg"
    mock_db.session.add.assert_called_once_with(new_row)
    mock_db.session.commit.assert_called_once()


def test_capture_updates_existing_baseline_when_row_already_exists(stub_signals):
    """Re-capture path: existing row gets fields overwritten + last_refresh_at
    bumped. db.session.add must NOT be called."""
    asset = _fake_asset()
    existing = MagicMock()
    existing.baseline_image_key = "baseline/1/1.jpg"
    with _enabled_env(), \
         patch.object(mb, "is_baseline_stale", return_value=True), \
         patch("app.services.page_renderer.render_page", return_value=_fake_render()), \
         patch("app.services.mimic_storage.upload_screenshot") as mock_upload, \
         patch("app.services.mimic_storage.delete_object") as mock_delete, \
         patch.object(mb, "_fetch_favicon", return_value=None), \
         patch("app.models.MimicBaseline") as mock_model, \
         patch("app.extensions.db") as mock_db:
        # Re-upload to the same key (deterministic) — delete_object not called
        mock_upload.return_value = SimpleNamespace(s3_key="baseline/1/1.jpg", public_url=None, size_bytes=500, refused_reason=None)
        mock_model.query.filter_by.return_value.first.return_value = existing

        result = mb.capture_baseline(asset, force=True)

    assert result.status == "captured"
    # UPDATE path: existing row's fields got set
    assert existing.structural_hash is not None
    assert existing.visual_phash is not None
    assert existing.last_refresh_at is not None
    # INSERT path NOT taken
    mock_db.session.add.assert_not_called()
    mock_db.session.commit.assert_called_once()
    # Same key → no delete
    mock_delete.assert_not_called()


def test_capture_deletes_old_image_when_baseline_key_changes(stub_signals):
    """Defensive cleanup: when the new S3 key differs from the old one,
    delete the old object. (Keys are deterministic so this should be rare.)"""
    asset = _fake_asset()
    existing = MagicMock()
    existing.baseline_image_key = "baseline/1/1-old.jpg"
    with _enabled_env(), \
         patch.object(mb, "is_baseline_stale", return_value=True), \
         patch("app.services.page_renderer.render_page", return_value=_fake_render()), \
         patch("app.services.mimic_storage.upload_screenshot") as mock_upload, \
         patch("app.services.mimic_storage.delete_object") as mock_delete, \
         patch.object(mb, "_fetch_favicon", return_value=None), \
         patch("app.models.MimicBaseline") as mock_model, \
         patch("app.extensions.db"):
        mock_upload.return_value = SimpleNamespace(s3_key="baseline/1/1-new.jpg", public_url=None, size_bytes=500, refused_reason=None)
        mock_model.query.filter_by.return_value.first.return_value = existing
        mb.capture_baseline(asset, force=True)
    mock_delete.assert_called_once_with("baseline/1/1-old.jpg")


def test_capture_returns_refused_persist_when_commit_raises(stub_signals):
    """DB write failure → refused_persist + rollback called."""
    asset = _fake_asset()
    with _enabled_env(), \
         patch.object(mb, "is_baseline_stale", return_value=True), \
         patch("app.services.page_renderer.render_page", return_value=_fake_render()), \
         patch("app.services.mimic_storage.upload_screenshot") as mock_upload, \
         patch.object(mb, "_fetch_favicon", return_value=None), \
         patch("app.models.MimicBaseline") as mock_model, \
         patch("app.extensions.db") as mock_db:
        mock_upload.return_value = SimpleNamespace(s3_key="baseline/1/1.jpg", public_url=None, size_bytes=500, refused_reason=None)
        mock_model.query.filter_by.return_value.first.return_value = None
        mock_db.session.commit.side_effect = RuntimeError("db gone")

        result = mb.capture_baseline(asset, force=True)

    assert result.status == "refused_persist"
    mock_db.session.rollback.assert_called_once()


def test_capture_refused_signals_when_visual_hash_fails():
    """If visual_perceptual_hash returns falsy (None / empty), the
    function explicitly raises inside the try/except → refused_signals."""
    asset = _fake_asset()
    with _enabled_env(), \
         patch.object(mb, "is_baseline_stale", return_value=True), \
         patch("app.services.page_renderer.render_page", return_value=_fake_render(screenshot=b"")), \
         patch.object(mb, "_fetch_favicon", return_value=None):
        result = mb.capture_baseline(asset, force=True)
    assert result.status == "refused_signals"
