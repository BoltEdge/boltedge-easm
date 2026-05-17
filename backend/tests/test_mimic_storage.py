"""Tests for app.services.mimic_storage.

S3 layer is mocked. Boto3 is imported lazily inside _client() so
patching at the module level works the same way as the threat_intel
test patterns.
"""
import os
from unittest.mock import MagicMock, patch

import pytest

from app.services import mimic_storage as ms


def _enabled_env():
    return patch.dict("os.environ", {
        "MIMIC_ENABLED": "true",
        "MIMIC_S3_BUCKET": "test-bucket",
        "MIMIC_S3_REGION": "us-east-1",
    })


# ─────────────────────────────────────────────────────────────────────
# Master switch
# ─────────────────────────────────────────────────────────────────────


def test_upload_refused_when_mimic_disabled():
    # No env vars set
    os.environ.pop("MIMIC_ENABLED", None)
    os.environ.pop("MIMIC_S3_BUCKET", None)
    result = ms.upload_screenshot(
        b"\xff\xd8\xff",
        kind="baseline",
        organization_id=1,
        asset_id=1,
    )
    assert result.s3_key is None
    assert result.refused_reason == "mimic_disabled"


def test_upload_refused_for_empty_bytes():
    with _enabled_env():
        result = ms.upload_screenshot(
            b"",
            kind="baseline",
            organization_id=1,
            asset_id=1,
        )
    assert result.refused_reason == "empty_bytes"


# ─────────────────────────────────────────────────────────────────────
# Plan-cap enforcement
# ─────────────────────────────────────────────────────────────────────


def test_upload_refused_when_plan_cap_zero():
    """Free-tier orgs have cap=0 → feature unavailable."""
    with _enabled_env():
        result = ms.upload_screenshot(
            b"\xff\xd8" * 100,
            kind="finding",
            organization_id=1,
            asset_id=1,
            finding_id=42,
            cap_bytes=0,
        )
    assert result.refused_reason == "plan_cap_zero"
    assert result.s3_key is None


def test_upload_refused_when_cap_exceeded():
    """current + this_upload > cap → refused."""
    with _enabled_env():
        result = ms.upload_screenshot(
            b"\xff" * 1000,
            kind="finding",
            organization_id=1,
            asset_id=1,
            finding_id=42,
            cap_bytes=500,                # only 500 bytes allowed
            current_usage_bytes=0,
        )
    assert result.refused_reason == "plan_cap_exceeded"
    assert result.s3_key is None


def test_upload_proceeds_when_under_cap():
    with _enabled_env(), patch.object(ms, "_client") as mock_client:
        mock_s3 = MagicMock()
        mock_client.return_value = mock_s3
        result = ms.upload_screenshot(
            b"\xff" * 1000,
            kind="finding",
            organization_id=1,
            asset_id=1,
            finding_id=42,
            cap_bytes=10_000,
            current_usage_bytes=2_000,
        )
    assert result.refused_reason is None
    assert result.s3_key == "findings/1/1/42.jpg"
    assert result.size_bytes == 1000
    mock_s3.put_object.assert_called_once()


def test_upload_unlimited_cap_proceeds():
    """cap_bytes == -1 means unlimited (Custom tier)."""
    with _enabled_env(), patch.object(ms, "_client") as mock_client:
        mock_s3 = MagicMock()
        mock_client.return_value = mock_s3
        result = ms.upload_screenshot(
            b"\xff" * 1_000_000,
            kind="baseline",
            organization_id=1,
            asset_id=1,
            cap_bytes=-1,
            current_usage_bytes=999_999_999,
        )
    assert result.refused_reason is None
    assert result.s3_key == "baseline/1/1.jpg"


# ─────────────────────────────────────────────────────────────────────
# S3 error handling
# ─────────────────────────────────────────────────────────────────────


def test_upload_returns_refused_on_s3_error():
    with _enabled_env(), patch.object(ms, "_client") as mock_client:
        mock_s3 = MagicMock()
        mock_s3.put_object.side_effect = RuntimeError("aws timeout")
        mock_client.return_value = mock_s3
        result = ms.upload_screenshot(
            b"\xff\xd8" * 100,
            kind="finding",
            organization_id=1,
            asset_id=1,
            finding_id=99,
            cap_bytes=10_000,
        )
    assert result.refused_reason == "s3_error"
    assert result.s3_key is None


# ─────────────────────────────────────────────────────────────────────
# Key construction
# ─────────────────────────────────────────────────────────────────────


def test_baseline_key_format():
    with _enabled_env(), patch.object(ms, "_client") as mock_client:
        mock_client.return_value = MagicMock()
        result = ms.upload_screenshot(
            b"\xff\xd8\xff",
            kind="baseline",
            organization_id=7,
            asset_id=42,
            cap_bytes=-1,
        )
    assert result.s3_key == "baseline/7/42.jpg"


def test_finding_key_format_with_finding_id():
    with _enabled_env(), patch.object(ms, "_client") as mock_client:
        mock_client.return_value = MagicMock()
        result = ms.upload_screenshot(
            b"\xff\xd8\xff",
            kind="finding",
            organization_id=7,
            asset_id=42,
            finding_id=123,
            cap_bytes=-1,
        )
    assert result.s3_key == "findings/7/42/123.jpg"


def test_unknown_kind_refused():
    with _enabled_env(), patch.object(ms, "_client") as mock_client:
        mock_client.return_value = MagicMock()
        result = ms.upload_screenshot(
            b"\xff\xd8\xff",
            kind="weird_kind",
            organization_id=7,
            asset_id=42,
            cap_bytes=-1,
        )
    assert result.refused_reason and "unknown_kind" in result.refused_reason


# ─────────────────────────────────────────────────────────────────────
# Storage accounting cache
# ─────────────────────────────────────────────────────────────────────


def test_storage_usage_cached_within_ttl():
    ms._USAGE_CACHE.clear()
    with patch.object(ms, "_compute_usage", return_value=1000) as mock_compute:
        bytes_used = ms.mimic_storage_used_for_org(42)
        # Second call within TTL should hit the cache
        ms.mimic_storage_used_for_org(42)
    assert bytes_used == 1000
    assert mock_compute.call_count == 1


def test_invalidate_usage_cache_forces_recompute():
    ms._USAGE_CACHE.clear()
    with patch.object(ms, "_compute_usage", side_effect=[100, 200]) as mock_compute:
        first = ms.mimic_storage_used_for_org(1)
        ms.invalidate_usage_cache(1)
        second = ms.mimic_storage_used_for_org(1)
    assert first == 100
    assert second == 200
    assert mock_compute.call_count == 2


# ─────────────────────────────────────────────────────────────────────
# Public URL construction
# ─────────────────────────────────────────────────────────────────────


def test_public_url_us_east_1():
    with _enabled_env():
        url = ms._public_url("findings/1/1/42.jpg")
    assert url == "https://test-bucket.s3.amazonaws.com/findings/1/1/42.jpg"


def test_public_url_other_region():
    with patch.dict("os.environ", {
        "MIMIC_S3_BUCKET": "test-bucket",
        "MIMIC_S3_REGION": "ap-southeast-2",
    }):
        url = ms._public_url("findings/1/1/42.jpg")
    assert url == "https://test-bucket.s3.ap-southeast-2.amazonaws.com/findings/1/1/42.jpg"
