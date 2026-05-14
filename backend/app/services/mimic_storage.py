# app/services/mimic_storage.py
"""
S3 storage wrapper for Site Mimic Watch screenshots.

Two public flows:

    upload_screenshot(image_bytes, *, kind, organization_id,
                      asset_id, finding_id=None) -> StorageResult
    delete_object(s3_key) -> bool

The "kind" argument segregates baseline images from finding images
so the lifecycle rule (90-day expiry on prefix `findings/`) can apply
selectively. baseline/ objects don't expire — we replace them on
each weekly refresh.

Per-org storage cap is enforced before upload; over-cap orgs receive
a refused-upload response and the caller produces the finding without
the screenshot URL. Hash-based detection never blocks on storage.

Auth: boto3's default credential chain (env vars + IAM role).
No bucket-region detection — operator sets MIMIC_S3_REGION explicitly.
"""
from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass
from typing import Optional


logger = logging.getLogger(__name__)


@dataclass
class StorageResult:
    """Returned from upload_screenshot. `s3_key` is None when the upload
    was refused (over storage cap, S3 error, or master switch off)."""
    s3_key: Optional[str]
    public_url: Optional[str]
    size_bytes: int
    refused_reason: Optional[str] = None


def _bucket() -> Optional[str]:
    return (os.environ.get("MIMIC_S3_BUCKET") or "").strip() or None


def _region() -> str:
    return (os.environ.get("MIMIC_S3_REGION") or "us-east-1").strip()


def _enabled() -> bool:
    """Master switch. When false, upload always returns a refused result."""
    return (
        os.environ.get("MIMIC_ENABLED", "").strip().lower() == "true"
        and bool(_bucket())
    )


def _client():
    """Build a boto3 S3 client. Lazy-imported so deployments without
    boto3 in their image keep working when the feature is off."""
    import boto3
    return boto3.client("s3", region_name=_region())


def _public_url(s3_key: str) -> str:
    """Construct the canonical public URL for an object in our bucket.
    Used by the UI to render screenshots. If the bucket has public-read
    blocked (recommended), the UI fetches via a presigned URL instead —
    that's a job for the routes layer, not the storage helper."""
    bucket = _bucket() or "<unset>"
    region = _region()
    if region == "us-east-1":
        return f"https://{bucket}.s3.amazonaws.com/{s3_key}"
    return f"https://{bucket}.s3.{region}.amazonaws.com/{s3_key}"


def upload_screenshot(
    image_bytes: bytes,
    *,
    kind: str,                         # "baseline" or "finding"
    organization_id: int,
    asset_id: int,
    finding_id: Optional[int] = None,
    cap_bytes: Optional[int] = None,
    current_usage_bytes: int = 0,
) -> StorageResult:
    """Upload a JPEG to S3 with the canonical key layout. Enforces the
    per-org storage cap before upload — if adding this object would
    exceed cap_bytes, the upload is refused and StorageResult.s3_key
    comes back as None with refused_reason set.

    Caller is responsible for computing current_usage_bytes from the
    org's existing findings (cheap aggregation in SQL — see
    mimic_storage_used_for_org).
    """
    size_bytes = len(image_bytes or b"")
    if size_bytes == 0:
        return StorageResult(
            s3_key=None, public_url=None, size_bytes=0,
            refused_reason="empty_bytes",
        )

    if not _enabled():
        return StorageResult(
            s3_key=None, public_url=None, size_bytes=size_bytes,
            refused_reason="mimic_disabled",
        )

    if cap_bytes is not None and cap_bytes >= 0:
        # cap_bytes < 0 means unlimited; cap_bytes == 0 means feature unavailable
        if cap_bytes == 0:
            return StorageResult(
                s3_key=None, public_url=None, size_bytes=size_bytes,
                refused_reason="plan_cap_zero",
            )
        if current_usage_bytes + size_bytes > cap_bytes:
            return StorageResult(
                s3_key=None, public_url=None, size_bytes=size_bytes,
                refused_reason="plan_cap_exceeded",
            )

    if kind == "baseline":
        s3_key = f"baseline/{organization_id}/{asset_id}.jpg"
    elif kind == "finding":
        finding_part = finding_id if finding_id is not None else uuid.uuid4().hex
        s3_key = f"findings/{organization_id}/{asset_id}/{finding_part}.jpg"
    else:
        return StorageResult(
            s3_key=None, public_url=None, size_bytes=size_bytes,
            refused_reason=f"unknown_kind:{kind}",
        )

    try:
        client = _client()
        client.put_object(
            Bucket=_bucket(),
            Key=s3_key,
            Body=image_bytes,
            ContentType="image/jpeg",
            CacheControl="public, max-age=86400",
        )
    except Exception:
        logger.exception("mimic_storage: S3 upload failed for %s", s3_key)
        return StorageResult(
            s3_key=None, public_url=None, size_bytes=size_bytes,
            refused_reason="s3_error",
        )

    return StorageResult(
        s3_key=s3_key,
        public_url=_public_url(s3_key),
        size_bytes=size_bytes,
    )


def delete_object(s3_key: str) -> bool:
    """Delete a single object from the bucket. Returns True on success
    or when the object doesn't exist (idempotent). Never raises."""
    if not s3_key or not _enabled():
        return False
    try:
        client = _client()
        client.delete_object(Bucket=_bucket(), Key=s3_key)
        return True
    except Exception:
        logger.exception("mimic_storage: S3 delete failed for %s", s3_key)
        return False


def presign_get_url(s3_key: str, *, expires_seconds: int = 3600) -> Optional[str]:
    """Generate a short-lived presigned URL for a private object.
    Used by the finding details UI to render images without making the
    bucket public. Returns None if the feature is off or boto3 errors."""
    if not s3_key or not _enabled():
        return None
    try:
        client = _client()
        return client.generate_presigned_url(
            "get_object",
            Params={"Bucket": _bucket(), "Key": s3_key},
            ExpiresIn=expires_seconds,
        )
    except Exception:
        logger.exception("mimic_storage: presign failed for %s", s3_key)
        return None


# ─────────────────────────────────────────────────────────────────────
# Storage accounting
# ─────────────────────────────────────────────────────────────────────

import time
_USAGE_CACHE: dict[int, tuple[int, float]] = {}        # org_id -> (bytes, ts)
_USAGE_CACHE_TTL_S = 60


def mimic_storage_used_for_org(organization_id: int) -> int:
    """Return current bytes-of-screenshot stored across this org's
    open mimic findings. Cached for 60 seconds in memory so a batch
    of upload calls doesn't recompute on every write.

    Computed from Finding.details_json.mimic_screenshot_size — no
    separate counter table needed."""
    now = time.monotonic()
    cached = _USAGE_CACHE.get(organization_id)
    if cached and (now - cached[1]) < _USAGE_CACHE_TTL_S:
        return cached[0]

    bytes_used = _compute_usage(organization_id)
    _USAGE_CACHE[organization_id] = (bytes_used, now)
    return bytes_used


def invalidate_usage_cache(organization_id: int) -> None:
    """Force a recompute on the next call. Useful after a deletion."""
    _USAGE_CACHE.pop(organization_id, None)


def _compute_usage(organization_id: int) -> int:
    """SQL aggregation — patched in tests."""
    try:
        from app.extensions import db
        from app.models import Asset, Finding
        from sqlalchemy import func, cast, BigInteger
    except Exception:
        return 0
    try:
        return int(
            db.session.query(
                func.coalesce(func.sum(
                    cast(Finding.details_json["mimic_screenshot_size"].astext, BigInteger)
                ), 0)
            )
            .join(Asset, Finding.asset_id == Asset.id)
            .filter(
                Asset.organization_id == organization_id,
                Finding.finding_type == "mimic",
            )
            .scalar() or 0
        )
    except Exception:
        logger.exception("mimic_storage: usage computation failed")
        return 0
