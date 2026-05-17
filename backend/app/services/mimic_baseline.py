# app/services/mimic_baseline.py
"""
Site Mimic Watch baseline capture.

A "baseline" is a snapshot of the customer's real page used as the
reference signal for the matcher. Stored as four hashes plus an S3
key for the actual screenshot (so the finding-details UI can render
side-by-side comparisons).

Public surface:

    capture_baseline(asset, force=False) -> CaptureResult
    is_baseline_stale(asset_id, max_age_days=7) -> bool

The lookalike scheduler calls capture_baseline before each watched
asset's weekly scan when MIMIC_ENABLED is on. The asset detail page's
manual refresh endpoint calls it directly with force=True.

Never raises. Every failure path returns a CaptureResult with status
indicating what went wrong.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional


logger = logging.getLogger(__name__)


BASELINE_MAX_AGE_DAYS = 7


@dataclass
class CaptureResult:
    """Outcome of a baseline capture. status is one of:
       captured            — fresh baseline written
       refused_disabled    — MIMIC_ENABLED is off
       refused_no_asset    — asset_id didn't resolve
       refused_render      — Playwright render failed
       refused_signals     — signal extraction failed
       refused_persist     — DB write failed
    """
    status: str
    asset_id: Optional[int]
    captured_at: Optional[datetime] = None
    baseline_image_key: Optional[str] = None


def _enabled() -> bool:
    return os.environ.get("MIMIC_ENABLED", "").strip().lower() == "true"


def is_baseline_stale(asset_id: int, max_age_days: int = BASELINE_MAX_AGE_DAYS) -> bool:
    """Return True when the asset has no baseline OR the existing one
    is older than max_age_days. Used by the scheduler to decide whether
    to recapture before a weekly scan."""
    try:
        from app.models import MimicBaseline
        row = MimicBaseline.query.filter_by(asset_id=asset_id).first()
    except Exception:
        # If we can't read the row we can't decide — be conservative
        # and say "not stale" so we don't burn render budget for nothing.
        return False
    if row is None:
        return True
    last = row.last_refresh_at or row.captured_at
    if last is None:
        return True
    last_aware = last if last.tzinfo else last.replace(tzinfo=timezone.utc)
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    return last_aware < cutoff


def capture_baseline(asset, *, force: bool = False) -> CaptureResult:
    """Render the asset's real page, compute four signal hashes, store
    in mimic_baseline + S3.

    `force=True` bypasses the staleness check so the manual refresh
    button always recaptures. `force=False` (the scheduler path) skips
    when the existing baseline is still fresh."""
    if not _enabled():
        return CaptureResult(status="refused_disabled", asset_id=getattr(asset, "id", None))
    if asset is None:
        return CaptureResult(status="refused_no_asset", asset_id=None)

    asset_id = asset.id
    if not force and not is_baseline_stale(asset_id):
        # Caller wanted a refresh-if-stale; we're not stale, so no work.
        return CaptureResult(status="captured", asset_id=asset_id)

    # Build the URL we'll render. Asset.value for a domain asset is
    # the bare hostname; prefer https://
    url = _asset_url(asset)
    if not url:
        return CaptureResult(status="refused_no_asset", asset_id=asset_id)

    # Render
    from app.services.page_renderer import render_page
    render = render_page(url)
    if render is None or not render.html:
        logger.warning("mimic_baseline: render failed for asset_id=%s url=%s",
                       asset_id, url)
        return CaptureResult(status="refused_render", asset_id=asset_id)

    # Compute signals
    from app.services.page_signals import (
        structural_hash, visual_perceptual_hash,
        favicon_perceptual_hash, extract_key_strings,
    )
    from app.services.ct_log_monitor import extract_brand_keyword

    try:
        struct_h = structural_hash(render.html)
        visual_h = visual_perceptual_hash(render.screenshot_bytes)
        if not visual_h:
            raise ValueError("visual hash failed")
        brand = extract_brand_keyword(asset.value)
        keys = extract_key_strings(
            render.html, brand_keywords=[brand] if brand else (),
        )
        favicon_bytes = _fetch_favicon(render.final_url or url)
        favicon_h = favicon_perceptual_hash(favicon_bytes) if favicon_bytes else None
    except Exception:
        logger.exception("mimic_baseline: signal extraction failed for asset_id=%s", asset_id)
        return CaptureResult(status="refused_signals", asset_id=asset_id)

    # Upload baseline screenshot (no per-org cap on baselines — they're
    # tiny and there's always at most one per asset, replaced on refresh)
    from app.services.mimic_storage import upload_screenshot, delete_object
    organization_id = getattr(asset, "organization_id", 0)

    storage_result = upload_screenshot(
        render.screenshot_bytes,
        kind="baseline",
        organization_id=organization_id,
        asset_id=asset_id,
        cap_bytes=-1,  # baselines aren't subject to the per-org cap
    )

    # Persist
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        from app.extensions import db
        from app.models import MimicBaseline
        existing = MimicBaseline.query.filter_by(asset_id=asset_id).first()
        if existing:
            # If we have a previous baseline image, delete the old S3
            # object (only when the new key differs — they should match
            # since the key is deterministic, but defensive cleanup).
            if (existing.baseline_image_key
                    and storage_result.s3_key
                    and existing.baseline_image_key != storage_result.s3_key):
                delete_object(existing.baseline_image_key)
            existing.structural_hash = struct_h
            existing.favicon_phash = favicon_h
            existing.visual_phash = visual_h
            existing.key_strings_json = keys
            if storage_result.s3_key:
                existing.baseline_image_key = storage_result.s3_key
            existing.last_refresh_at = now
        else:
            db.session.add(MimicBaseline(
                asset_id=asset_id,
                structural_hash=struct_h,
                favicon_phash=favicon_h,
                visual_phash=visual_h,
                key_strings_json=keys,
                baseline_image_key=storage_result.s3_key,
                captured_at=now,
                last_refresh_at=now,
            ))
        db.session.commit()
    except Exception:
        logger.exception("mimic_baseline: persist failed for asset_id=%s", asset_id)
        try:
            db.session.rollback()
        except Exception:
            pass
        return CaptureResult(status="refused_persist", asset_id=asset_id)

    return CaptureResult(
        status="captured",
        asset_id=asset_id,
        captured_at=now,
        baseline_image_key=storage_result.s3_key,
    )


def _asset_url(asset) -> Optional[str]:
    """Build a renderable URL for the asset. Domain assets render as
    https://<value>/. Non-domain assets aren't supported here."""
    asset_type = getattr(asset, "asset_type", "")
    value = (getattr(asset, "value", "") or "").strip()
    if not value or asset_type != "domain":
        return None
    if value.startswith("*."):
        value = value[2:]
    return f"https://{value}/"


def _fetch_favicon(page_url: str) -> Optional[bytes]:
    """Best-effort favicon fetch from the rendered page's origin."""
    try:
        import requests
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(page_url)
        if not parts.scheme or not parts.netloc:
            return None
        favicon_url = urlunsplit((parts.scheme, parts.netloc, "/favicon.ico", "", ""))
        resp = requests.get(
            favicon_url, timeout=10,
            headers={"User-Agent": "Nano-EASM-MimicProbe/1.0"},
        )
        if resp.status_code != 200:
            return None
        return resp.content[:512_000]
    except Exception:
        return None
