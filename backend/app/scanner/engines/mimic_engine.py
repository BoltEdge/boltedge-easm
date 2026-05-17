# app/scanner/engines/mimic_engine.py
"""
Site Mimic Watch engine.

Reads two candidate-discovery sources:

  1. lookalike engine's verified_hits (any with live HTTP)
  2. ct_log_candidate queue rows whose brand_keyword matches this
     asset's derived keyword (LIMIT 20, oldest unprocessed first)

For each candidate hostname:
  - Renders with Playwright (page_renderer)
  - Computes four signals (page_signals)
  - Compares against the asset's mimic_baseline
  - Returns scored matches; the analyzer turns them into findings

Engine short-circuits silently when:
  - MIMIC_ENABLED isn't true
  - The asset doesn't have lookalike_watch on
  - No baseline exists (the scheduler captures one before the next run)

Never raises. All errors logged + per-candidate skip.

See docs/superpowers/specs/2026-05-15-site-mimic-watch-design.md for
the full design.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from app.scanner.base import BaseEngine, EngineResult, ScanContext


logger = logging.getLogger(__name__)


MAX_CT_CANDIDATES_PER_SCAN = 20
FETCH_TIMEOUT = 10
MAX_LOOKALIKE_CANDIDATES = 30


class MimicEngine(BaseEngine):
    """Render-and-match candidates against a per-asset baseline."""

    @property
    def name(self) -> str:
        return "mimic"

    @property
    def supported_asset_types(self) -> List[str]:
        return ["domain"]

    def execute(self, ctx: ScanContext, config: Dict[str, Any]) -> EngineResult:
        result = EngineResult(engine_name=self.name)
        data: Dict[str, Any] = {
            "domain": ctx.asset_value,
            "matches": [],
            "candidates_processed": 0,
            "skipped_reason": None,
        }

        if not _mimic_enabled():
            data["skipped_reason"] = "mimic_disabled"
            result.data = data
            return result

        # Resolve the asset + brand keyword + baseline.
        from app.extensions import db
        from app.models import Asset, MimicBaseline, CtLogCandidate
        from app.services.ct_log_monitor import extract_brand_keyword

        asset = db.session.get(Asset, ctx.asset_id)
        if not asset:
            data["skipped_reason"] = "asset_not_found"
            result.data = data
            result.success = False
            return result
        if not getattr(asset, "lookalike_watch", False):
            data["skipped_reason"] = "lookalike_watch_off"
            result.data = data
            return result

        brand_keyword = extract_brand_keyword(asset.value)
        if not brand_keyword:
            data["skipped_reason"] = "no_brand_keyword"
            result.data = data
            return result

        baseline = _load_baseline(asset.id)
        if not baseline:
            data["skipped_reason"] = "no_baseline"
            data["needs_baseline"] = True
            result.data = data
            return result

        # Source A — lookalike-driven candidates
        candidates: List[Dict[str, Any]] = []
        lookalike_data = ctx.get_engine_data("lookalike") or {}
        for hit in (lookalike_data.get("verified_hits") or [])[:MAX_LOOKALIKE_CANDIDATES]:
            if not isinstance(hit, dict):
                continue
            variant_domain = hit.get("variant_domain")
            if not variant_domain or variant_domain == asset.value:
                continue
            http_80 = hit.get("http_80_status")
            http_443 = hit.get("http_443_status")
            live = (
                (isinstance(http_443, int) and 200 <= http_443 < 400)
                or (isinstance(http_80, int) and 200 <= http_80 < 400)
            )
            if not live:
                continue
            scheme = "https" if isinstance(http_443, int) and http_443 < 400 else "http"
            candidates.append({
                "hostname": variant_domain,
                "url": f"{scheme}://{variant_domain}/",
                "source": "lookalike_hit",
                "cert_logged_at": hit.get("cert_first_seen"),
            })

        # Source B — CT log queue candidates
        try:
            ct_rows = (
                CtLogCandidate.query
                .filter(CtLogCandidate.brand_keyword == brand_keyword)
                .filter(CtLogCandidate.processed_at.is_(None))
                .order_by(CtLogCandidate.discovered_at.asc())
                .limit(MAX_CT_CANDIDATES_PER_SCAN)
                .all()
            )
        except Exception:
            logger.exception("mimic_engine: CT queue read failed")
            ct_rows = []

        for row in ct_rows:
            if row.hostname == asset.value:
                # Self-match guard
                _mark_processed(row.id, "self_skip")
                continue
            candidates.append({
                "hostname": row.hostname,
                "url": f"https://{row.hostname}/",
                "source": "ct_log_candidate",
                "ct_log_candidate_id": row.id,
                "cert_logged_at": row.cert_logged_at.isoformat() if row.cert_logged_at else None,
            })

        if not candidates:
            data["skipped_reason"] = "no_candidates"
            result.data = data
            return result

        # Dedupe by hostname so a candidate that came from both sources
        # only gets rendered once (preferring lookalike source for the
        # finding metadata).
        seen: set = set()
        deduped: List[Dict[str, Any]] = []
        for c in candidates:
            if c["hostname"] in seen:
                continue
            seen.add(c["hostname"])
            deduped.append(c)

        # Process each candidate through the matcher
        matches: List[Dict[str, Any]] = []
        processed = 0
        for c in deduped:
            try:
                match = _match_candidate(
                    candidate=c,
                    baseline=baseline,
                    brand_keyword=brand_keyword,
                )
            except Exception:
                logger.exception(
                    "mimic_engine: candidate matcher crashed for %s", c["hostname"]
                )
                _mark_processed(c.get("ct_log_candidate_id"), "matcher_crash")
                continue
            processed += 1
            _mark_processed(
                c.get("ct_log_candidate_id"),
                "match" if match and match.get("composite_score", 0) >= 0.4 else "no_match",
            )
            if match:
                matches.append(match)

        data["matches"] = matches
        data["candidates_processed"] = processed
        data["brand_keyword"] = brand_keyword
        result.data = data
        result.metadata = {
            "lookalike_candidates": sum(1 for c in deduped if c["source"] == "lookalike_hit"),
            "ct_log_candidates": sum(1 for c in deduped if c["source"] == "ct_log_candidate"),
        }
        return result


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────


def _mimic_enabled() -> bool:
    return os.environ.get("MIMIC_ENABLED", "").strip().lower() == "true"


def _load_baseline(asset_id: int) -> Optional[Dict[str, Any]]:
    """Read a baseline from DB. Returns a plain dict, not an ORM row,
    so the engine doesn't carry session state through the match loop."""
    try:
        from app.models import MimicBaseline
        row = MimicBaseline.query.filter_by(asset_id=asset_id).first()
    except Exception:
        return None
    if not row:
        return None
    return {
        "structural_hash": row.structural_hash,
        "favicon_phash": row.favicon_phash,
        "visual_phash": row.visual_phash,
        "key_strings": row.key_strings_json or {},
        "baseline_image_key": row.baseline_image_key,
        "captured_at": row.captured_at.isoformat() if row.captured_at else None,
    }


def _mark_processed(candidate_id: Optional[int], status: str) -> None:
    """Tag a ct_log_candidate row as processed. No-op when the candidate
    didn't come from the queue (lookalike-driven candidates have no row)."""
    if candidate_id is None:
        return
    try:
        from app.extensions import db
        from app.models import CtLogCandidate
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        row = db.session.get(CtLogCandidate, candidate_id)
        if row:
            row.processed_at = now
            row.processed_status = status[:20]
            db.session.commit()
    except Exception:
        logger.exception("mimic_engine: mark_processed failed for %s", candidate_id)
        try:
            from app.extensions import db
            db.session.rollback()
        except Exception:
            pass


def _match_candidate(
    *,
    candidate: Dict[str, Any],
    baseline: Dict[str, Any],
    brand_keyword: str,
) -> Optional[Dict[str, Any]]:
    """Run the four-signal matcher for one candidate. Returns a match
    dict if composite_score >= no-finding-threshold, else None."""
    from app.services.page_renderer import render_page
    from app.services.page_signals import (
        composite_score, extract_key_strings, favicon_perceptual_hash,
        hash_similarity, jaccard_similarity, severity_for_composite,
        structural_hash, visual_perceptual_hash,
    )

    url = candidate["url"]

    # Render: gets us HTML + screenshot in one trip
    render = render_page(url)
    if render is None or not render.html:
        return None
    if render.status_code is not None and (render.status_code >= 400):
        return None

    # Cheap signals on the HTML
    cand_struct = structural_hash(render.html)
    cand_keys = extract_key_strings(
        render.html, brand_keywords=[brand_keyword]
    )

    # Favicon — best-effort; fetch via simple GET
    favicon_bytes = _fetch_favicon(render.final_url or url)
    cand_favicon = favicon_perceptual_hash(favicon_bytes) if favicon_bytes else None

    # Visual screenshot
    cand_visual = visual_perceptual_hash(render.screenshot_bytes) if render.screenshot_bytes else None

    # Score each dimension
    structural_score = hash_similarity(cand_struct, baseline.get("structural_hash"))
    favicon_score = hash_similarity(cand_favicon, baseline.get("favicon_phash"))
    visual_score = hash_similarity(cand_visual, baseline.get("visual_phash"))
    baseline_tokens = (baseline.get("key_strings") or {}).get("tokens") or []
    text_score = jaccard_similarity(cand_keys.get("tokens", []), baseline_tokens)

    scores = {
        "structural": structural_score,
        "favicon": favicon_score,
        "text": text_score,
        "visual": visual_score,
    }
    composite = composite_score(scores)
    severity = severity_for_composite(composite)
    if severity is None:
        # Below the no-finding threshold
        return None

    return {
        "hostname": candidate["hostname"],
        "url": url,
        "source": candidate["source"],
        "composite_score": round(composite, 4),
        "signal_scores": {k: round(v, 4) for k, v in scores.items()},
        "severity": severity,
        "screenshot_bytes": render.screenshot_bytes,
        "screenshot_size": len(render.screenshot_bytes or b""),
        "render_ms": render.render_ms,
        "cert_logged_at": candidate.get("cert_logged_at"),
        "title": (cand_keys.get("title") or "")[:255],
        "brand_mentions": cand_keys.get("brand_mentions") or [],
    }


def _fetch_favicon(page_url: str) -> Optional[bytes]:
    """Best-effort favicon fetch. Tries /favicon.ico on the rendered
    page's origin. Returns bytes on success, None otherwise."""
    try:
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(page_url)
        if not parts.scheme or not parts.netloc:
            return None
        favicon_url = urlunsplit((parts.scheme, parts.netloc, "/favicon.ico", "", ""))
        resp = requests.get(
            favicon_url, timeout=FETCH_TIMEOUT,
            headers={"User-Agent": "Nano-EASM-MimicProbe/1.0"},
        )
        if resp.status_code != 200:
            return None
        return resp.content[:512_000]  # 500 KB cap — favicons are small
    except Exception:
        return None
