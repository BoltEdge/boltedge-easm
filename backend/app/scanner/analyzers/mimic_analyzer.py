# app/scanner/analyzers/mimic_analyzer.py
"""
MimicAnalyzer — converts engine matches into FindingDraft rows.

One finding per match. The engine has already done the matching and
scoring; the analyzer's job is to:

  - Upload the screenshot to S3 (subject to per-org cap)
  - Build the FindingDraft with severity from the composite bucket
  - Tag with site-mimic + source-of-discovery
  - Carry per-signal scores and screenshot URL in details_json

Findings carry:
  category = lookalike     (reuses Lookalike Domains customer cat)
  finding_type = mimic
  tag = site-mimic
  template_id = mimic-detected

Storage cap behaviour: if the upload is refused (over cap, S3 down),
the finding still lands — just without the screenshot URL. A
mimic_storage_full flag in details_json drives the UI banner.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext


logger = logging.getLogger(__name__)


class MimicAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "mimic_analyzer"

    @property
    def required_engines(self) -> List[str]:
        return ["mimic"]

    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        engine_data = ctx.get_engine_data("mimic")
        matches = engine_data.get("matches") or []
        if not matches:
            return []

        # Get the org's storage cap once for this batch
        cap_bytes = _plan_cap_bytes(ctx.organization_id)
        current_usage = _current_storage_bytes(ctx.organization_id)

        drafts: List[FindingDraft] = []
        for m in matches:
            if not isinstance(m, dict):
                continue
            draft = self._build_draft(
                ctx=ctx, match=m,
                cap_bytes=cap_bytes,
                current_usage_bytes=current_usage,
            )
            if draft is None:
                continue
            # Update usage on the fly so subsequent uploads in this
            # batch respect the cap correctly.
            uploaded_size = draft.details.get("mimic_screenshot_size", 0)
            if uploaded_size and draft.details.get("mimic_screenshot_url"):
                current_usage += int(uploaded_size)
            drafts.append(draft)

        return drafts

    def _build_draft(
        self,
        *,
        ctx: ScanContext,
        match: Dict[str, Any],
        cap_bytes: Optional[int],
        current_usage_bytes: int,
    ) -> Optional[FindingDraft]:
        from app.scanner.templates import get_template
        from app.services.mimic_storage import upload_screenshot

        template = get_template("mimic-detected")
        if template is None:
            logger.warning("Missing mimic template: mimic-detected")
            return None

        hostname = match.get("hostname") or ""
        if not hostname:
            return None
        severity = match.get("severity") or "low"

        # Upload screenshot — best-effort; over-cap orgs proceed without
        screenshot_bytes = match.get("screenshot_bytes") or b""
        storage_result = upload_screenshot(
            screenshot_bytes,
            kind="finding",
            organization_id=ctx.organization_id,
            asset_id=ctx.asset_id,
            finding_id=None,  # we don't know the finding row's id yet
            cap_bytes=cap_bytes,
            current_usage_bytes=current_usage_bytes,
        )

        details = {
            "value": hostname,
            "hostname": hostname,
            "candidate_url": match.get("url"),
            "input_source": match.get("source"),
            "composite_score": match.get("composite_score"),
            "signal_scores": match.get("signal_scores") or {},
            "cert_logged_at": match.get("cert_logged_at"),
            "candidate_title": match.get("title"),
            "brand_mentions": match.get("brand_mentions") or [],
            "render_ms": match.get("render_ms"),
            "mimic_screenshot_url": storage_result.public_url,
            "mimic_screenshot_key": storage_result.s3_key,
            "mimic_screenshot_size": storage_result.size_bytes,
            "mimic_storage_full": (
                storage_result.refused_reason == "plan_cap_exceeded"
            ),
            "mimic_storage_refused_reason": storage_result.refused_reason,
        }

        # Build copy via the template
        title = (template.title or "Site mimic detected: {asset}").replace(
            "{asset}", hostname
        )
        description = (template.description or "").replace(
            "{asset}", ctx.asset_value
        ).replace("{candidate}", hostname)
        remediation = (template.remediation or "").replace(
            "{asset}", ctx.asset_value
        ).replace("{candidate}", hostname)

        return FindingDraft(
            template_id="mimic-detected",
            title=title[:255],
            severity=severity,
            category=template.category or "lookalike",
            description=description[:2000],
            remediation=remediation or None,
            finding_type="mimic",
            cwe=template.cwe,
            references=list(template.references),
            tags=list(template.tags) + ["site-mimic", match.get("source") or "unknown"],
            engine="mimic",
            confidence="high" if match.get("composite_score", 0) >= 0.85 else "medium",
            details=details,
            dedupe_fields={"hostname": hostname},
        )


# ─────────────────────────────────────────────────────────────────────
# Plan-cap helpers — kept module-private so we don't bleed plan logic
# into the analyzer pipeline.
# ─────────────────────────────────────────────────────────────────────


def _plan_cap_bytes(organization_id: int) -> Optional[int]:
    """Return the org's mimic_storage_mb cap as bytes. -1 / unlimited
    returns -1 (interpreted as 'no cap' by mimic_storage). 0 means
    feature unavailable."""
    try:
        from app.models import Organization
        from app.billing.routes import get_effective_limits
        org = Organization.query.get(organization_id)
        if not org:
            return 0
        limits = get_effective_limits(org)
        cap_mb = int(limits.get("mimic_storage_mb", 0) or 0)
        if cap_mb < 0:
            return -1
        return cap_mb * 1024 * 1024
    except Exception:
        logger.exception("mimic_analyzer: plan cap lookup failed")
        return 0


def _current_storage_bytes(organization_id: int) -> int:
    """Current usage. Patched in tests."""
    try:
        from app.services.mimic_storage import mimic_storage_used_for_org
        return mimic_storage_used_for_org(organization_id)
    except Exception:
        return 0
