# app/scanner/analyzers/exposure_scorer.py
"""
Exposure Scorer Analyzer.

Runs LAST after all other analyzers. Reads all FindingDrafts produced
so far and computes an overall exposure score for the asset.

Scoring methodology (per-asset):
    Uses the centralized formula from app.utils.scoring which applies
    severity-weighted scoring with diminishing returns and tier caps.

    Letter grades:
        A: 0-14   (excellent — minimal exposure)
        B: 15-29  (good — low-severity findings only)
        C: 30-49  (moderate — some concerning findings)
        D: 50-69  (significant — high-severity findings present)
        F: 70-100 (critical — immediate remediation required)

Produces:
    - A single finding with the overall exposure score, grade, and breakdown
    - This is used by the dashboard to show the asset's risk level
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext
from app.utils.scoring import calc_exposure_score, exposure_grade

logger = logging.getLogger(__name__)


class ExposureScorer(BaseAnalyzer):
    """
    Computes an overall exposure score from all findings.

    This analyzer MUST run last — it reads ctx.finding_drafts which
    are populated by all previous analyzers.
    """

    @property
    def name(self) -> str:
        return "exposure_scorer"

    @property
    def required_engines(self) -> List[str]:
        return ["shodan"]

    def can_run(self, ctx: ScanContext) -> bool:
        """Override: always run if there are any finding drafts."""
        return len(ctx.finding_drafts) > 0

    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        drafts = ctx.finding_drafts

        if not drafts:
            return [self._clean_score_finding(ctx)]

        # --- Count severities ---
        severity_counts: Dict[str, int] = defaultdict(int)
        for d in drafts:
            sev = (d.severity or "info").lower()
            severity_counts[sev] += 1

        # --- Calculate score using centralized formula ---
        exposure_score = calc_exposure_score(
            critical=severity_counts.get("critical", 0),
            high=severity_counts.get("high", 0),
            medium=severity_counts.get("medium", 0),
            low=severity_counts.get("low", 0),
            info=severity_counts.get("info", 0),
        )

        # --- Grade (aligned with centralized grading) ---
        grade, grade_desc = exposure_grade(exposure_score)

        # --- Category breakdown ---
        category_breakdown: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        )
        for d in drafts:
            cat = d.category or "other"
            sev = (d.severity or "info").lower()
            category_breakdown[cat]["count"] += 1
            if sev in ("critical", "high", "medium", "low"):
                category_breakdown[cat][sev] += 1

        # Sort categories by severity impact
        def _cat_sort_key(item):
            v = item[1]
            return (v.get("critical", 0) * 4 + v.get("high", 0) * 3 +
                    v.get("medium", 0) * 2 + v.get("low", 0))
        sorted_categories = dict(
            sorted(category_breakdown.items(), key=_cat_sort_key, reverse=True)
        )

        # --- Top issues (highest severity findings) ---
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            drafts,
            key=lambda d: severity_order.get((d.severity or "info").lower(), 5)
        )
        top_issues = []
        for d in sorted_findings[:10]:
            top_issues.append({
                "title": d.title,
                "severity": d.severity,
                "category": d.category,
                "template_id": d.template_id,
            })

        # --- Build the score finding ---
        finding_count = len(drafts)
        actionable_count = sum(
            1 for d in drafts if (d.severity or "info").lower() in ("critical", "high", "medium")
        )

        title = (
            f"Exposure Score: {exposure_score}/100 (Grade {grade}) — "
            f"{finding_count} findings, {actionable_count} actionable"
        )

        description = (
            f"Overall exposure assessment for {ctx.asset_value}. "
            f"Grade: {grade} — {grade_desc}. "
            f"Found {severity_counts.get('critical', 0)} critical, "
            f"{severity_counts.get('high', 0)} high, "
            f"{severity_counts.get('medium', 0)} medium, "
            f"{severity_counts.get('low', 0)} low, and "
            f"{severity_counts.get('info', 0)} informational findings."
        )

        # Remediation priority
        remediation_parts = []
        if severity_counts.get("critical", 0) > 0:
            remediation_parts.append(
                f"Fix {severity_counts['critical']} critical finding(s) immediately."
            )
        if severity_counts.get("high", 0) > 0:
            remediation_parts.append(
                f"Address {severity_counts['high']} high-severity finding(s) this week."
            )
        if severity_counts.get("medium", 0) > 0:
            remediation_parts.append(
                f"Plan fixes for {severity_counts['medium']} medium finding(s)."
            )
        remediation = " ".join(remediation_parts) if remediation_parts else "No critical issues found."

        return [FindingDraft(
            template_id="exposure-score",
            title=title,
            severity="info",
            category="score",
            description=description,
            remediation=remediation,
            finding_type="exposure_score",
            tags=["score", f"grade-{grade.lower()}"],
            engine="orchestrator",
            confidence="high",
            details={
                "exposure_score": exposure_score,
                "grade": grade,
                "grade_description": grade_desc,
                "severity_counts": dict(severity_counts),
                "category_breakdown": sorted_categories,
                "top_issues": top_issues,
                "total_findings": finding_count,
                "actionable_findings": actionable_count,
            },
            dedupe_fields={
                "check": "exposure_score",
            },
        )]

    def _clean_score_finding(self, ctx: ScanContext) -> FindingDraft:
        """Generate a clean score when no findings were produced."""
        return FindingDraft(
            template_id="exposure-score",
            title=f"Exposure Score: 0/100 (Grade A) — No issues found",
            severity="info",
            category="score",
            description=(
                f"No security issues were detected for {ctx.asset_value}. "
                "This is an excellent result. Continue monitoring regularly."
            ),
            finding_type="exposure_score",
            tags=["score", "grade-a"],
            engine="orchestrator",
            confidence="high",
            details={
                "exposure_score": 0,
                "grade": "A",
                "grade_description": "Excellent — minimal exposure",
                "severity_counts": {},
                "category_breakdown": {},
                "top_issues": [],
                "total_findings": 0,
                "actionable_findings": 0,
            },
            dedupe_fields={
                "check": "exposure_score",
            },
        )