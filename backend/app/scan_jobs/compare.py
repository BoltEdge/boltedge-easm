# =============================================================================
# File: app/scan_jobs/compare.py
# Description: Scan comparison endpoint — compares findings between two scan
#   jobs for the same asset using dedupe_key matching.
#
# Endpoint:
#   GET /scan-jobs/<job_a>/compare/<job_b> — all roles can view
#
# Returns:
#   - new:       findings in job_b but not job_a (appeared since last scan)
#   - removed:   findings in job_a but not job_b (no longer detected)
#   - unchanged: findings present in both scans
#   - summary:   counts and severity breakdown for each category
# =============================================================================

from __future__ import annotations

import logging
from flask import Blueprint, jsonify
from sqlalchemy import desc

from app.extensions import db
from app.models import Finding, Asset, ScanJob
from app.auth.decorators import require_auth, current_organization_id

# Template registry for summary lookups
try:
    from app.scanner.templates import get_template as _get_template
except ImportError:
    _get_template = None

logger = logging.getLogger(__name__)

compare_bp = Blueprint("scan_compare", __name__, url_prefix="/scan-jobs")


def _sid(x) -> str:
    return str(x) if x is not None else ""


def _finding_to_diff(f: Finding) -> dict:
    """Minimal finding representation for diff display."""
    template_id = getattr(f, "template_id", None)

    summary = None
    if _get_template and template_id:
        tmpl = _get_template(template_id)
        if tmpl:
            summary = tmpl.summary

    return {
        "id": _sid(f.id),
        "title": f.title or "Finding",
        "severity": f.severity or "info",
        "category": getattr(f, "category", None) or "",
        "findingType": f.finding_type or "",
        "description": (f.description or "")[:300],
        "dedupeKey": f.dedupe_key or "",
        "source": f.source or "engine",
        "confidence": getattr(f, "confidence", None),
        "detectedAt": f.created_at.isoformat() if f.created_at else None,
        "details": f.details_json or {},
        "summary": summary,
    }


def _severity_counts(findings: list) -> dict:
    """Count findings by severity."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") if isinstance(f, dict) else (f.severity or "info")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


@compare_bp.get("/<int:job_a_id>/compare/<int:job_b_id>")
@require_auth
def compare_scans(job_a_id: int, job_b_id: int):
    """
    Compare findings between two scan jobs.

    job_a = the older/baseline scan
    job_b = the newer/current scan

    Uses dedupe_key to match findings across scans:
    - new:       dedupe_key in job_b but not in job_a
    - removed:   dedupe_key in job_a but not in job_b
    - unchanged: dedupe_key in both job_a and job_b

    Both jobs must belong to the same asset and organization.
    """
    org_id = current_organization_id()

    # Load both jobs with org check
    job_a = (
        ScanJob.query
        .join(Asset, ScanJob.asset_id == Asset.id)
        .filter(ScanJob.id == job_a_id, Asset.organization_id == org_id)
        .first()
    )
    job_b = (
        ScanJob.query
        .join(Asset, ScanJob.asset_id == Asset.id)
        .filter(ScanJob.id == job_b_id, Asset.organization_id == org_id)
        .first()
    )

    if not job_a or not job_b:
        return jsonify(error="One or both scan jobs not found"), 404

    # Must be same asset
    if job_a.asset_id != job_b.asset_id:
        return jsonify(error="Scan jobs must be for the same asset"), 400

    # Must be completed
    if job_a.status != "completed" or job_b.status != "completed":
        return jsonify(error="Both scan jobs must be completed"), 400

    # Load findings for each job
    findings_a = Finding.query.filter_by(scan_job_id=job_a.id).all()
    findings_b = Finding.query.filter_by(scan_job_id=job_b.id).all()

    # Build dedupe_key → finding maps
    map_a: dict = {}
    for f in findings_a:
        key = f.dedupe_key or f"no-key-{f.id}"
        map_a[key] = f

    map_b: dict = {}
    for f in findings_b:
        key = f.dedupe_key or f"no-key-{f.id}"
        map_b[key] = f

    keys_a = set(map_a.keys())
    keys_b = set(map_b.keys())

    # Compute diff
    new_keys = keys_b - keys_a
    removed_keys = keys_a - keys_b
    unchanged_keys = keys_a & keys_b

    new_findings = [_finding_to_diff(map_b[k]) for k in new_keys]
    removed_findings = [_finding_to_diff(map_a[k]) for k in removed_keys]
    unchanged_findings = [_finding_to_diff(map_b[k]) for k in unchanged_keys]

    # Sort each group: critical first
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sort_fn = lambda f: (sev_order.get(f["severity"], 5), f["title"])

    new_findings.sort(key=sort_fn)
    removed_findings.sort(key=sort_fn)
    unchanged_findings.sort(key=sort_fn)

    # Job metadata
    asset = Asset.query.get(job_a.asset_id)

    # Profile names
    profile_a_name = None
    profile_b_name = None
    if job_a.profile_id:
        from app.models import ScanProfile
        pa = ScanProfile.query.get(job_a.profile_id)
        if pa:
            profile_a_name = pa.name
    if job_b.profile_id:
        from app.models import ScanProfile
        pb = ScanProfile.query.get(job_b.profile_id)
        if pb:
            profile_b_name = pb.name

    return jsonify(
        assetId=_sid(job_a.asset_id),
        assetValue=asset.value if asset else None,
        assetType=asset.asset_type if asset else None,

        jobA={
            "id": _sid(job_a.id),
            "status": job_a.status,
            "profileName": profile_a_name,
            "startedAt": job_a.started_at.isoformat() if job_a.started_at else None,
            "finishedAt": job_a.finished_at.isoformat() if job_a.finished_at else None,
            "findingCount": len(findings_a),
        },
        jobB={
            "id": _sid(job_b.id),
            "status": job_b.status,
            "profileName": profile_b_name,
            "startedAt": job_b.started_at.isoformat() if job_b.started_at else None,
            "finishedAt": job_b.finished_at.isoformat() if job_b.finished_at else None,
            "findingCount": len(findings_b),
        },

        new=new_findings,
        removed=removed_findings,
        unchanged=unchanged_findings,

        summary={
            "newCount": len(new_findings),
            "removedCount": len(removed_findings),
            "unchangedCount": len(unchanged_findings),
            "newSeverity": _severity_counts(new_findings),
            "removedSeverity": _severity_counts(removed_findings),
        },
    ), 200