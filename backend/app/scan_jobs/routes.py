# =============================================================================
# File: app/scan_jobs/routes.py
# Description: Scan job routes — create, list, execute, delete scan jobs.
#   M7 UPDATE: run_scan_job uses ScanOrchestrator with legacy fallback.
#   Background thread execution for non-blocking HTTP responses.
#
# Permissions Integration (based on permissions integration guide):
#   - GET /scan-jobs: all roles can view
#   - POST /scan-jobs: analyst+ with scans_per_month limit + scan profile check
#   - POST /scan-jobs/<id>/run: analyst+
#   - DELETE /scan-jobs/<id>: analyst+
#   - GET /scan-jobs/<id>/findings: all roles can view
#   - GET /scan-jobs/export: admin+ (export_scan_results permission)
#     — not yet implemented in this file
#   - POST /scan-jobs/bulk: admin+ (bulk_scan permission) with scans_per_month
#     limit + scan profile check — not yet implemented in this file
# =============================================================================

from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
import logging
from flask import Blueprint, request, jsonify

from app.extensions import db

# Template registry for summary lookups
try:
    from app.scanner.templates import get_template as _get_template
except ImportError:
    _get_template = None
from app.models import ScanJob, Asset, Finding, AssetGroup, ScanProfile
from app.auth.decorators import require_auth, current_user_id, current_organization_id
from app.auth.permissions import require_role, check_limit, check_scan_profile
from app.audit.routes import log_audit

logger = logging.getLogger(__name__)

scan_jobs_bp = Blueprint("scan_jobs", __name__, url_prefix="/scan-jobs")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sid(x) -> str:
    return str(x) if x is not None else ""


def scanjob_to_ui(j: ScanJob) -> dict:
    asset = j.asset
    group = asset.group if asset else None

    # Resolve profile name
    profile_name = None
    if j.profile_id:
        profile = ScanProfile.query.filter_by(id=j.profile_id).first()
        if profile:
            profile_name = profile.name

    return {
        "id": _sid(j.id),
        "assetId": _sid(j.asset_id),
        "assetValue": asset.value if asset else None,
        "assetType": asset.asset_type if asset else None,
        "groupId": _sid(group.id) if group else None,
        "groupName": group.name if group else None,
        "profileId": _sid(j.profile_id),
        "profileName": profile_name,
        "status": j.status,
        "createdAt": j.created_at.isoformat() if j.created_at else None,
        "startedAt": j.started_at.isoformat() if j.started_at else None,
        "finishedAt": j.finished_at.isoformat() if j.finished_at else None,
        "error": j.error_message,
    }


def now_utc():
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Legacy helpers (kept as fallback — used only if orchestrator unavailable)
# ---------------------------------------------------------------------------

def _stable_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def build_dedupe_key(*, organization_id: int, asset_id: int, finding_type: str, details: dict) -> str:
    """Build dedupe key scoped to organization (legacy path)."""
    scope = {
        "ip": details.get("ip"),
        "port": details.get("port"),
        "transport": details.get("transport"),
        "cve": details.get("cve"),
        "product": details.get("product"),
        "version": details.get("version"),
        "service_label": details.get("service_label"),
    }
    base = {
        "organization_id": organization_id,
        "asset_id": asset_id,
        "finding_type": finding_type,
        "scope": scope,
    }
    return hashlib.sha1(_stable_json(base).encode("utf-8")).hexdigest()


def persist_findings(asset, job, findings):
    """Persist findings from scan results with deduplication."""
    created = 0
    updated = 0
    now = now_utc()

    for f in findings:
        ftype = (f.get("finding_type") or "unknown").strip()
        details = f.get("details_json") or {}

        dedupe_key = build_dedupe_key(
            organization_id=int(asset.organization_id),
            asset_id=int(asset.id),
            finding_type=ftype,
            details=details,
        )

        prev = (
            Finding.query.filter_by(asset_id=asset.id, dedupe_key=dedupe_key)
            .order_by(Finding.id.desc())
            .first()
        )

        if prev:
            # ── Duplicate found: update existing, skip creation ──
            prev.last_seen_at = now
            prev.scan_job_id = job.id  # Link to latest scan
            # Update severity/title/description if changed
            prev.severity = f.get("severity") or prev.severity
            prev.title = f.get("title") or prev.title
            prev.description = f.get("description") or prev.description
            prev.details_json = details or prev.details_json
            db.session.add(prev)
            updated += 1
            continue  # ← THIS WAS MISSING — skip to next finding

        # ── New finding: create it ──
        db.session.add(
            Finding(
                asset_id=asset.id,
                scan_job_id=job.id,
                source=f.get("source") or "engine",
                finding_type=ftype,
                dedupe_key=dedupe_key,
                first_seen_at=now,
                last_seen_at=now,
                title=f.get("title") or "Finding",
                severity=(f.get("severity") or "info"),
                description=f.get("description") or "",
                details_json=details,
                created_at=now,
            )
        )
        created += 1

    logger.info(f"persist_findings: {created} created, {updated} updated (deduped) for asset {asset.id}")
    return created



def extract_shodan_findings(shodan_results: dict) -> list:
    """Convert Shodan scan results to findings format (legacy path)."""
    findings = []

    current = shodan_results.get("current", {})
    for service in current.get("services", []):
        findings.append({
            "source": "shodan",
            "finding_type": "open_port",
            "title": f"Open Port {service['port']}/{service.get('transport', 'tcp')}",
            "severity": "info",
            "description": f"Port {service['port']} is open running {service.get('product', 'unknown service')}",
            "details_json": {
                "ip": current.get("ip"),
                "port": service["port"],
                "transport": service.get("transport"),
                "product": service.get("product"),
                "version": service.get("version"),
            },
        })

    for cve in shodan_results.get("cves", []):
        severity = "high" if cve.get("cvss", 0) >= 7 else "medium"
        findings.append({
            "source": "shodan",
            "finding_type": "cve",
            "title": f"Vulnerability {cve['cve_id']}",
            "severity": severity,
            "description": cve.get("summary", "No description available"),
            "details_json": {
                "cve": cve["cve_id"],
                "cvss": cve.get("cvss"),
            },
        })

    return findings


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

# POST /scan-jobs — analyst+ with scans_per_month limit + scan profile check
@scan_jobs_bp.post("")
@require_auth
@require_role("analyst")
@check_limit("scans_per_month")
@check_scan_profile()
def create_scan_job():
    """Create a new scan job with optional profile."""
    org_id = current_organization_id()
    uid = current_user_id()

    body = request.get_json(silent=True) or {}
    asset_id = body.get("assetId") or body.get("asset_id")
    profile_id = body.get("profileId") or body.get("profile_id")

    if not asset_id:
        return jsonify(error="assetId is required"), 400

    asset = Asset.query.filter_by(id=int(asset_id), organization_id=org_id).first()
    if not asset:
        return jsonify(error="asset not found"), 404

    # Get profile (use default if not specified)
    profile = None
    if profile_id:
        profile = ScanProfile.query.filter_by(id=int(profile_id)).first()
        if not profile:
            return jsonify(error="profile not found"), 404
        if not profile.is_system and profile.organization_id != org_id:
            return jsonify(error="access denied to this profile"), 403
    else:
        profile = (
            ScanProfile.query
            .filter_by(is_system=True, is_default=True, is_active=True)
            .first()
        )

    job = ScanJob(
        asset_id=asset.id,
        status="queued",
        profile_id=profile.id if profile else None,
    )
    db.session.add(job)
    db.session.flush()  # get job.id before logging

    log_audit(
        organization_id=org_id,
        user_id=uid,
        action="scan.created",
        category="scan",
        target_type="scan_job",
        target_id=str(job.id),
        target_label=asset.value,
        description=f"Created scan job for {asset.value}" + (f" with profile {profile.name}" if profile else ""),
        metadata={"asset_id": str(asset.id), "profile": profile.name if profile else None},
    )

    db.session.commit()

    result = scanjob_to_ui(job)
    if profile:
        result["profileId"] = str(profile.id)
        result["profileName"] = profile.name

    return jsonify(result), 201


# GET /scan-jobs — all roles can view
@scan_jobs_bp.get("")
@require_auth
def list_scan_jobs():
    org_id = current_organization_id()

    jobs = (
        ScanJob.query
        .join(Asset, ScanJob.asset_id == Asset.id)
        .join(AssetGroup, Asset.group_id == AssetGroup.id)
        .filter(Asset.organization_id == org_id)
        .options(db.joinedload(ScanJob.asset).joinedload(Asset.group))
        .order_by(ScanJob.id.desc())
        .all()
    )

    return jsonify([scanjob_to_ui(j) for j in jobs]), 200


# POST /scan-jobs/<id>/run — analyst+
@scan_jobs_bp.post("/<job_id>/run")
@require_auth
@require_role("analyst")
def run_scan_job(job_id: str):
    """
    Execute a scan job.

    M7: Runs the scan in a background thread so the HTTP request
    returns immediately. The frontend polls job status via GET.

    For Quick scans (Shodan-only), this completes in ~5s.
    For Standard/Deep scans, this can take 1-10 minutes.
    """
    import threading

    org_id = current_organization_id()
    uid = current_user_id()

    job = (
        ScanJob.query.join(Asset, ScanJob.asset_id == Asset.id)
        .filter(ScanJob.id == int(job_id), Asset.organization_id == org_id)
        .first()
    )

    if not job:
        return jsonify(error="scan job not found"), 404

    if job.status != "queued":
        return jsonify(error="scan job is not in queued state"), 400

    asset = job.asset

    # Get profile
    profile = None
    if job.profile_id:
        profile = ScanProfile.query.filter_by(id=job.profile_id).first()
    if not profile:
        profile = (
            ScanProfile.query
            .filter_by(is_system=True, is_default=True, is_active=True)
            .first()
        )

    # Mark as running immediately
    job.status = "running"
    job.started_at = now_utc()
    asset.scan_status = "scan_pending"

    # Get IDs for the background thread (avoid detached instance issues)
    job_id_int = job.id
    asset_id_int = asset.id
    asset_value = asset.value
    profile_id_int = profile.id if profile else None
    profile_name = profile.name if profile else None

    log_audit(
        organization_id=org_id,
        user_id=uid,
        action="scan.started",
        category="scan",
        target_type="scan_job",
        target_id=str(job_id_int),
        target_label=asset_value,
        description=f"Started scan for {asset_value}",
        metadata={"profile": profile_name},
    )

    db.session.commit()

    # Get the Flask app for the background thread's app context
    from flask import current_app
    app = current_app._get_current_object()

    def _run_in_background():
        """Execute the scan inside a fresh app context."""
        with app.app_context():
            bg_job = db.session.get(ScanJob, job_id_int)
            bg_asset = db.session.get(Asset, asset_id_int)
            bg_profile = db.session.get(ScanProfile, profile_id_int) if profile_id_int else None

            if not bg_job or not bg_asset:
                logger.error(f"Background scan: job {job_id_int} or asset {asset_id_int} not found")
                return

            try:
                result_summary = _run_with_orchestrator(bg_job, bg_asset, bg_profile)

                bg_job.result_json = result_summary
                bg_job.status = "completed"
                bg_job.finished_at = now_utc()
                bg_asset.last_scan_at = bg_job.finished_at
                bg_asset.scan_status = "scanned"

                log_audit(
                    organization_id=bg_asset.organization_id,
                    action="scan.completed",
                    category="scan",
                    target_type="scan_job",
                    target_id=str(job_id_int),
                    target_label=bg_asset.value,
                    description=f"Scan completed for {bg_asset.value}",
                )

            except Exception as e:
                logger.exception(f"Background scan job {bg_job.id} failed for {bg_asset.value}")
                bg_job.status = "failed"
                bg_job.error_message = str(e)[:500]
                bg_job.finished_at = now_utc()
                bg_asset.scan_status = "scan_failed"

                log_audit(
                    organization_id=bg_asset.organization_id,
                    action="scan.failed",
                    category="scan",
                    target_type="scan_job",
                    target_id=str(job_id_int),
                    target_label=bg_asset.value,
                    description=f"Scan failed for {bg_asset.value}: {str(e)[:200]}",
                )

            db.session.commit()
            logger.info(f"Background scan job {job_id_int} finished: {bg_job.status}")

    thread = threading.Thread(target=_run_in_background, daemon=True)
    thread.start()

    return jsonify(
        message="scan started",
        jobId=str(job_id_int),
        status="running",
    ), 202


def _run_with_orchestrator(
    job: ScanJob,
    asset: Asset,
    profile: ScanProfile | None,
) -> dict:
    """
    Run scan using the M7 orchestrator.
    Falls back to legacy path if orchestrator import fails.
    """
    try:
        from app.scanner import ScanOrchestrator

        orchestrator = ScanOrchestrator()
        return orchestrator.execute(job, profile)

    except ImportError:
        logger.warning("ScanOrchestrator not available, falling back to legacy scan")
        return _run_legacy(job, asset, profile)


def _run_legacy(
    job: ScanJob,
    asset: Asset,
    profile: ScanProfile | None,
) -> dict:
    """
    Legacy scan path — used as fallback if orchestrator isn't available.
    This is the old code from the original run_scan_job route.
    """
    try:
        from app.scanners.profile_scanner import scanner as legacy_scanner

        if profile:
            scan_result = legacy_scanner.scan_with_profile(asset, profile)

            job.scan_engines = {
                "shodan": profile.use_shodan,
                "nmap": profile.use_nmap,
                "nuclei": profile.use_nuclei,
                "sslyze": profile.use_sslyze,
            }

            findings = []
            if "shodan" in scan_result.get("engines", {}):
                findings = extract_shodan_findings(scan_result["engines"]["shodan"])

            created = persist_findings(asset, job, findings)

            return {
                "profileName": profile.name,
                "engines": list(scan_result.get("engines", {}).keys()),
                "findingsCreated": created,
                "scanResult": scan_result,
                "_legacy": True,
            }
    except ImportError:
        pass

    # Final fallback: old unified scan
    from app.engine import run_unified_scan

    result = run_unified_scan(
        asset_type=asset.asset_type,
        value=asset.value,
        max_ips=5,
    )
    created = persist_findings(asset, job, result.findings)

    return {
        "summary": result.summary,
        "risk": result.risk,
        "findingsCreated": created,
        "_legacy": True,
    }


# DELETE /scan-jobs/<id> — analyst+
@scan_jobs_bp.delete("/<job_id>")
@require_auth
@require_role("analyst")
def delete_scan_job(job_id: str):
    org_id = current_organization_id()

    job = (
        ScanJob.query.join(Asset, ScanJob.asset_id == Asset.id)
        .filter(ScanJob.id == int(job_id), Asset.organization_id == org_id)
        .first()
    )

    if not job:
        return jsonify(error="scan job not found"), 404

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="scan.deleted",
        category="scan",
        target_type="scan_job",
        target_id=str(job.id),
        target_label=job.asset.value if job.asset else None,
        description=f"Deleted scan job {job.id}",
    )

    db.session.delete(job)
    db.session.commit()

    return jsonify(message="deleted", jobId=str(job.id)), 200


# GET /scan-jobs/<id>/findings — all roles can view
@scan_jobs_bp.get("/<job_id>/findings")
@require_auth
def list_job_findings(job_id: str):
    org_id = current_organization_id()

    job = (
        ScanJob.query.join(Asset, ScanJob.asset_id == Asset.id)
        .filter(ScanJob.id == int(job_id), Asset.organization_id == org_id)
        .first()
    )

    if not job:
        return jsonify(error="scan job not found"), 404

    rows = Finding.query.filter_by(scan_job_id=job.id).order_by(Finding.id.desc()).all()

    return jsonify([{
        "id": str(f.id),
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "details": f.details_json,
        "detectedAt": f.created_at.isoformat() if f.created_at else None,
        # M7 enrichment fields
        "category": getattr(f, "category", None),
        "remediation": getattr(f, "remediation", None),
        "cwe": getattr(f, "cwe", None),
        "confidence": getattr(f, "confidence", None),
        "tags": getattr(f, "tags_json", None),
        "references": getattr(f, "references_json", None),
        # Human-readable summary from template registry
        "summary": (
            _get_template(f.template_id).summary
            if _get_template and getattr(f, "template_id", None)
            and _get_template(f.template_id)
            else None
        ),
    } for f in rows]), 200