# =============================================================================
# File: app/scan_jobs/executor.py
# Description: Shared scan-job executor used by both the manual-scan POST
#   route and the scan scheduler. Consolidating the path removed the
#   architectural drift that caused SC0178-class TypeErrors — scheduled
#   scans used to run through a separate legacy module whose
#   _persist_findings constructor used stale column names that no longer
#   matched the Finding model.
#
# Lifecycle: queued/running -> completed | failed | cancelled
#
# Callers:
#   * Manual scan (POST /scan-jobs/<id>/run): the route marks the job
#     running + writes the scan.started audit, then spawns a daemon
#     thread that calls execute_scan_job. The executor sees status =
#     'running' and skips the queued->running transition block.
#   * Scheduler (APScheduler tick): _execute_schedule creates the queued
#     ScanJob and calls execute_scan_job synchronously inside the tick.
#     The executor sees status = 'queued' and handles the transition +
#     scan.started audit itself.
#
# Both callers share orchestrator-first execution, cancellation
# semantics, error mapping (user_facing_error_message), and audit
# logging (scan.completed / scan.failed). _run_legacy stays as the
# ImportError safety net — it uses the modern persist_findings helper
# from scan_jobs.routes, not the broken finder in the old scheduler.
# =============================================================================

from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.extensions import db
from app.models import ScanJob, Asset, ScanProfile
from app.audit.routes import log_audit


logger = logging.getLogger(__name__)


def _now_utc():
    return datetime.now(timezone.utc)


def execute_scan_job(job_id: int, app, profile_id: int | None = None) -> None:
    """
    Run a scan job through the modern orchestrator end-to-end.

    Always commits at the end with a final status of completed / failed /
    cancelled. Never raises — every exception is caught, logged with a
    full traceback, and mapped to a short user_facing_error_message
    stored on ``ScanJob.error_message``.

    ``app`` is the Flask app object (typically ``current_app._get_current_object()``).
    The executor enters ``app.app_context()`` itself so it can be called
    from a daemon thread that has no context. Nested entries are safe;
    Flask app contexts are LIFO.

    ``profile_id`` is honoured when provided; otherwise the job's
    ``profile_id`` is used; otherwise the default system profile.
    """
    with app.app_context():
        job = db.session.get(ScanJob, job_id)
        if not job:
            logger.error("execute_scan_job: job %s not found", job_id)
            return

        asset = db.session.get(Asset, job.asset_id)
        if not asset:
            logger.error(
                "execute_scan_job: asset %s for job %s not found",
                job.asset_id, job_id,
            )
            return

        profile = None
        if profile_id is not None:
            profile = db.session.get(ScanProfile, profile_id)
        elif job.profile_id:
            profile = db.session.get(ScanProfile, job.profile_id)

        if not profile:
            profile = (
                ScanProfile.query
                .filter_by(is_system=True, is_default=True, is_active=True)
                .first()
            )

        # Scheduler path: job is still 'queued'. Transition + write the
        # scan.started audit so scheduled scans leave the same trail as
        # manual ones. Manual route already did this before spawning the
        # thread, so the block is skipped when status is already 'running'.
        if job.status == "queued":
            job.status = "running"
            job.started_at = _now_utc()
            asset.scan_status = "scan_pending"
            log_audit(
                organization_id=asset.organization_id,
                action="scan.started",
                category="scan",
                target_type="scan_job",
                target_id=str(job.id),
                target_label=asset.value,
                description=f"Started scan for {asset.value}",
                metadata={"profile": profile.name if profile else None},
            )
            db.session.commit()

        try:
            result_summary = _run_with_orchestrator(job, asset, profile)

            # Cancellation race: a user/admin may have cancelled while
            # the orchestrator was running. Don't overwrite 'cancelled'.
            db.session.refresh(job)
            if job.status == "cancelled":
                logger.info(
                    "Scan job %s was cancelled; discarding results", job.id
                )
                db.session.commit()
                return

            job.result_json = result_summary
            job.status = "completed"
            job.finished_at = _now_utc()
            asset.last_scan_at = job.finished_at
            asset.scan_status = "scanned"

            log_audit(
                organization_id=asset.organization_id,
                action="scan.completed",
                category="scan",
                target_type="scan_job",
                target_id=str(job.id),
                target_label=asset.value,
                description=f"Scan completed for {asset.value}",
            )

        except Exception as e:
            logger.exception(
                "Scan job %s failed for %s", job.id, asset.value
            )

            # Same cancellation race on the error side — if the user
            # cancelled while the orchestrator was raising, keep their
            # final status, don't overwrite with 'failed'.
            db.session.refresh(job)
            if job.status == "cancelled":
                db.session.commit()
                return

            from app.scanner.errors import user_facing_error_message
            friendly = user_facing_error_message(e)

            job.status = "failed"
            job.error_message = friendly
            job.finished_at = _now_utc()
            asset.scan_status = "scan_failed"

            log_audit(
                organization_id=asset.organization_id,
                action="scan.failed",
                category="scan",
                target_type="scan_job",
                target_id=str(job.id),
                target_label=asset.value,
                description=f"Scan failed for {asset.value}: {friendly}",
            )

        db.session.commit()
        logger.info("Scan job %s finished: %s", job.id, job.status)


def _run_with_orchestrator(
    job: ScanJob,
    asset: Asset,
    profile: ScanProfile | None,
) -> dict:
    """Run via the M7 orchestrator. ImportError falls back to legacy."""
    try:
        from app.scanner import ScanOrchestrator

        orchestrator = ScanOrchestrator()
        return orchestrator.execute(job, profile)

    except ImportError:
        logger.warning(
            "ScanOrchestrator not available; falling back to legacy scan path"
        )
        return _run_legacy(job, asset, profile)


def _run_legacy(
    job: ScanJob,
    asset: Asset,
    profile: ScanProfile | None,
) -> dict:
    """
    ImportError-only fallback. Uses the modern persist_findings helper
    from scan_jobs.routes, not the stale-column-name persister that used
    to live in app/scheduler.py.
    """
    # Lazy imports to dodge a circular import with scan_jobs.routes,
    # which imports execute_scan_job from this module.
    try:
        from app.scanners.profile_scanner import scanner as legacy_scanner
        from app.scan_jobs.routes import (
            extract_shodan_findings,
            persist_findings,
        )

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

    # Final fallback: unified scan engine
    from app.engine import run_unified_scan
    from app.scan_jobs.routes import persist_findings

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
