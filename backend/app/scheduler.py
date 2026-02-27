# app/scheduler.py
"""
Background Scheduler for Scan Schedules
────────────────────────────────────────
Uses APScheduler to check for due schedules every 60 seconds.
When a schedule is due, it creates scan jobs and executes them.

Setup in your app factory (__init__.py):
    from app.scheduler import init_scheduler
    init_scheduler(app)

Requirements:
    pip install APScheduler --break-system-packages
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger("scheduler")
logger.setLevel(logging.INFO)

_scheduler: BackgroundScheduler | None = None


def now_utc():
    return datetime.now(timezone.utc)


def _compute_next_run(frequency, time_of_day, day_of_week=None, day_of_month=None):
    now = now_utc()
    hh, mm = (int(x) for x in time_of_day.split(":"))

    if frequency == "daily":
        candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate

    if frequency == "weekly" and day_of_week is not None:
        candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        days_ahead = day_of_week - now.weekday()
        if days_ahead < 0 or (days_ahead == 0 and candidate <= now):
            days_ahead += 7
        candidate += timedelta(days=days_ahead)
        return candidate

    if frequency == "monthly" and day_of_month is not None:
        candidate = now.replace(
            day=min(day_of_month, 28), hour=hh, minute=mm, second=0, microsecond=0
        )
        if candidate <= now:
            if now.month == 12:
                candidate = candidate.replace(year=now.year + 1, month=1)
            else:
                candidate = candidate.replace(month=now.month + 1)
        return candidate

    candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=1)
    return candidate


def _process_due_schedules(app):
    """Check for and execute any due scan schedules."""
    with app.app_context():
        from app.extensions import db
        from app.models import ScanSchedule, ScanJob, Asset

        now = now_utc()

        # Find all enabled schedules that are due
        due_schedules = (
            ScanSchedule.query
            .filter(
                ScanSchedule.enabled == True,
                ScanSchedule.next_run_at <= now,
            )
            .all()
        )

        if not due_schedules:
            return

        logger.info(f"Found {len(due_schedules)} due schedule(s)")

        for schedule in due_schedules:
            try:
                _execute_schedule(schedule, db)
            except Exception as e:
                logger.error(f"Failed to execute schedule {schedule.id}: {e}")
                # Don't let one failure block others - still update next_run
                try:
                    schedule.next_run_at = _compute_next_run(
                        schedule.frequency,
                        schedule.time_of_day,
                        schedule.day_of_week,
                        schedule.day_of_month,
                    )
                    db.session.commit()
                except Exception:
                    db.session.rollback()


def _execute_schedule(schedule, db):
    """Execute a single schedule - create and optionally run scan jobs."""
    from app.models import ScanJob, Asset

    schedule_type = getattr(schedule, "schedule_type", "asset") or "asset"
    job_ids = []

    if schedule_type == "group" and schedule.group_id:
        # Group schedule: create a job for each asset in the group
        assets = Asset.query.filter_by(
            group_id=schedule.group_id,
            organization_id=schedule.organization_id,
        ).all()

        if not assets:
            logger.warning(
                f"Schedule {schedule.id}: group {schedule.group_id} has no assets, skipping"
            )
        else:
            for asset in assets:
                job = ScanJob(
                    asset_id=asset.id,
                    status="queued",
                    profile_id=schedule.profile_id,
                    schedule_id=schedule.id,
                )
                db.session.add(job)
                db.session.flush()
                job_ids.append(job.id)

            logger.info(
                f"Schedule {schedule.id}: created {len(job_ids)} job(s) for group {schedule.group_id}"
            )
    else:
        # Single asset schedule
        if not schedule.asset_id:
            logger.warning(f"Schedule {schedule.id}: no asset_id, skipping")
        else:
            job = ScanJob(
                asset_id=schedule.asset_id,
                status="queued",
                profile_id=schedule.profile_id,
                schedule_id=schedule.id,
            )
            db.session.add(job)
            db.session.flush()
            job_ids.append(job.id)

            logger.info(
                f"Schedule {schedule.id}: created job {job.id} for asset {schedule.asset_id}"
            )

    # Update schedule metadata
    if job_ids:
        schedule.last_scan_job_id = job_ids[-1]

    schedule.last_run_at = now_utc()
    schedule.next_run_at = _compute_next_run(
        schedule.frequency,
        schedule.time_of_day,
        schedule.day_of_week,
        schedule.day_of_month,
    )

    db.session.commit()

    # Now run the queued jobs
    for job_id in job_ids:
        try:
            _run_job(job_id, db)
        except Exception as e:
            logger.error(f"Failed to run job {job_id}: {e}")


def _run_job(job_id, db):
    """Execute a single scan job using the profile scanner."""
    from app.models import ScanJob, ScanProfile, Asset
    from app.scanners.profile_scanner import scanner

    job = ScanJob.query.get(job_id)
    if not job or job.status != "queued":
        return

    job.status = "running"
    job.started_at = now_utc()
    db.session.commit()

    try:
        asset = Asset.query.get(job.asset_id)
        if not asset:
            raise ValueError(f"Asset {job.asset_id} not found")

        # Get profile (or use default)
        profile = None
        if job.profile_id:
            profile = ScanProfile.query.get(job.profile_id)

        if not profile:
            profile = ScanProfile.query.filter_by(is_default=True, is_system=True).first()

        if not profile:
            raise ValueError("No scan profile available")

        # Run the scan using the global scanner instance
        result = scanner.scan_with_profile(asset, profile)

        # Store results
        job.result = result
        job.status = "completed"
        job.finished_at = now_utc()

        # Extract and persist findings from scan results
        _persist_findings(job, asset, result, db)

        db.session.commit()
        logger.info(f"Job {job_id} completed for {asset.value}")

    except Exception as e:
        logger.error(f"Job {job_id} failed: {e}")
        job.status = "failed"
        job.error_message = str(e)[:500]
        job.finished_at = now_utc()
        db.session.commit()


def _persist_findings(job, asset, result, db):
    """Extract findings from scan result and save to database."""
    from app.models import Finding
    import json

    if not isinstance(result, dict):
        return

    # The ProfileBasedScanner returns: { engines: { shodan: { current: {...}, cves: [...] } } }
    engines = result.get("engines", {})

    # Process Shodan results
    shodan_data = engines.get("shodan", {})
    current = shodan_data.get("current", {})

    # Extract open ports from services
    services = current.get("services", [])
    for svc in services:
        if not isinstance(svc, dict):
            continue
        port = svc.get("port", "unknown")
        product = svc.get("product", "unknown")
        dedupe = f"open_port:{asset.id}:{port}"

        existing = Finding.query.filter_by(dedupe_key=dedupe).first()
        if existing:
            existing.last_seen = now_utc()
            existing.scan_job_id = job.id
        else:
            f = Finding(
                asset_id=asset.id,
                scan_job_id=job.id,
                organization_id=asset.organization_id,
                title=f"Open port {port} ({product})",
                severity="info",
                description=f"Port {port} running {product} v{svc.get('version', 'unknown')} is accessible",
                source="scan",
                dedupe_key=dedupe,
                metadata_json=json.dumps(svc),
                first_seen=now_utc(),
                last_seen=now_utc(),
            )
            db.session.add(f)

    # Extract CVEs
    cves = shodan_data.get("cves", [])
    for cve in cves:
        if isinstance(cve, str):
            cve_id = cve
            cvss = None
        elif isinstance(cve, dict):
            cve_id = cve.get("cve_id", cve.get("id", "unknown"))
            cvss = cve.get("cvss")
        else:
            continue

        # Determine severity from CVSS
        severity = "high"
        if cvss is not None:
            try:
                score = float(cvss)
                if score >= 9.0:
                    severity = "critical"
                elif score >= 7.0:
                    severity = "high"
                elif score >= 4.0:
                    severity = "medium"
                else:
                    severity = "low"
            except (ValueError, TypeError):
                pass

        dedupe = f"cve:{asset.id}:{cve_id}"
        existing = Finding.query.filter_by(dedupe_key=dedupe).first()
        if existing:
            existing.last_seen = now_utc()
            existing.scan_job_id = job.id
        else:
            f = Finding(
                asset_id=asset.id,
                scan_job_id=job.id,
                organization_id=asset.organization_id,
                title=f"Vulnerability: {cve_id}",
                severity=severity,
                description=cve.get("summary", f"Known vulnerability {cve_id} detected") if isinstance(cve, dict) else f"Known vulnerability {cve_id} detected",
                source="scan",
                dedupe_key=dedupe,
                metadata_json=json.dumps(cve if isinstance(cve, dict) else {"cve_id": cve}),
                first_seen=now_utc(),
                last_seen=now_utc(),
            )
            db.session.add(f)

    # Process generic findings array if present
    findings_data = result.get("findings", [])
    for finding_data in findings_data:
        if not isinstance(finding_data, dict):
            continue
        title = finding_data.get("title", "Unknown finding")
        dedupe = finding_data.get("dedupe_key", f"finding:{asset.id}:{title}")

        existing = Finding.query.filter_by(dedupe_key=dedupe).first()
        if existing:
            existing.last_seen = now_utc()
            existing.scan_job_id = job.id
        else:
            f = Finding(
                asset_id=asset.id,
                scan_job_id=job.id,
                organization_id=asset.organization_id,
                title=title,
                severity=finding_data.get("severity", "info"),
                description=finding_data.get("description", ""),
                source=finding_data.get("source", "scan"),
                dedupe_key=dedupe,
                metadata_json=json.dumps(finding_data),
                first_seen=now_utc(),
                last_seen=now_utc(),
            )
            db.session.add(f)


def init_scheduler(app):
    """Initialize and start the background scheduler."""
    global _scheduler

    # Don't start scheduler in certain contexts
    import os
    if os.environ.get("FLASK_NO_SCHEDULER"):
        logger.info("Scheduler disabled via FLASK_NO_SCHEDULER")
        return

    if _scheduler is not None:
        logger.info("Scheduler already running")
        return

    _scheduler = BackgroundScheduler(daemon=True)

    # Check for due schedules every 60 seconds
    _scheduler.add_job(
        func=lambda: _process_due_schedules(app),
        trigger=IntervalTrigger(seconds=60),
        id="scan_schedule_checker",
        name="Check for due scan schedules",
        replace_existing=True,
        max_instances=1,  # Prevent overlapping runs
    )

    _scheduler.start()
    logger.info("Background scheduler started (checking every 60s)")


def shutdown_scheduler():
    """Gracefully stop the scheduler."""
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Scheduler stopped")