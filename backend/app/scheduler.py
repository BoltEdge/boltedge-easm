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
from apscheduler.triggers.cron import CronTrigger
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

        cycle_success = True
        executed = 0
        failed = 0
        try:
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

            if due_schedules:
                logger.info(f"Found {len(due_schedules)} due schedule(s)")

            for schedule in due_schedules:
                try:
                    _execute_schedule(schedule, db)
                    executed += 1
                except Exception as e:
                    failed += 1
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
        except Exception as e:
            cycle_success = False
            logger.exception("scan_schedule cycle crashed: %s", e)
            raise
        finally:
            try:
                from app.health.heartbeat import heartbeat
                heartbeat(
                    "scan_schedule",
                    success=cycle_success and failed == 0,
                    message=(
                        f"Executed {executed}, failed {failed}"
                        if (executed or failed) else "Idle cycle"
                    ),
                    metadata={"executed": executed, "failed": failed},
                )
            except Exception:
                logger.exception("scan_schedule heartbeat failed")


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
                    initiator="scheduled",
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
                initiator="scheduled",
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
    """
    Execute a single scheduled scan job via the shared executor.

    The executor handles the full lifecycle: queued -> running transition,
    scan.started audit, orchestrator (or _run_legacy on ImportError),
    cancellation race, result/status persistence, scan.completed /
    scan.failed audit. ``db`` is unused but kept in the signature for
    backwards compatibility with the existing _execute_schedule call.
    """
    from flask import current_app
    from app.scan_jobs.executor import execute_scan_job

    execute_scan_job(job_id, current_app._get_current_object())


def _run_monday_weekly_summary():
    """Phase-1 scheduled job: Founder Ops weekly summary, Monday 08:00."""
    from app.agents.skills.weekly_summary import run_weekly_summary
    try:
        run_weekly_summary(send=True)
    except Exception as e:
        # Never propagate — APScheduler should keep running. The failure
        # is captured in agent_run.status='failed' by run_agent itself.
        import logging
        logging.getLogger("agents").exception("weekly_summary failed: %s", e)


def _run_tuesday_competitor_pulse():
    """Phase 2A.1 scheduled job: Ava competitor pulse, Tuesday 08:00."""
    from app.agents.skills.competitor_pulse import run_competitor_pulse
    try:
        run_competitor_pulse(send=True)
    except Exception as e:
        import logging
        logging.getLogger("agents").exception("competitor_pulse failed: %s", e)


def _run_wednesday_finding_brief():
    """Phase 2A.1 scheduled job: Maya weekly-finding-brief, Wednesday 08:00."""
    from app.agents.skills.weekly_finding_brief import run_weekly_finding_brief
    try:
        run_weekly_finding_brief(send=True)
    except Exception as e:
        import logging
        logging.getLogger("agents").exception("weekly_finding_brief failed: %s", e)


def _run_refresh_kev_feed(app):
    """Daily APScheduler job: refresh CISA KEV cache. Never raises."""
    with app.app_context():
        from app.scanner.threat_intel import refresh_kev_feed
        try:
            count = refresh_kev_feed()
            logger.info("refresh_kev_feed: upserted %d entries", count)
        except Exception:
            logger.exception("refresh_kev_feed crashed")


def _run_pastebin_fetcher(app):
    """60s APScheduler job: pull the latest 250 public Pastebin pastes
    and upsert them into paste_cache. Skips silently when
    PASTEBIN_FETCHER_ENABLED is unset. Never raises."""
    with app.app_context():
        from app.services.pastebin_client import fetch_recent_pastes_and_upsert
        try:
            n = fetch_recent_pastes_and_upsert()
            if n:
                logger.info("pastebin_fetcher: ingested %d new pastes", n)
        except Exception:
            logger.exception("pastebin_fetcher crashed")


def _run_pastebin_cleanup(app):
    """Hourly APScheduler job: delete paste_cache rows whose expires_at
    is in the past. Bounds the table at ~360k rows over the 7-day TTL."""
    from datetime import datetime, timezone
    with app.app_context():
        from app.extensions import db
        from app.models import PasteCache
        try:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            deleted = (
                PasteCache.query
                .filter(PasteCache.expires_at < now)
                .delete(synchronize_session=False)
            )
            db.session.commit()
            if deleted:
                logger.info("pastebin_cleanup: removed %d expired pastes", deleted)
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
            logger.exception("pastebin_cleanup crashed")


def _run_ct_log_monitor(app):
    """15-minute job: poll crt.sh for every unique brand keyword across
    watched assets; insert new candidates into ct_log_candidate. Only
    runs when MIMIC_ENABLED is set so deployments without the S3 bucket
    configured don't burn cycles."""
    import os
    if os.environ.get("MIMIC_ENABLED", "").strip().lower() != "true":
        return
    with app.app_context():
        from app.services.ct_log_monitor import (
            collect_brand_keywords, poll_brand_keywords,
        )
        try:
            keywords = collect_brand_keywords()
            if not keywords:
                return
            n = poll_brand_keywords(keywords)
            if n:
                logger.info("ct_log_monitor: ingested %d candidates across %d keywords",
                            n, len(keywords))
        except Exception:
            logger.exception("ct_log_monitor crashed")


def _run_ct_log_cleanup(app):
    """Hourly cleanup: delete ct_log_candidate rows past their TTL."""
    with app.app_context():
        from app.services.ct_log_monitor import cleanup_expired_candidates
        try:
            deleted = cleanup_expired_candidates()
            if deleted:
                logger.info("ct_log_cleanup: removed %d expired candidates", deleted)
        except Exception:
            logger.exception("ct_log_cleanup crashed")


def _run_lookalike_schedule(app):
    """
    Daily APScheduler job: enqueue lookalike scans for watched assets
    that haven't been scanned in the last 6 days. Net effective cadence
    is weekly per asset (because the LookalikeEngine self-rate-limits to
    6 days). Daily check means a missed day is automatically caught up
    next tick.
    """
    from datetime import timedelta
    with app.app_context():
        from app.extensions import db
        from app.models import Asset, ScanProfile, ScanJob

        try:
            profile = (
                ScanProfile.query
                .filter_by(name="Lookalike Scan", is_system=True, is_active=True)
                .first()
            )
            if not profile:
                logger.warning(
                    "lookalike_schedule: 'Lookalike Scan' profile missing; skipping cycle"
                )
                return

            cutoff = now_utc().replace(tzinfo=None) - timedelta(days=6)
            watched = (
                Asset.query
                .filter(Asset.lookalike_watch.is_(True))
                .filter(Asset.asset_type == "domain")
                .filter(
                    db.or_(
                        Asset.last_lookalike_scan_at.is_(None),
                        Asset.last_lookalike_scan_at < cutoff,
                    )
                )
                .all()
            )

            if not watched:
                logger.info("lookalike_schedule: no stale watched assets this cycle")
                return

            # When Site Mimic Watch is enabled on the deployment, capture
            # / refresh each watched asset's baseline BEFORE we enqueue
            # the scan job. The scan runs the mimic engine as a second
            # pass after lookalike; it short-circuits silently if no
            # baseline exists, which is why we capture first.
            import os as _os
            mimic_enabled = _os.environ.get("MIMIC_ENABLED", "").strip().lower() == "true"
            baseline_captured = 0
            if mimic_enabled:
                from app.services.mimic_baseline import capture_baseline
                for asset in watched:
                    try:
                        res = capture_baseline(asset, force=False)
                        if res.status == "captured" and res.captured_at is not None:
                            baseline_captured += 1
                    except Exception:
                        logger.exception(
                            "lookalike_schedule: baseline capture failed for asset_id=%s",
                            asset.id,
                        )

            for asset in watched:
                job = ScanJob(
                    asset_id=asset.id,
                    status="queued",
                    profile_id=profile.id,
                    initiator="lookalike_schedule",
                )
                db.session.add(job)
            db.session.commit()
            logger.info(
                "lookalike_schedule: enqueued %d lookalike scans"
                " (mimic baselines captured/refreshed: %d)",
                len(watched), baseline_captured,
            )
        except Exception:
            logger.exception("lookalike_schedule crashed")
            try:
                db.session.rollback()
            except Exception:
                pass


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

    # Founder Ops weekly summary — every Monday at 08:00 UTC
    _scheduler.add_job(
        func=_run_monday_weekly_summary,
        trigger=CronTrigger(day_of_week="mon", hour=8, minute=0),
        id="agents.founder_ops.weekly_summary",
        name="Founder Ops weekly summary (Monday 08:00 UTC)",
        replace_existing=True,
        max_instances=1,
    )

    # Ava (strategy) competitor pulse — every Tuesday at 08:00 UTC
    _scheduler.add_job(
        func=_run_tuesday_competitor_pulse,
        trigger=CronTrigger(day_of_week="tue", hour=8, minute=0),
        id="agents.strategy.competitor_pulse",
        name="Strategy competitor pulse (Tuesday 08:00 UTC)",
        replace_existing=True,
        max_instances=1,
    )

    # Maya (security-analyst) weekly finding brief — every Wednesday at 08:00 UTC
    _scheduler.add_job(
        func=_run_wednesday_finding_brief,
        trigger=CronTrigger(day_of_week="wed", hour=8, minute=0),
        id="agents.security_analyst.weekly_finding_brief",
        name="Security analyst weekly finding brief (Wednesday 08:00 UTC)",
        replace_existing=True,
        max_instances=1,
    )

    # Threat-intel: refresh CISA KEV feed — every day at 02:00 UTC.
    # EPSS is per-CVE on-demand with a 7-day cache TTL, so no scheduled
    # job is needed for that side.
    _scheduler.add_job(
        func=lambda: _run_refresh_kev_feed(app),
        trigger=CronTrigger(hour=2, minute=0),
        id="threat_intel.refresh_kev_feed",
        name="Refresh CISA KEV cache (daily 02:00 UTC)",
        replace_existing=True,
        max_instances=1,
    )

    # Lookalike scans — daily check at 03:00 UTC for watched assets that
    # haven't been scanned in the last 6 days. Effective cadence is weekly
    # per asset; daily polling means a missed day catches up next tick.
    _scheduler.add_job(
        func=lambda: _run_lookalike_schedule(app),
        trigger=CronTrigger(hour=3, minute=0),
        id="lookalike.schedule",
        name="Enqueue weekly lookalike scans for watched assets (daily 03:00 UTC)",
        replace_existing=True,
        max_instances=1,
    )

    # Pastebin background fetcher — every 60 seconds. Skips itself when
    # PASTEBIN_FETCHER_ENABLED is not set, so deployments without a PRO
    # account don't burn cycles. Cleanup runs hourly to bound the table.
    _scheduler.add_job(
        func=lambda: _run_pastebin_fetcher(app),
        trigger=IntervalTrigger(seconds=60),
        id="pastebin.fetcher",
        name="Pastebin scraping API fetcher (every 60s)",
        replace_existing=True,
        max_instances=1,
    )
    _scheduler.add_job(
        func=lambda: _run_pastebin_cleanup(app),
        trigger=IntervalTrigger(hours=1),
        id="pastebin.cleanup",
        name="Delete expired paste_cache rows (hourly)",
        replace_existing=True,
        max_instances=1,
    )

    # Site Mimic Watch — CT log polling. Job itself no-ops when
    # MIMIC_ENABLED isn't set; safe to register unconditionally.
    _scheduler.add_job(
        func=lambda: _run_ct_log_monitor(app),
        trigger=IntervalTrigger(minutes=15),
        id="mimic.ct_log_monitor",
        name="Site Mimic Watch — CT log polling (every 15 min)",
        replace_existing=True,
        max_instances=1,
    )
    _scheduler.add_job(
        func=lambda: _run_ct_log_cleanup(app),
        trigger=IntervalTrigger(hours=1),
        id="mimic.ct_log_cleanup",
        name="Site Mimic Watch — delete expired CT log candidates (hourly)",
        replace_existing=True,
        max_instances=1,
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