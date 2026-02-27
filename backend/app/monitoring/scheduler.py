# app/monitoring/scheduler.py
"""
Monitor scheduler — periodically checks for monitors that are due and
triggers change detection + notification dispatch.

Designed to run as a lightweight background thread alongside the Flask app.
For production, this can be swapped out for Celery beat or APScheduler.

Usage in app factory:
    from app.monitoring.scheduler import start_monitor_scheduler
    start_monitor_scheduler(app)

The scheduler:
    1. Wakes up every CHECK_INTERVAL_SECONDS (default 60s)
    2. Queries for monitors where next_check_at <= now AND enabled
    3. For each due monitor, kicks off a scan + change detection
    4. Dispatches notifications for generated alerts
    5. Sleeps until next cycle
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# How often the scheduler checks for due monitors (in seconds)
CHECK_INTERVAL_SECONDS = 60

# Global flag to stop the scheduler thread cleanly
_stop_event = threading.Event()
_scheduler_thread: threading.Thread | None = None


# ---------------------------------------------------------------------------
# Notification dispatch
# ---------------------------------------------------------------------------

def _dispatch_notifications(alerts: list, org_id: int) -> None:
    """
    Send notifications for generated alerts based on org settings.

    Handles: email, in-app, webhook.
    Each alert is tagged with notified_via after dispatch.
    """
    if not alerts:
        return

    from app.models import MonitorSettings
    from app.extensions import db

    settings = MonitorSettings.query.filter_by(organization_id=org_id).first()
    if not settings:
        return  # No settings → no notifications

    # Filter by severity preference
    severity_filter = set(settings.notify_on_severity or [])

    for alert in alerts:
        if alert.severity not in severity_filter:
            continue

        channels_used = []

        # --- Email ---
        if settings.email_enabled and settings.email_recipients:
            try:
                _send_email_notification(alert, settings.email_recipients)
                channels_used.append("email")
            except Exception:
                logger.exception("Email notification failed for alert %s", alert.id)

        # --- In-app ---
        if settings.in_app_enabled:
            try:
                _create_in_app_notification(alert, org_id)
                channels_used.append("in_app")
            except Exception:
                logger.exception("In-app notification failed for alert %s", alert.id)

        # --- Webhook ---
        if settings.webhook_enabled and settings.webhook_url:
            try:
                _send_webhook_notification(alert, settings.webhook_url)
                channels_used.append("webhook")
            except Exception:
                logger.exception("Webhook notification failed for alert %s", alert.id)

        # --- Integration dispatch (Slack, Jira, PagerDuty, Webhook, Email) ---
        try:
            from app.monitoring.routes import dispatch_monitor_alert
            dispatch_monitor_alert(alert, org_id)
            channels_used.append("integrations")
        except Exception:
            logger.exception("Integration dispatch failed for alert %s", alert.id)

        # Track which channels were used
        alert.notified_via = channels_used

    db.session.commit()


def _send_email_notification(alert, recipients: list[str]) -> None:
    """
    Send an email notification for an alert.

    TODO: Integrate with actual email provider (SendGrid, SES, SMTP).
    For now, logs the notification.
    """
    logger.info(
        "EMAIL → %s | [%s] %s — %s on %s",
        ", ".join(recipients),
        alert.severity.upper(),
        alert.alert_type,
        alert.title,
        alert.asset_value,
    )
    # IMPLEMENTATION:
    # from app.email import send_alert_email
    # send_alert_email(
    #     recipients=recipients,
    #     subject=f"[{alert.severity.upper()}] {alert.title}",
    #     alert=alert,
    # )


def _create_in_app_notification(alert, org_id: int) -> None:
    """
    Create an in-app notification record.

    TODO: Create a Notification model or push to a WebSocket channel.
    For now, logs the notification.
    """
    logger.info(
        "IN-APP → org=%s | [%s] %s — %s",
        org_id,
        alert.severity.upper(),
        alert.alert_type,
        alert.title,
    )
    # IMPLEMENTATION:
    # from app.models import Notification
    # notif = Notification(
    #     organization_id=org_id,
    #     type="monitor_alert",
    #     title=alert.title,
    #     message=alert.summary,
    #     severity=alert.severity,
    #     link=f"/monitoring?tab=alerts&id={alert.id}",
    # )
    # db.session.add(notif)


def _send_webhook_notification(alert, webhook_url: str) -> None:
    """
    POST alert data to a webhook URL (Slack, Discord, PagerDuty, etc.).

    TODO: Make actual HTTP request with retries.
    For now, logs the notification.
    """
    import json

    payload = {
        "event": "monitor_alert",
        "alert": {
            "id": str(alert.id),
            "type": alert.alert_type,
            "title": alert.title,
            "summary": alert.summary,
            "severity": alert.severity,
            "status": alert.status,
            "asset": alert.asset_value,
            "group": alert.group_name,
            "template_id": alert.template_id,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        },
    }

    logger.info(
        "WEBHOOK → %s | %s",
        webhook_url,
        json.dumps(payload, indent=None),
    )
    # IMPLEMENTATION:
    # import requests
    # resp = requests.post(
    #     webhook_url,
    #     json=payload,
    #     headers={"Content-Type": "application/json"},
    #     timeout=10,
    # )
    # resp.raise_for_status()


# ---------------------------------------------------------------------------
# Scan trigger for monitors
# ---------------------------------------------------------------------------

def _trigger_monitor_scan(monitor) -> None:
    """
    Trigger a new scan for a monitored asset, then run change detection.

    For asset monitors: creates + runs a scan job for the asset.
    For group monitors: creates + runs scan jobs for each asset in the group.
    """
    from app.models import Asset, ScanJob, ScanProfile
    from app.extensions import db

    org_id = monitor.organization_id

    # Get default scan profile
    profile = ScanProfile.query.filter_by(
        is_system=True, is_default=True, is_active=True
    ).first()

    if monitor.asset_id:
        assets = [Asset.query.get(monitor.asset_id)]
    elif monitor.group_id:
        assets = Asset.query.filter_by(group_id=monitor.group_id).all()
    else:
        return

    assets = [a for a in assets if a is not None]

    for asset in assets:
        # Check if there's already a running/queued scan for this asset
        active = ScanJob.query.filter(
            ScanJob.asset_id == asset.id,
            ScanJob.status.in_(["queued", "running"]),
        ).first()

        if active:
            logger.debug("Skipping scan for %s — already has active job %s", asset.value, active.id)
            continue

        # Create scan job
        job = ScanJob(
            asset_id=asset.id,
            status="queued",
            profile_id=profile.id if profile else None,
        )
        db.session.add(job)
        db.session.flush()

        logger.info("Created monitor scan job %s for asset %s", job.id, asset.value)

        # Run the scan synchronously within the scheduler thread
        # (The scheduler already runs in a background thread, so this is fine)
        try:
            _execute_scan_job(job, asset, profile)
        except Exception:
            logger.exception("Monitor scan failed for asset %s", asset.value)
            job.status = "failed"
            job.error_message = "Monitor scan execution failed"
            db.session.commit()


def _execute_scan_job(job, asset, profile) -> None:
    """
    Execute a scan job synchronously.
    Reuses the orchestrator from the scanning system.
    """
    from app.extensions import db
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    job.status = "running"
    job.started_at = now
    asset.scan_status = "scan_pending"
    db.session.commit()

    try:
        # Try to use the ScanOrchestrator
        from app.scanner.orchestrator import ScanOrchestrator
        orchestrator = ScanOrchestrator(
            job=job,
            asset=asset,
            profile=profile,
        )
        result = orchestrator.run()

        job.result_json = result if isinstance(result, dict) else {"status": "completed"}
        job.status = "completed"
        job.finished_at = datetime.now(timezone.utc).replace(tzinfo=None)
        asset.last_scan_at = job.finished_at
        asset.scan_status = "scanned"

    except ImportError:
        logger.warning("ScanOrchestrator not available — marking job as completed for change detection")
        job.status = "completed"
        job.finished_at = datetime.now(timezone.utc).replace(tzinfo=None)
        asset.scan_status = "scanned"

    except Exception as e:
        logger.exception("Scan execution failed for job %s", job.id)
        job.status = "failed"
        job.error_message = str(e)[:500]
        job.finished_at = datetime.now(timezone.utc).replace(tzinfo=None)
        asset.scan_status = "scan_failed"

    db.session.commit()


# ---------------------------------------------------------------------------
# Scheduler loop
# ---------------------------------------------------------------------------

def _scheduler_loop(app) -> None:
    """
    Main scheduler loop. Runs inside a background thread with Flask app context.
    """
    logger.info("Monitor scheduler started (interval: %ds)", CHECK_INTERVAL_SECONDS)

    while not _stop_event.is_set():
        try:
            with app.app_context():
                _run_cycle()
        except Exception:
            logger.exception("Scheduler cycle error")

        # Sleep in small increments so we can respond to stop quickly
        for _ in range(CHECK_INTERVAL_SECONDS):
            if _stop_event.is_set():
                break
            time.sleep(1)

    logger.info("Monitor scheduler stopped")


def _run_cycle() -> None:
    """Execute one scheduler cycle: find due monitors, scan, detect changes, notify."""
    from app.models import Monitor
    from app.extensions import db

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    due_monitors = Monitor.query.filter(
        Monitor.enabled == True,
        Monitor.next_check_at <= now,
    ).all()

    if not due_monitors:
        return

    logger.info("Scheduler cycle: %d monitors due", len(due_monitors))

    for monitor in due_monitors:
        try:
            logger.info(
                "Processing monitor %s (target: %s)",
                monitor.id,
                monitor.asset.value if monitor.asset else
                (monitor.group.name if monitor.group else "unknown"),
            )

            # Step 1: Trigger scans for the monitored assets
            _trigger_monitor_scan(monitor)

            # Step 2: Run change detection
            from app.monitoring.change_detector import run_change_detection
            alerts = run_change_detection(monitor)

            # Step 3: Dispatch notifications
            if alerts:
                _dispatch_notifications(alerts, monitor.organization_id)
                logger.info(
                    "Monitor %s generated %d alerts",
                    monitor.id, len(alerts),
                )

        except Exception:
            logger.exception("Failed to process monitor %s", monitor.id)

            # Still update next_check_at so we don't retry forever
            from app.monitoring.routes import _compute_next_check
            monitor.next_check_at = _compute_next_check(monitor.frequency)
            monitor.updated_at = now
            db.session.commit()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start_monitor_scheduler(app) -> None:
    """
    Start the monitor scheduler as a background daemon thread.

    Call this from your app factory:
        from app.monitoring.scheduler import start_monitor_scheduler
        start_monitor_scheduler(app)
    """
    global _scheduler_thread

    if _scheduler_thread and _scheduler_thread.is_alive():
        logger.warning("Monitor scheduler already running")
        return

    _stop_event.clear()
    _scheduler_thread = threading.Thread(
        target=_scheduler_loop,
        args=(app,),
        daemon=True,
        name="monitor-scheduler",
    )
    _scheduler_thread.start()
    logger.info("Monitor scheduler thread started")


def stop_monitor_scheduler() -> None:
    """Stop the scheduler thread gracefully."""
    global _scheduler_thread
    _stop_event.set()
    if _scheduler_thread:
        _scheduler_thread.join(timeout=10)
        _scheduler_thread = None
    logger.info("Monitor scheduler thread stopped")


def is_scheduler_running() -> bool:
    """Check if the scheduler thread is alive."""
    return _scheduler_thread is not None and _scheduler_thread.is_alive()


def run_monitor_now(monitor_id: int) -> list:
    """
    Manually trigger a monitor check (e.g. from admin UI or CLI).
    Must be called within Flask app context.
    """
    from app.models import Monitor

    monitor = Monitor.query.get(monitor_id)
    if not monitor:
        raise ValueError(f"Monitor {monitor_id} not found")

    # Trigger scan
    _trigger_monitor_scan(monitor)

    # Run change detection
    from app.monitoring.change_detector import run_change_detection
    alerts = run_change_detection(monitor)

    # Dispatch notifications
    if alerts:
        _dispatch_notifications(alerts, monitor.organization_id)

    return alerts