from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models import Monitor, MonitorAlert

logger = logging.getLogger(__name__)


def run_change_detection(monitor: "Monitor") -> list["MonitorAlert"]:
    """
    For each asset in the monitor's scope, compare the latest completed scan
    against the previously compared scan and emit MonitorAlert records for
    new findings, resolved findings, and severity changes.

    Uses monitor.last_scan_job_ids ({str(asset_id): scan_job_id}) to track the
    last scan job seen per asset, so group monitors with many assets are handled
    correctly without cross-contamination.

    Returns the list of created MonitorAlert objects (already added to session,
    not yet committed — _advance_monitor commits everything at the end).
    """
    from app.extensions import db
    from app.models import Asset, Finding, MonitorAlert, ScanJob, TuningRule
    from app.monitoring.tuning_engine import should_alert
    from app.monitoring.routes import _compute_next_check

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    org_id = monitor.organization_id

    # ── Resolve target asset IDs ────────────────────────────────────────────
    if monitor.asset_id:
        asset_ids = [monitor.asset_id]
    elif monitor.group_id:
        asset_ids = [a.id for a in Asset.query.filter_by(group_id=monitor.group_id).all()]
    else:
        _advance_monitor(monitor, now, _compute_next_check)
        return []

    if not asset_ids:
        _advance_monitor(monitor, now, _compute_next_check)
        return []

    # Load tuning rules once for the whole org
    tuning_rules = TuningRule.query.filter_by(organization_id=org_id, enabled=True).all()
    group_name = monitor.group.name if monitor.group else None

    # Mutable copy — we'll write updated job IDs back at the end
    job_ids: dict[str, int] = dict(monitor.last_scan_job_ids or {})

    all_alerts: list[MonitorAlert] = []

    for asset_id in asset_ids:
        alerts = _check_asset(
            monitor=monitor,
            asset_id=asset_id,
            job_ids=job_ids,
            tuning_rules=tuning_rules,
            group_name=group_name,
            org_id=org_id,
            db=db,
        )
        all_alerts.extend(alerts)

    # Persist the updated per-asset job tracking
    monitor.last_scan_job_ids = job_ids
    _advance_monitor(monitor, now, _compute_next_check)

    if all_alerts:
        logger.info(
            "Monitor %s: %d alert(s) — new=%d resolved=%d severity=%d",
            monitor.id,
            len(all_alerts),
            sum(1 for a in all_alerts if a.alert_type == "new_finding"),
            sum(1 for a in all_alerts if a.alert_type == "resolved"),
            sum(1 for a in all_alerts if a.alert_type == "severity_change"),
        )

    return all_alerts


def _check_asset(
    monitor,
    asset_id: int,
    job_ids: dict[str, int],
    tuning_rules: list,
    group_name: str | None,
    org_id: int,
    db,
) -> list:
    """
    Compare the latest scan vs the previously seen scan for a single asset.
    Mutates job_ids[str(asset_id)] with the new last-seen job ID.
    """
    from app.models import Asset, Finding, MonitorAlert, ScanJob

    asset = Asset.query.get(asset_id)
    if not asset:
        return []

    # Find the most recent completed scan for this asset
    latest_job = (
        ScanJob.query
        .filter_by(asset_id=asset_id, status="completed")
        .order_by(ScanJob.finished_at.desc())
        .first()
    )
    if not latest_job:
        return []

    key = str(asset_id)
    prev_job_id = job_ids.get(key)

    # First time we see this asset — establish baseline, no alerts
    if prev_job_id is None:
        job_ids[key] = latest_job.id
        logger.debug("Monitor %s: baselined asset %s at job %s", monitor.id, asset.value, latest_job.id)
        return []

    # No new scan since last check
    if prev_job_id == latest_job.id:
        return []

    # ── Load findings from each scan (exclude already-suppressed) ──────────
    def load_findings(job_id: int) -> dict[tuple, Finding]:
        rows = Finding.query.filter_by(scan_job_id=job_id, ignored=False).all()
        result = {}
        for f in rows:
            # dedupe_key is the most reliable fingerprint; fall back to template_id then title
            fk = (f.asset_id, f.dedupe_key or f.template_id or f.title)
            result[fk] = f
        return result

    current_map = load_findings(latest_job.id)
    prev_map = load_findings(prev_job_id)

    alerts: list[MonitorAlert] = []

    # New findings
    for fk, finding in current_map.items():
        if fk in prev_map:
            continue
        generate, tuning = should_alert(finding, asset, org_id, rules=tuning_rules)
        if not generate:
            continue
        alert = MonitorAlert(
            organization_id=org_id,
            monitor_id=monitor.id,
            finding_id=finding.id,
            alert_type="new_finding",
            template_id=finding.template_id,
            title=f"New finding: {finding.title}",
            summary=(finding.description or "")[:500] or None,
            severity=tuning.severity,
            asset_value=asset.value,
            group_name=group_name,
            status="open",
        )
        db.session.add(alert)
        alerts.append(alert)

    # Resolved findings
    for fk, finding in prev_map.items():
        if fk in current_map:
            continue
        alert = MonitorAlert(
            organization_id=org_id,
            monitor_id=monitor.id,
            finding_id=finding.id,
            alert_type="resolved",
            template_id=finding.template_id,
            title=f"Resolved: {finding.title}",
            summary="This finding was not detected in the latest scan.",
            severity="info",
            asset_value=asset.value,
            group_name=group_name,
            status="open",
        )
        db.session.add(alert)
        alerts.append(alert)

    # Severity changes
    for fk in set(current_map) & set(prev_map):
        curr = current_map[fk]
        prev = prev_map[fk]
        if curr.severity == prev.severity:
            continue
        generate, tuning = should_alert(curr, asset, org_id, rules=tuning_rules)
        if not generate:
            continue
        alert = MonitorAlert(
            organization_id=org_id,
            monitor_id=monitor.id,
            finding_id=curr.id,
            alert_type="severity_change",
            template_id=curr.template_id,
            title=f"Severity changed: {curr.title}",
            summary=f"Severity changed from {prev.severity} to {curr.severity}.",
            severity=tuning.severity,
            asset_value=asset.value,
            group_name=group_name,
            status="open",
        )
        db.session.add(alert)
        alerts.append(alert)

    # Advance this asset's pointer
    job_ids[key] = latest_job.id
    logger.debug(
        "Monitor %s: asset %s — %d alert(s) (prev job %s → job %s)",
        monitor.id, asset.value, len(alerts), prev_job_id, latest_job.id,
    )
    return alerts


def _advance_monitor(monitor, now: datetime, compute_next_check) -> None:
    from app.extensions import db
    monitor.last_checked_at = now
    monitor.next_check_at = compute_next_check(monitor.frequency)
    db.session.commit()
