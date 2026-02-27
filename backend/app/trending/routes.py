# =============================================================================
# File: app/trending/routes.py
# Description: Historical trending routes for security posture tracking.
#   Provides trend data for exposure score, findings over time, MTTR,
#   and severity breakdown. Supports org-wide and group-scoped views.
#   Also handles snapshot generation (daily rollups) and finding event logging.
#
# Permissions (following existing RBAC pattern):
#   - GET /trending/data: viewer+ (view trend charts)
#   - GET /trending/summary: viewer+ (current posture summary with deltas)
#   - GET /trending/finding-events/<finding_id>: viewer+ (finding timeline)
#   - POST /trending/snapshot: admin+ (manually trigger snapshot generation)
# =============================================================================

from __future__ import annotations

from datetime import datetime, date, timedelta, timezone
from flask import Blueprint, request, jsonify
from sqlalchemy import func, and_, or_, desc
from app.extensions import db
from app.models import (
    HistorySnapshot, FindingEvent, Finding, Asset, AssetGroup,
    Organization, OrganizationMember, User,
)
from app.auth.decorators import (
    require_auth, current_user_id, current_organization_id,
)
from app.auth.permissions import require_role

import logging
logger = logging.getLogger(__name__)

trending_bp = Blueprint("trending", __name__, url_prefix="/trending")


# ────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────

def _sid(x) -> str:
    return str(x) if x is not None else ""


from app.utils.scoring import calc_exposure_score as _calc_exposure_score


def _today() -> date:
    return datetime.now(timezone.utc).date()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ────────────────────────────────────────────────────────────
# Finding Event Logging (called from other routes)
# ────────────────────────────────────────────────────────────

def log_finding_event(
    finding_id: int,
    organization_id: int,
    event_type: str,
    user_id: int | None = None,
    old_value: str | None = None,
    new_value: str | None = None,
    notes: str | None = None,
):
    """
    Log a finding lifecycle event. Call this from findings routes
    when findings are created, suppressed, resolved, or changed.
    
    Event types: opened, resolved, suppressed, unsuppressed, reopened, severity_changed
    """
    event = FindingEvent(
        finding_id=finding_id,
        organization_id=organization_id,
        event_type=event_type,
        user_id=user_id,
        old_value=old_value,
        new_value=new_value,
        notes=notes,
    )
    db.session.add(event)
    # Don't commit here — let the caller commit with their transaction


# ────────────────────────────────────────────────────────────
# Snapshot Generation
# ────────────────────────────────────────────────────────────

def generate_snapshot(org_id: int, group_id: int | None = None, snapshot_date: date | None = None) -> HistorySnapshot:
    """
    Generate a snapshot of current security posture for an org (or group).
    Calculates all metrics from live data and finding events.
    """
    if snapshot_date is None:
        snapshot_date = _today()

    # Check if snapshot already exists
    existing = HistorySnapshot.query.filter_by(
        organization_id=org_id,
        group_id=group_id,
        snapshot_date=snapshot_date,
    ).first()

    if existing:
        snapshot = existing
    else:
        snapshot = HistorySnapshot(
            organization_id=org_id,
            group_id=group_id,
            snapshot_date=snapshot_date,
        )

    # ── Base queries ──
    asset_query = Asset.query.filter(Asset.organization_id == org_id)
    finding_query = (
        db.session.query(Finding)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Asset.organization_id == org_id)
    )

    if group_id:
        asset_query = asset_query.filter(Asset.group_id == group_id)
        finding_query = finding_query.filter(Asset.group_id == group_id)

    # ── Asset count ──
    snapshot.asset_count = asset_query.count()

    # ── Active findings (not suppressed) ──
    active_findings = finding_query.filter(
        or_(Finding.ignored == False, Finding.ignored == None)
    )

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in active_findings.all():
        sev = f.severity or "info"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    snapshot.total_findings = sum(severity_counts.values())
    snapshot.critical_count = severity_counts["critical"]
    snapshot.high_count = severity_counts["high"]
    snapshot.medium_count = severity_counts["medium"]
    snapshot.low_count = severity_counts["low"]
    snapshot.info_count = severity_counts["info"]

    # ── Suppressed count ──
    snapshot.suppressed_count = finding_query.filter(Finding.ignored == True).count()

    # ── Exposure score ──
    snapshot.exposure_score = _calc_exposure_score(
        severity_counts["critical"],
        severity_counts["high"],
        severity_counts["medium"],
        severity_counts["low"],
    )

    # ── Activity since last snapshot ──
    prev_snapshot = (
        HistorySnapshot.query
        .filter(
            HistorySnapshot.organization_id == org_id,
            HistorySnapshot.group_id == group_id if group_id else HistorySnapshot.group_id.is_(None),
            HistorySnapshot.snapshot_date < snapshot_date,
        )
        .order_by(desc(HistorySnapshot.snapshot_date))
        .first()
    )

    if prev_snapshot:
        since = datetime.combine(prev_snapshot.snapshot_date, datetime.min.time())
    else:
        since = datetime.min

    # Count events since last snapshot
    event_query = FindingEvent.query.filter(
        FindingEvent.organization_id == org_id,
        FindingEvent.created_at >= since,
    )

    if group_id:
        # Filter events by findings that belong to this group
        event_query = (
            event_query
            .join(Finding, FindingEvent.finding_id == Finding.id)
            .join(Asset, Finding.asset_id == Asset.id)
            .filter(Asset.group_id == group_id)
        )

    snapshot.new_findings = event_query.filter(FindingEvent.event_type == "opened").count()
    snapshot.resolved_findings = event_query.filter(FindingEvent.event_type == "resolved").count()
    snapshot.suppressed_findings = event_query.filter(FindingEvent.event_type == "suppressed").count()

    # ── MTTR (Mean Time To Remediate) ──
    # Calculate from resolved findings that have both opened and resolved events
    resolved_events = (
        FindingEvent.query
        .filter(
            FindingEvent.organization_id == org_id,
            FindingEvent.event_type == "resolved",
            FindingEvent.created_at >= since,
        )
    )

    if group_id:
        resolved_events = (
            resolved_events
            .join(Finding, FindingEvent.finding_id == Finding.id)
            .join(Asset, Finding.asset_id == Asset.id)
            .filter(Asset.group_id == group_id)
        )

    mttr_values = []
    for re in resolved_events.all():
        # Find the most recent "opened" event for this finding before the resolve
        opened_event = (
            FindingEvent.query
            .filter(
                FindingEvent.finding_id == re.finding_id,
                FindingEvent.event_type == "opened",
                FindingEvent.created_at < re.created_at,
            )
            .order_by(desc(FindingEvent.created_at))
            .first()
        )
        if opened_event:
            delta = (re.created_at - opened_event.created_at).total_seconds() / 3600.0
            mttr_values.append(delta)

    snapshot.mttr_hours = round(sum(mttr_values) / len(mttr_values), 1) if mttr_values else None

    if not existing:
        db.session.add(snapshot)

    db.session.commit()

    # --- Dispatch exposure threshold notification if score is high ---
    try:
        if snapshot.exposure_score and snapshot.exposure_score >= 70:
            from app.integrations.routes import dispatch_event
            group_name = "Organization-wide"
            if group_id:
                g = AssetGroup.query.get(group_id)
                group_name = g.name if g else f"Group {group_id}"

            dispatch_event(org_id, "exposure.threshold", {
                "title": f"Exposure score is {snapshot.exposure_score}/100",
                "severity": "critical" if snapshot.exposure_score >= 85 else "high",
                "exposure_score": snapshot.exposure_score,
                "group": group_name,
                "group_id": str(group_id) if group_id else "",
                "description": f"Exposure score has reached {snapshot.exposure_score}/100 for {group_name}, exceeding the risk threshold.",
            })
    except Exception as e:
        logger.warning(f"Failed to dispatch exposure threshold notification: {e}")

    return snapshot


def generate_all_snapshots(org_id: int, snapshot_date: date | None = None):
    """
    Generate snapshots for an organization: one org-wide + one per group.
    """
    if snapshot_date is None:
        snapshot_date = _today()

    # Org-wide snapshot
    generate_snapshot(org_id, group_id=None, snapshot_date=snapshot_date)

    # Per-group snapshots
    groups = AssetGroup.query.filter_by(organization_id=org_id, is_active=True).all()
    for g in groups:
        generate_snapshot(org_id, group_id=g.id, snapshot_date=snapshot_date)


# ────────────────────────────────────────────────────────────
# Serializers
# ────────────────────────────────────────────────────────────

def _snapshot_to_dict(s: HistorySnapshot) -> dict:
    return {
        "id": _sid(s.id),
        "date": s.snapshot_date.isoformat() if s.snapshot_date else None,
        "assetCount": s.asset_count,
        "totalFindings": s.total_findings,
        "critical": s.critical_count,
        "high": s.high_count,
        "medium": s.medium_count,
        "low": s.low_count,
        "info": s.info_count,
        "suppressedCount": s.suppressed_count,
        "exposureScore": s.exposure_score,
        "newFindings": s.new_findings,
        "resolvedFindings": s.resolved_findings,
        "suppressedFindings": s.suppressed_findings,
        "mttrHours": s.mttr_hours,
    }


def _event_to_dict(e: FindingEvent) -> dict:
    return {
        "id": _sid(e.id),
        "findingId": _sid(e.finding_id),
        "eventType": e.event_type,
        "oldValue": e.old_value,
        "newValue": e.new_value,
        "userId": _sid(e.user_id) if e.user_id else None,
        "userName": e.user.name or e.user.email if e.user else None,
        "notes": e.notes,
        "createdAt": e.created_at.isoformat() if e.created_at else None,
    }


# ────────────────────────────────────────────────────────────
# Routes
# ────────────────────────────────────────────────────────────

# GET /trending/data — viewer+ (trend chart data)
@trending_bp.get("/data")
@require_auth
def get_trend_data():
    """
    Returns time-series data for trend charts.
    Supports org-wide or group-scoped via ?group_id=X
    Supports date range via ?days=30 (default 30, max 365)
    """
    org_id = current_organization_id()

    group_id = request.args.get("group_id")
    days = min(request.args.get("days", 30, type=int), 365)
    start_date = _today() - timedelta(days=days)

    query = HistorySnapshot.query.filter(
        HistorySnapshot.organization_id == org_id,
        HistorySnapshot.snapshot_date >= start_date,
    )

    if group_id and group_id != "all":
        query = query.filter(HistorySnapshot.group_id == int(group_id))
    else:
        query = query.filter(HistorySnapshot.group_id.is_(None))

    snapshots = query.order_by(HistorySnapshot.snapshot_date.asc()).all()

    return jsonify(
        snapshots=[_snapshot_to_dict(s) for s in snapshots],
        days=days,
        startDate=start_date.isoformat(),
        endDate=_today().isoformat(),
        groupId=group_id if group_id and group_id != "all" else None,
        scope="group" if group_id and group_id != "all" else "organization",
    ), 200


# GET /trending/summary — viewer+ (current posture with deltas)
@trending_bp.get("/summary")
@require_auth
def get_trend_summary():
    """
    Returns current posture snapshot with comparison to previous period.
    Used for the summary cards at the top of the trending page.
    """
    org_id = current_organization_id()
    group_id = request.args.get("group_id")

    gid = int(group_id) if group_id and group_id != "all" else None

    # Get latest snapshot
    latest_query = HistorySnapshot.query.filter(
        HistorySnapshot.organization_id == org_id,
    )
    if gid:
        latest_query = latest_query.filter(HistorySnapshot.group_id == gid)
    else:
        latest_query = latest_query.filter(HistorySnapshot.group_id.is_(None))

    latest = latest_query.order_by(desc(HistorySnapshot.snapshot_date)).first()

    if not latest:
        return jsonify(
            current=None,
            previous=None,
            deltas=None,
            message="No snapshot data available. Generate a snapshot first.",
        ), 200

    # Get previous period snapshot (same number of days back)
    days_back = 7
    prev_date = latest.snapshot_date - timedelta(days=days_back)

    prev_query = HistorySnapshot.query.filter(
        HistorySnapshot.organization_id == org_id,
        HistorySnapshot.snapshot_date <= prev_date,
    )
    if gid:
        prev_query = prev_query.filter(HistorySnapshot.group_id == gid)
    else:
        prev_query = prev_query.filter(HistorySnapshot.group_id.is_(None))

    previous = prev_query.order_by(desc(HistorySnapshot.snapshot_date)).first()

    # Calculate deltas
    deltas = None
    if previous:
        def _delta(current_val, prev_val):
            diff = current_val - prev_val
            if prev_val == 0:
                pct = 100.0 if diff > 0 else 0.0
            else:
                pct = round((diff / prev_val) * 100, 1)
            return {"value": diff, "percent": pct, "direction": "up" if diff > 0 else "down" if diff < 0 else "flat"}

        deltas = {
            "exposureScore": _delta(latest.exposure_score, previous.exposure_score),
            "totalFindings": _delta(latest.total_findings, previous.total_findings),
            "critical": _delta(latest.critical_count, previous.critical_count),
            "high": _delta(latest.high_count, previous.high_count),
            "assetCount": _delta(latest.asset_count, previous.asset_count),
        }

    return jsonify(
        current=_snapshot_to_dict(latest),
        previous=_snapshot_to_dict(previous) if previous else None,
        deltas=deltas,
        comparedToDaysAgo=days_back,
    ), 200


# GET /trending/finding-events/<finding_id> — viewer+ (finding timeline)
@trending_bp.get("/finding-events/<int:finding_id>")
@require_auth
def get_finding_events(finding_id: int):
    """Returns the timeline of events for a specific finding."""
    org_id = current_organization_id()

    events = (
        FindingEvent.query
        .filter(
            FindingEvent.finding_id == finding_id,
            FindingEvent.organization_id == org_id,
        )
        .order_by(FindingEvent.created_at.desc())
        .all()
    )

    return jsonify(events=[_event_to_dict(e) for e in events]), 200


# POST /trending/snapshot — admin+ (manually generate snapshots)
@trending_bp.post("/snapshot")
@require_auth
@require_role("admin")
def trigger_snapshot():
    """
    Manually trigger snapshot generation for the organization.
    Generates org-wide + per-group snapshots.
    Optionally backfill multiple days via ?backfill=7
    """
    org_id = current_organization_id()
    body = request.get_json(silent=True) or {}

    backfill = body.get("backfill", 0)
    if backfill and isinstance(backfill, int) and backfill > 0:
        backfill = min(backfill, 90)  # Max 90 days backfill
        for i in range(backfill, -1, -1):
            d = _today() - timedelta(days=i)
            generate_all_snapshots(org_id, snapshot_date=d)
        return jsonify(
            message=f"Generated snapshots for {backfill + 1} days",
            days=backfill + 1,
        ), 201
    else:
        generate_all_snapshots(org_id)
        return jsonify(
            message="Snapshot generated for today",
            date=_today().isoformat(),
        ), 201


# GET /trending/groups — viewer+ (list groups with latest snapshot data)
@trending_bp.get("/groups")
@require_auth
def get_group_trends():
    """
    Returns latest snapshot for each group — used for the group comparison view.
    """
    org_id = current_organization_id()

    groups = AssetGroup.query.filter_by(organization_id=org_id, is_active=True).all()

    result = []
    for g in groups:
        latest = (
            HistorySnapshot.query
            .filter_by(organization_id=org_id, group_id=g.id)
            .order_by(desc(HistorySnapshot.snapshot_date))
            .first()
        )
        result.append({
            "groupId": _sid(g.id),
            "groupName": g.name,
            "snapshot": _snapshot_to_dict(latest) if latest else None,
        })

    # Sort by exposure score descending (most exposed first)
    result.sort(key=lambda x: x["snapshot"]["exposureScore"] if x.get("snapshot") else 0, reverse=True)

    return jsonify(groups=result), 200