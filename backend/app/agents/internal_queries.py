"""Read-only queries consumed by internal agent endpoints.

This is the only place agent code touches Nano EASM customer data
*directly* via SQLAlchemy — and only because this module IS the seam.
The /api/internal/* endpoints wrap these functions. Everything outside
this seam (agent runtime, skills, etc.) goes through the API.
"""
from __future__ import annotations
from datetime import datetime, timedelta

from sqlalchemy import desc, func

from app.extensions import db
from app.models import (
    AuditLog,
    Asset,
    ContactRequest,
    Finding,
    Organization,
    ScanJob,
    User,
    now_utc,
)


def weekly_stats(window_days: int = 7) -> dict:
    end = now_utc()
    start = end - timedelta(days=window_days)

    orgs_total = db.session.query(func.count(Organization.id)).scalar() or 0
    users_total = db.session.query(func.count(User.id)).scalar() or 0
    signups_in_window = (
        db.session.query(func.count(User.id))
        .filter(User.created_at >= start)
        .scalar() or 0
    )
    scans_in_window = (
        db.session.query(func.count(ScanJob.id))
        .filter(ScanJob.created_at >= start)
        .scalar() or 0
    )

    plan_rows = (
        db.session.query(Organization.plan, func.count(Organization.id))
        .group_by(Organization.plan)
        .all()
    )
    plan_mix = {plan or "unknown": cnt for plan, cnt in plan_rows}

    return {
        "window": {
            "from": start.isoformat() + "Z",
            "to": end.isoformat() + "Z",
            "days": window_days,
        },
        "orgs_total": orgs_total,
        "users_total": users_total,
        "signups_in_window": signups_in_window,
        "scans_in_window": scans_in_window,
        "plan_mix": plan_mix,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_since(since_iso: str | None, default_days: int = 7) -> datetime:
    """Parse an ISO-8601 string into a datetime, falling back to now()-N days."""
    if not since_iso:
        return now_utc() - timedelta(days=default_days)
    try:
        return datetime.fromisoformat(since_iso.replace("Z", ""))
    except (ValueError, TypeError):
        return now_utc() - timedelta(days=default_days)


def _finding_status(f: Finding) -> str:
    """Derive a single status string from the Finding's boolean workflow fields."""
    if f.ignored:
        return "ignored"
    if f.accepted_risk:
        return "accepted_risk"
    if f.resolved:
        return "resolved"
    if f.in_progress:
        return "in_progress"
    return "open"


# ---------------------------------------------------------------------------
# Query functions
# ---------------------------------------------------------------------------

def recent_findings(
    severity: str | None = None,
    since: str | None = None,
    limit: int = 50,
) -> dict:
    """Return the most-recent findings across all orgs, newest first.

    Model notes:
    - Finding.asset_id → Asset.id → Asset.value (the asset identifier string)
    - Asset.organization_id → Organization.name
    - Finding has no status column; derived from resolved/ignored/accepted_risk/in_progress booleans
    """
    limit = max(1, min(limit, 200))
    start = _parse_since(since, default_days=30)

    q = (
        db.session.query(Finding, Organization.name, Asset.value)
        .join(Asset, Finding.asset_id == Asset.id)
        .join(Organization, Asset.organization_id == Organization.id)
        .filter(Finding.created_at >= start)
    )
    if severity:
        q = q.filter(Finding.severity == severity)
    rows = q.order_by(desc(Finding.created_at)).limit(limit).all()

    return {
        "findings": [
            {
                "id": f.id,
                "org_name": org_name,
                "asset": asset_value,
                "severity": f.severity,
                "title": f.title,
                "status": _finding_status(f),
                "created_at": f.created_at.isoformat() + "Z",
            }
            for f, org_name, asset_value in rows
        ],
        "count": len(rows),
        "since": start.isoformat() + "Z",
    }


def recent_contact_requests(
    since: str | None = None,
    limit: int = 50,
) -> dict:
    """Return the most-recent contact requests, newest first.

    Model notes:
    - ContactRequest.request_type holds the kind (general, trial, demo)
    - ContactRequest.message is a Text column
    """
    limit = max(1, min(limit, 200))
    start = _parse_since(since, default_days=30)

    rows = (
        ContactRequest.query
        .filter(ContactRequest.created_at >= start)
        .order_by(desc(ContactRequest.created_at))
        .limit(limit)
        .all()
    )
    return {
        "contact_requests": [
            {
                "id": c.id,
                "kind": c.request_type,
                "name": c.name,
                "email": c.email,
                "message_excerpt": (c.message or "")[:300],
                "created_at": c.created_at.isoformat() + "Z",
                "status": c.status,
            }
            for c in rows
        ],
        "count": len(rows),
        "since": start.isoformat() + "Z",
    }


def recent_audit_log(
    category: str | None = None,
    since: str | None = None,
    limit: int = 50,
) -> dict:
    """Return the most-recent audit log entries, newest first.

    Model notes:
    - AuditLog.user_email is the actor field
    - target is split into target_type, target_id, target_label
    """
    limit = max(1, min(limit, 200))
    start = _parse_since(since, default_days=7)

    q = AuditLog.query.filter(AuditLog.created_at >= start)
    if category:
        q = q.filter(AuditLog.category == category)
    rows = q.order_by(desc(AuditLog.created_at)).limit(limit).all()

    return {
        "entries": [
            {
                "id": e.id,
                "actor": e.user_email,
                "action": e.action,
                "category": e.category,
                "target": e.target_label or (
                    f"{e.target_type}:{e.target_id}" if e.target_type else None
                ),
                "description": e.description,
                "created_at": e.created_at.isoformat() + "Z",
            }
            for e in rows
        ],
        "count": len(rows),
        "since": start.isoformat() + "Z",
    }


def recent_scans(
    status: str | None = None,
    since: str | None = None,
    limit: int = 50,
) -> dict:
    """Return the most-recent scan jobs across all orgs, newest first.

    Model notes:
    - ScanJob has no organization_id column; organisation is reached via Asset
    - ScanJob.asset_id → Asset.value (the asset identifier string)
    - Asset.organization_id → Organization.name
    - Select explicit columns to avoid errors from pending migrations
      (e.g. scan_job.initiator may not exist in older DB schemas).
    """
    limit = max(1, min(limit, 200))
    start = _parse_since(since, default_days=7)

    q = (
        db.session.query(
            ScanJob.id,
            ScanJob.status,
            ScanJob.created_at,
            ScanJob.started_at,
            ScanJob.finished_at,
            Organization.name.label("org_name"),
            Asset.value.label("asset_value"),
        )
        .join(Asset, ScanJob.asset_id == Asset.id)
        .join(Organization, Asset.organization_id == Organization.id)
        .filter(ScanJob.created_at >= start)
    )
    if status:
        q = q.filter(ScanJob.status == status)
    rows = q.order_by(desc(ScanJob.created_at)).limit(limit).all()

    return {
        "scans": [
            {
                "id": row.id,
                "org_name": row.org_name,
                "asset": row.asset_value,
                "status": row.status,
                "started_at": row.started_at.isoformat() + "Z" if row.started_at else None,
                "finished_at": row.finished_at.isoformat() + "Z" if row.finished_at else None,
            }
            for row in rows
        ],
        "count": len(rows),
        "since": start.isoformat() + "Z",
    }
