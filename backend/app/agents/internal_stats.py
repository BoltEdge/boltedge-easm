"""Read-only aggregate stats consumed by the Founder Ops weekly summary.

This is the only place agent code touches Nano EASM customer data
*directly* via SQLAlchemy — and only because this module IS the seam.
The /api/internal/stats/weekly endpoint wraps it. Everything outside
this seam (agent runtime, skills, etc.) goes through the API.
"""
from __future__ import annotations
from datetime import datetime, timedelta

from sqlalchemy import func

from app.extensions import db
from app.models import Organization, User, ScanJob, now_utc


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
