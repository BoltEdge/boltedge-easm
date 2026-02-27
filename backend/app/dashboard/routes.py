# =============================================================================
# File: app/dashboard/routes.py
# Description: Dashboard summary route providing org-wide metrics including
#   asset counts, scan activity, finding severity breakdown, 7-day trend,
#   top risky assets, recent scan jobs, and monitoring stats.
# =============================================================================

from __future__ import annotations

from datetime import datetime, timedelta

from flask import Blueprint, jsonify
from sqlalchemy import func, distinct, desc, or_, case, select

from app.extensions import db
from app.models import AssetGroup, Asset, ScanJob, Finding
from app.auth.decorators import require_auth, current_user_id, current_organization_id

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


@dashboard_bp.get("/summary")
@require_auth
def dashboard_summary():
    org_id = current_organization_id()

    # Active group IDs for this organization
    active_group_ids = select(AssetGroup.id).where(
        AssetGroup.organization_id == org_id,
        AssetGroup.is_active.is_(True),
    )

    total_groups = (
        db.session.query(func.count(AssetGroup.id))
        .filter(AssetGroup.organization_id == org_id, AssetGroup.is_active.is_(True))
        .scalar()
        or 0
    )

    total_assets = (
        db.session.query(func.count(Asset.id))
        .filter(Asset.organization_id == org_id, Asset.group_id.in_(active_group_ids))
        .scalar()
        or 0
    )

    dist_rows = (
        db.session.query(Asset.asset_type, func.count(Asset.id))
        .filter(Asset.organization_id == org_id, Asset.group_id.in_(active_group_ids))
        .group_by(Asset.asset_type)
        .all()
    )
    asset_distribution = {"ip": 0, "domain": 0, "email": 0}
    for t, c in dist_rows:
        tt = (t or "").lower()
        if tt in asset_distribution:
            asset_distribution[tt] = int(c)

    active_scans = (
        db.session.query(func.count(ScanJob.id))
        .join(Asset, ScanJob.asset_id == Asset.id)
        .filter(Asset.organization_id == org_id, Asset.group_id.in_(active_group_ids))
        .filter(ScanJob.status.in_(["queued", "running"]))
        .scalar()
        or 0
    )

    open_findings = (
        db.session.query(func.count(Finding.id))
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Asset.organization_id == org_id, Asset.group_id.in_(active_group_ids))
        .filter(or_(Finding.ignored.is_(False), Finding.ignored.is_(None)))
        .scalar()
        or 0
    )

    sev_rows = (
        db.session.query(Finding.severity, func.count(Finding.id))
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Asset.organization_id == org_id, Asset.group_id.in_(active_group_ids))
        .filter(or_(Finding.ignored.is_(False), Finding.ignored.is_(None)))
        .group_by(Finding.severity)
        .all()
    )
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sev, cnt in sev_rows:
        s = (sev or "info").lower()
        if s not in severity_counts:
            s = "info"
        severity_counts[s] += int(cnt)
    total_findings = int(sum(severity_counts.values()))

    total_all_findings = (
        db.session.query(func.count(Finding.id))
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Asset.organization_id == org_id, Asset.group_id.in_(active_group_ids))
        .scalar()
        or 0
    )
    ignored_findings = (
        db.session.query(func.count(Finding.id))
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Asset.organization_id == org_id, Asset.group_id.in_(active_group_ids))
        .filter(Finding.ignored.is_(True))
        .scalar()
        or 0
    )
    remediation_rate = (ignored_findings / total_all_findings) if total_all_findings else 0.0

    covered_assets = (
        db.session.query(func.count(distinct(ScanJob.asset_id)))
        .join(Asset, ScanJob.asset_id == Asset.id)
        .filter(Asset.organization_id == org_id, Asset.group_id.in_(active_group_ids))
        .filter(ScanJob.status == "completed")
        .scalar()
        or 0
    )
    scan_coverage = (covered_assets / total_assets) if total_assets else 0.0

    # ── 7-day trend ──

    today = datetime.utcnow().date()
    start_day = today - timedelta(days=6)
    start_dt = datetime.combine(start_day, datetime.min.time())

    trend_rows = (
        db.session.query(
            func.date(Finding.created_at).label("day"),
            Finding.severity,
            func.count(Finding.id),
        )
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Asset.organization_id == org_id, Asset.group_id.in_(active_group_ids))
        .filter(or_(Finding.ignored.is_(False), Finding.ignored.is_(None)))
        .filter(Finding.created_at >= start_dt)
        .group_by("day", Finding.severity)
        .all()
    )

    trend_map = {}
    for day, sev, cnt in trend_rows:
        day_str = str(day)
        s = (sev or "info").lower()
        if s not in severity_counts:
            s = "info"
        trend_map.setdefault(day_str, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
        trend_map[day_str][s] = int(cnt)

    trend7d = []
    for i in range(7):
        d = (start_day + timedelta(days=i)).isoformat()
        trend7d.append(
            {"date": d, **trend_map.get(d, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})}
        )

    # ── Recent scan jobs (with asset value) ──

    recent_jobs = (
        db.session.query(ScanJob, Asset.value, Asset.asset_type, AssetGroup.name)
        .join(Asset, ScanJob.asset_id == Asset.id)
        .outerjoin(AssetGroup, Asset.group_id == AssetGroup.id)
        .filter(Asset.organization_id == org_id, Asset.group_id.in_(active_group_ids))
        .order_by(ScanJob.created_at.desc())
        .limit(5)
        .all()
    )

    def _sid(x):
        return str(x) if x is not None else ""

    recent_jobs_ui = [
        {
            "id": _sid(j.id),
            "assetId": _sid(j.asset_id),
            "assetValue": asset_value or "",
            "assetType": (asset_type or "").lower(),
            "groupName": group_name or "",
            "status": j.status,
            "timeStarted": (j.started_at or j.created_at).isoformat() if (j.started_at or j.created_at) else None,
            "timeCompleted": j.finished_at.isoformat() if j.finished_at else None,
            "errorMessage": j.error_message,
        }
        for j, asset_value, asset_type, group_name in recent_jobs
    ]

    # ── Top risky assets ──

    ranked = (
        db.session.query(
            Asset.id.label("asset_id"),
            Asset.asset_type,
            Asset.value,
            func.count(Finding.id).label("finding_count"),
            func.min(
                case(
                    (Finding.severity == "critical", 0),
                    (Finding.severity == "high", 1),
                    (Finding.severity == "medium", 2),
                    (Finding.severity == "low", 3),
                    else_=4,
                )
            ).label("severity_rank"),
        )
        .join(Finding, Finding.asset_id == Asset.id)
        .filter(Asset.organization_id == org_id, Asset.group_id.in_(active_group_ids))
        .filter(or_(Finding.ignored.is_(False), Finding.ignored.is_(None)))
        .group_by(Asset.id, Asset.asset_type, Asset.value)
        .order_by("severity_rank", desc("finding_count"))
        .limit(5)
        .all()
    )

    sev_list = ["critical", "high", "medium", "low", "info"]
    top_risky_assets = []
    for r in ranked:
        idx = int(r.severity_rank) if r.severity_rank is not None else 4
        idx = idx if 0 <= idx < len(sev_list) else 4
        top_risky_assets.append(
            {
                "assetId": _sid(r.asset_id),
                "type": (r.asset_type or "").lower(),
                "value": r.value,
                "openFindings": int(r.finding_count or 0),
                "maxSeverity": sev_list[idx],
            }
        )

# ── Exposure Score (centralized formula) ──
    from app.utils.scoring import calc_exposure_score, exposure_label_and_color

    exposure_score = calc_exposure_score(
        critical=severity_counts["critical"],
        high=severity_counts["high"],
        medium=severity_counts["medium"],
        low=severity_counts["low"],
        info=severity_counts["info"],
    )
    exposure_label, exposure_color = exposure_label_and_color(exposure_score)
    # ── Monitoring stats ──

    monitoring_data = {"openAlerts": 0, "monitored": 0, "totalAlerts": 0}
    try:
        from app.models import Monitor, MonitorAlert

        monitoring_data["monitored"] = (
            db.session.query(func.count(Monitor.id))
            .filter(Monitor.organization_id == org_id, Monitor.enabled.is_(True))
            .scalar()
            or 0
        )

        monitoring_data["openAlerts"] = (
            db.session.query(func.count(MonitorAlert.id))
            .join(Monitor, MonitorAlert.monitor_id == Monitor.id)
            .filter(Monitor.organization_id == org_id)
            .filter(MonitorAlert.status == "open")
            .scalar()
            or 0
        )

        monitoring_data["totalAlerts"] = (
            db.session.query(func.count(MonitorAlert.id))
            .join(Monitor, MonitorAlert.monitor_id == Monitor.id)
            .filter(Monitor.organization_id == org_id)
            .scalar()
            or 0
        )
    except Exception:
        # Monitor/MonitorAlert models may not exist yet
        pass

    return jsonify(
        {
            "exposureScore": {
                "score": exposure_score,
                "label": exposure_label,
                "color": exposure_color,
            },
            "assets": {"total": int(total_assets), "groups": int(total_groups), "distribution": asset_distribution},
            "scans": {"active": int(active_scans), "coverage": float(scan_coverage)},
            "findings": {
                "total": int(total_findings),
                "open": int(open_findings),
                "bySeverity": severity_counts,
                "remediationRate": float(remediation_rate),
                "trend7d": trend7d,
            },
            "monitoring": monitoring_data,
            "topRiskyAssets": top_risky_assets,
            "recentScanJobs": recent_jobs_ui,
        }
    ), 200