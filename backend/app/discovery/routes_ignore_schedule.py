# FILE: app/discovery/routes_ignore_schedule.py
"""
Additional Discovery Routes — Ignore List + Scheduling

INSTRUCTIONS: Register this blueprint in your app factory alongside discovery_bp.
  from app.discovery.routes_ignore_schedule import discovery_ext_bp
  app.register_blueprint(discovery_ext_bp)

New endpoints:
  POST   /discovery/ignore                — ignore one or more discovered assets
  DELETE /discovery/ignore                — un-ignore assets
  GET    /discovery/ignore                — list all ignored assets
  POST   /discovery/ignore/bulk           — bulk ignore from a discovery job

  GET    /discovery/schedules             — list schedules
  POST   /discovery/schedules             — create schedule
  PATCH  /discovery/schedules/<id>        — update schedule
  DELETE /discovery/schedules/<id>        — delete schedule
  POST   /discovery/schedules/<id>/run    — run a schedule immediately
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from flask import Blueprint, request, jsonify, g
from app.extensions import db
from app.auth.decorators import require_auth, current_organization_id
from app.auth.permissions import require_role

logger = logging.getLogger(__name__)

discovery_ext_bp = Blueprint("discovery_ext", __name__, url_prefix="/discovery")


def _now_utc():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _compute_next_run(frequency: str, hour: int, day_of_week: int = None, day_of_month: int = None) -> datetime:
    """Compute the next run time from now."""
    now = _now_utc()
    base = now.replace(hour=hour, minute=0, second=0, microsecond=0)

    if frequency == "daily":
        if base <= now:
            base += timedelta(days=1)
        return base

    elif frequency == "weekly":
        dow = day_of_week if day_of_week is not None else 0  # Monday default
        days_ahead = dow - base.weekday()
        if days_ahead <= 0 or (days_ahead == 0 and base <= now):
            days_ahead += 7
        return base + timedelta(days=days_ahead)

    elif frequency == "monthly":
        dom = day_of_month if day_of_month else 1
        dom = max(1, min(28, dom))  # cap at 28 for safety
        try:
            base = base.replace(day=dom)
        except ValueError:
            base = base.replace(day=28)
        if base <= now:
            # Move to next month
            if base.month == 12:
                base = base.replace(year=base.year + 1, month=1)
            else:
                base = base.replace(month=base.month + 1)
        return base

    return base + timedelta(days=1)


# ═══════════════════════════════════════════════════════════════
# IGNORE LIST
# ═══════════════════════════════════════════════════════════════

@discovery_ext_bp.post("/ignore")
@require_auth
@require_role("analyst")
def ignore_assets():
    """
    Ignore one or more discovered assets.
    Body: { "assets": [{"assetType": "domain", "value": "cdn.example.com"}], "reason": "CDN infra" }
    or:   { "assetIds": [1, 2, 3], "reason": "..." }  — ignore by discovered_asset IDs
    """
    from app.models import IgnoredDiscoveredAsset, DiscoveredAsset

    org_id = int(current_organization_id())
    user_id = int(g.current_user.id)
    body = request.get_json(silent=True) or {}
    reason = (body.get("reason") or "").strip()[:500] or None

    items_to_ignore = []

    # Mode 1: by asset type + value
    if "assets" in body:
        for item in body["assets"]:
            at = (item.get("assetType") or item.get("asset_type") or "").strip().lower()
            val = (item.get("value") or "").strip().lower()
            if at and val:
                items_to_ignore.append((at, val))

    # Mode 2: by discovered asset IDs
    elif "assetIds" in body:
        asset_ids = body["assetIds"]
        discovered = DiscoveredAsset.query.filter(
            DiscoveredAsset.id.in_(asset_ids),
            DiscoveredAsset.organization_id == org_id,
        ).all()
        for da in discovered:
            items_to_ignore.append((da.asset_type, da.value.strip().lower()))

    if not items_to_ignore:
        return jsonify(error="No assets to ignore."), 400

    added = 0
    skipped = 0
    for asset_type, value in items_to_ignore:
        existing = IgnoredDiscoveredAsset.query.filter_by(
            organization_id=org_id, asset_type=asset_type, value=value
        ).first()
        if existing:
            skipped += 1
            continue
        db.session.add(IgnoredDiscoveredAsset(
            organization_id=org_id,
            asset_type=asset_type,
            value=value,
            reason=reason,
            ignored_by=user_id,
        ))
        added += 1

    db.session.commit()
    return jsonify(added=added, skipped=skipped), 200


@discovery_ext_bp.delete("/ignore")
@require_auth
@require_role("analyst")
def unignore_assets():
    """
    Remove assets from ignore list.
    Body: { "assets": [{"assetType": "domain", "value": "cdn.example.com"}] }
    or:   { "ids": [1, 2, 3] }  — by IgnoredDiscoveredAsset IDs
    """
    from app.models import IgnoredDiscoveredAsset

    org_id = int(current_organization_id())
    body = request.get_json(silent=True) or {}

    removed = 0

    if "ids" in body:
        items = IgnoredDiscoveredAsset.query.filter(
            IgnoredDiscoveredAsset.id.in_(body["ids"]),
            IgnoredDiscoveredAsset.organization_id == org_id,
        ).all()
        for item in items:
            db.session.delete(item)
            removed += 1

    elif "assets" in body:
        for item in body["assets"]:
            at = (item.get("assetType") or item.get("asset_type") or "").strip().lower()
            val = (item.get("value") or "").strip().lower()
            found = IgnoredDiscoveredAsset.query.filter_by(
                organization_id=org_id, asset_type=at, value=val
            ).first()
            if found:
                db.session.delete(found)
                removed += 1

    db.session.commit()
    return jsonify(removed=removed), 200


@discovery_ext_bp.get("/ignore")
@require_auth
def list_ignored():
    """List all ignored assets for the org."""
    from app.models import IgnoredDiscoveredAsset

    org_id = int(current_organization_id())
    items = IgnoredDiscoveredAsset.query.filter_by(organization_id=org_id)\
        .order_by(IgnoredDiscoveredAsset.ignored_at.desc()).all()

    return jsonify([{
        "id": i.id,
        "assetType": i.asset_type,
        "value": i.value,
        "reason": i.reason,
        "ignoredAt": i.ignored_at.isoformat() + "Z" if i.ignored_at else None,
    } for i in items]), 200


# ═══════════════════════════════════════════════════════════════
# SCHEDULES
# ═══════════════════════════════════════════════════════════════

def _serialize_schedule(s) -> dict:
    return {
        "id": s.id,
        "name": s.name,
        "target": s.target,
        "targetType": s.target_type,
        "scanDepth": s.scan_depth,
        "frequency": s.frequency,
        "dayOfWeek": s.day_of_week,
        "dayOfMonth": s.day_of_month,
        "hour": s.hour,
        "enabled": s.enabled,
        "lastRunAt": s.last_run_at.isoformat() + "Z" if s.last_run_at else None,
        "lastJobId": s.last_job_id,
        "nextRunAt": s.next_run_at.isoformat() + "Z" if s.next_run_at else None,
        "runCount": s.run_count,
        "createdAt": s.created_at.isoformat() + "Z" if s.created_at else None,
    }


@discovery_ext_bp.get("/schedules")
@require_auth
def list_schedules():
    from app.models import DiscoverySchedule
    org_id = int(current_organization_id())
    schedules = DiscoverySchedule.query.filter_by(organization_id=org_id)\
        .order_by(DiscoverySchedule.created_at.desc()).all()
    return jsonify([_serialize_schedule(s) for s in schedules]), 200


@discovery_ext_bp.post("/schedules")
@require_auth
@require_role("admin")
def create_schedule():
    from app.models import DiscoverySchedule

    org_id = int(current_organization_id())
    user_id = int(g.current_user.id)
    body = request.get_json(silent=True) or {}

    name = (body.get("name") or "").strip()
    target = (body.get("target") or "").strip()
    target_type = (body.get("targetType") or "domain").strip().lower()
    scan_depth = (body.get("scanDepth") or "standard").strip().lower()
    frequency = (body.get("frequency") or "weekly").strip().lower()
    day_of_week = body.get("dayOfWeek")
    day_of_month = body.get("dayOfMonth")
    hour = int(body.get("hour", 2))

    if not name:
        return jsonify(error="Name is required."), 400
    if not target:
        return jsonify(error="Target is required."), 400
    if frequency not in ("daily", "weekly", "monthly"):
        return jsonify(error="Frequency must be daily, weekly, or monthly."), 400
    if target_type not in ("domain", "ip", "asn", "cidr"):
        return jsonify(error="Invalid target type."), 400
    if scan_depth not in ("standard", "deep"):
        scan_depth = "standard"
    hour = max(0, min(23, hour))

    next_run = _compute_next_run(frequency, hour, day_of_week, day_of_month)

    schedule = DiscoverySchedule(
        organization_id=org_id,
        created_by=user_id,
        name=name,
        target=target,
        target_type=target_type,
        scan_depth=scan_depth,
        frequency=frequency,
        day_of_week=day_of_week,
        day_of_month=day_of_month,
        hour=hour,
        enabled=True,
        next_run_at=next_run,
    )
    db.session.add(schedule)
    db.session.commit()

    return jsonify(_serialize_schedule(schedule)), 201


@discovery_ext_bp.patch("/schedules/<int:schedule_id>")
@require_auth
@require_role("admin")
def update_schedule(schedule_id: int):
    from app.models import DiscoverySchedule

    org_id = int(current_organization_id())
    schedule = DiscoverySchedule.query.filter_by(id=schedule_id, organization_id=org_id).first()
    if not schedule:
        return jsonify(error="Schedule not found."), 404

    body = request.get_json(silent=True) or {}

    if "name" in body:
        schedule.name = (body["name"] or "").strip()
    if "target" in body:
        schedule.target = (body["target"] or "").strip()
    if "targetType" in body:
        schedule.target_type = body["targetType"]
    if "scanDepth" in body:
        schedule.scan_depth = body["scanDepth"]
    if "frequency" in body:
        schedule.frequency = body["frequency"]
    if "dayOfWeek" in body:
        schedule.day_of_week = body["dayOfWeek"]
    if "dayOfMonth" in body:
        schedule.day_of_month = body["dayOfMonth"]
    if "hour" in body:
        schedule.hour = max(0, min(23, int(body["hour"])))
    if "enabled" in body:
        schedule.enabled = bool(body["enabled"])

    # Recompute next run
    schedule.next_run_at = _compute_next_run(
        schedule.frequency, schedule.hour,
        schedule.day_of_week, schedule.day_of_month,
    )

    db.session.commit()
    return jsonify(_serialize_schedule(schedule)), 200


@discovery_ext_bp.delete("/schedules/<int:schedule_id>")
@require_auth
@require_role("admin")
def delete_schedule(schedule_id: int):
    from app.models import DiscoverySchedule

    org_id = int(current_organization_id())
    schedule = DiscoverySchedule.query.filter_by(id=schedule_id, organization_id=org_id).first()
    if not schedule:
        return jsonify(error="Schedule not found."), 404

    db.session.delete(schedule)
    db.session.commit()
    return jsonify(status="deleted"), 200


@discovery_ext_bp.post("/schedules/<int:schedule_id>/run")
@require_auth
@require_role("admin")
def run_schedule_now(schedule_id: int):
    """Trigger a scheduled discovery immediately."""
    from app.models import DiscoverySchedule, DiscoveryJob
    from app.discovery.orchestrator import DiscoveryOrchestrator
    from app.discovery.routes import _get_existing_asset_values
    from threading import Thread
    from flask import current_app

    org_id = int(current_organization_id())
    user_id = int(g.current_user.id)
    org = g.current_organization

    schedule = DiscoverySchedule.query.filter_by(id=schedule_id, organization_id=org_id).first()
    if not schedule:
        return jsonify(error="Schedule not found."), 404

    plan = org.effective_plan
    app = current_app._get_current_object()
    existing = _get_existing_asset_values(org_id)
    ignored = _get_ignored_values(org_id)

    # Create job
    job = DiscoveryJob(
        organization_id=org_id,
        created_by=user_id,
        target=schedule.target,
        target_type=schedule.target_type,
        status="pending",
        config={"scan_depth": schedule.scan_depth, "scheduled": True, "schedule_id": schedule.id},
    )
    db.session.add(job)
    db.session.commit()
    job_id = job.id

    def _run():
        with app.app_context():
            orchestrator = DiscoveryOrchestrator(app=app)
            try:
                orchestrator.run_discovery(
                    job_id=job_id, org_id=org_id,
                    target=schedule.target, target_type=schedule.target_type,
                    plan=plan, config={"scan_depth": schedule.scan_depth},
                    existing_asset_values=existing | ignored,
                )
            except Exception as e:
                logger.error("Scheduled discovery failed: %s", e, exc_info=True)
            finally:
                with app.app_context():
                    s = db.session.get(DiscoverySchedule, schedule_id)
                    if s:
                        s.last_run_at = _now_utc()
                        s.last_job_id = job_id
                        s.run_count = (s.run_count or 0) + 1
                        s.next_run_at = _compute_next_run(
                            s.frequency, s.hour, s.day_of_week, s.day_of_month
                        )
                        db.session.commit()

    Thread(target=_run, daemon=True).start()

    schedule.last_job_id = job_id
    db.session.commit()

    return jsonify(jobId=job_id, status="started"), 202


def _get_ignored_values(org_id: int) -> set:
    """Get all ignored asset values for an org."""
    from app.models import IgnoredDiscoveredAsset
    items = IgnoredDiscoveredAsset.query.filter_by(organization_id=org_id)\
        .with_entities(IgnoredDiscoveredAsset.value).all()
    return {i.value.strip().lower() for i in items}