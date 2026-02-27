# =============================================================================
# File: app/scan_schedules/routes.py
# Description: Scan schedule routes for creating, updating, deleting, and
#   manually triggering scheduled scans. Supports asset and group schedules
#   with daily/weekly/monthly frequencies.
#
# Permissions Integration (based on permissions integration guide):
#   - GET /scan-schedules: all roles can view
#   - POST /scan-schedules: analyst+ with scheduled_scans limit + scan profile check
#   - PATCH /scan-schedules/<id>: analyst+
#   - DELETE /scan-schedules/<id>: analyst+
#   - POST /scan-schedules/<id>/run-now: analyst+ with scans_per_month limit
# =============================================================================

from __future__ import annotations
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify
from app.extensions import db
from app.models import ScanSchedule, ScanJob, ScanProfile, Asset, AssetGroup
from app.auth.decorators import require_auth, current_user_id, current_organization_id
from app.auth.permissions import require_role, check_limit, check_scan_profile
from app.audit.routes import log_audit

scan_schedules_bp = Blueprint("scan_schedules", __name__, url_prefix="/scan-schedules")


def now_utc():
    return datetime.now(timezone.utc)


def _to_dict(s):
    asset = s.asset if s.asset_id else None
    group = None
    if s.group_id:
        group = AssetGroup.query.get(s.group_id)
    elif asset and hasattr(asset, "group"):
        group = asset.group
    profile = s.profile

    return {
        "id": str(s.id),
        "scheduleType": s.schedule_type or "asset",
        "assetId": str(s.asset_id) if s.asset_id else None,
        "assetValue": asset.value if asset else None,
        "assetType": asset.asset_type if asset else None,
        "groupId": str(s.group_id or (group.id if group else None)) if (s.group_id or group) else None,
        "groupName": group.name if group else None,
        "profileId": str(s.profile_id) if s.profile_id else None,
        "profileName": profile.name if profile else None,
        "name": s.name,
        "frequency": s.frequency,
        "timeOfDay": s.time_of_day,
        "dayOfWeek": s.day_of_week,
        "dayOfMonth": s.day_of_month,
        "enabled": s.enabled,
        "lastRunAt": s.last_run_at.isoformat() if s.last_run_at else None,
        "nextRunAt": s.next_run_at.isoformat() if s.next_run_at else None,
        "lastScanJobId": str(s.last_scan_job_id) if s.last_scan_job_id else None,
        "createdAt": s.created_at.isoformat() if s.created_at else None,
        "updatedAt": s.updated_at.isoformat() if s.updated_at else None,
    }


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


def _schedule_label(s) -> str:
    """Build a human-readable label for a schedule."""
    if s.name:
        return s.name
    if s.asset_id and s.asset:
        return s.asset.value
    if s.group_id:
        group = AssetGroup.query.get(s.group_id)
        if group:
            return f"Group: {group.name}"
    return f"Schedule #{s.id}"


# -- LIST -- all roles can view
@scan_schedules_bp.get("")
@require_auth
def list_schedules():
    org_id = current_organization_id()
    rows = (
        ScanSchedule.query
        .filter_by(organization_id=org_id)
        .order_by(ScanSchedule.enabled.desc(), ScanSchedule.created_at.desc())
        .all()
    )
    return jsonify([_to_dict(s) for s in rows]), 200


# -- CREATE -- analyst+ with scheduled_scans limit + scan profile check
@scan_schedules_bp.post("")
@require_auth
@require_role("analyst")
@check_limit("scheduled_scans")
@check_scan_profile()
def create_schedule():
    org_id = current_organization_id()
    user_id = current_user_id()
    body = request.get_json(silent=True) or {}

    schedule_type = body.get("scheduleType") or body.get("schedule_type") or "asset"
    if schedule_type not in ("asset", "group"):
        return jsonify(error="scheduleType must be 'asset' or 'group'"), 400

    asset_id = None
    group_id = None
    target_label = None

    if schedule_type == "asset":
        raw_asset_id = body.get("assetId") or body.get("asset_id")
        if not raw_asset_id:
            return jsonify(error="assetId is required for asset schedules"), 400
        asset = Asset.query.filter_by(id=int(raw_asset_id), organization_id=org_id).first()
        if not asset:
            return jsonify(error="Asset not found"), 404
        asset_id = asset.id
        target_label = asset.value

    elif schedule_type == "group":
        raw_group_id = body.get("groupId") or body.get("group_id")
        if not raw_group_id:
            return jsonify(error="groupId is required for group schedules"), 400
        group = AssetGroup.query.filter_by(id=int(raw_group_id), organization_id=org_id).first()
        if not group:
            return jsonify(error="Group not found"), 404
        group_id = group.id
        target_label = f"Group: {group.name}"

    frequency = body.get("frequency", "daily")
    if frequency not in ("daily", "weekly", "monthly"):
        return jsonify(error="frequency must be daily, weekly, or monthly"), 400

    time_of_day = body.get("timeOfDay") or body.get("time_of_day") or "02:00"

    day_of_week = body.get("dayOfWeek") or body.get("day_of_week")
    day_of_month = body.get("dayOfMonth") or body.get("day_of_month")
    if day_of_week is not None:
        day_of_week = int(day_of_week)
    if day_of_month is not None:
        day_of_month = int(day_of_month)

    profile_id = body.get("profileId") or body.get("profile_id")
    profile_name = None
    if profile_id:
        profile = ScanProfile.query.filter_by(id=int(profile_id)).first()
        if not profile:
            return jsonify(error="Profile not found"), 404
        if not profile.is_system and profile.organization_id != org_id:
            return jsonify(error="Access denied to this profile"), 403
        profile_id = profile.id
        profile_name = profile.name
    else:
        profile_id = None

    next_run = _compute_next_run(frequency, time_of_day, day_of_week, day_of_month)

    schedule = ScanSchedule(
        organization_id=org_id,
        user_id=user_id,
        schedule_type=schedule_type,
        asset_id=asset_id,
        group_id=group_id,
        profile_id=profile_id,
        name=body.get("name") or None,
        frequency=frequency,
        time_of_day=time_of_day,
        day_of_week=day_of_week,
        day_of_month=day_of_month,
        enabled=True,
        next_run_at=next_run,
    )
    db.session.add(schedule)
    db.session.flush()  # get schedule.id

    log_audit(
        organization_id=org_id,
        user_id=user_id,
        action="scan.schedule_created",
        category="scan",
        target_type="scan_schedule",
        target_id=str(schedule.id),
        target_label=target_label,
        description=f"Created {frequency} scan schedule for {target_label}",
        metadata={"schedule_type": schedule_type, "frequency": frequency, "profile": profile_name},
    )

    db.session.commit()
    return jsonify(_to_dict(schedule)), 201


# -- UPDATE (PATCH) -- analyst+
@scan_schedules_bp.patch("/<int:schedule_id>")
@require_auth
@require_role("analyst")
def update_schedule(schedule_id):
    org_id = current_organization_id()
    schedule = ScanSchedule.query.filter_by(id=schedule_id, organization_id=org_id).first()
    if not schedule:
        return jsonify(error="Schedule not found"), 404

    body = request.get_json(silent=True) or {}
    changed_fields = []

    if "enabled" in body:
        schedule.enabled = bool(body["enabled"])
        changed_fields.append("enabled")

    if "name" in body:
        schedule.name = body["name"] or None
        changed_fields.append("name")

    new_freq = body.get("frequency")
    new_time = body.get("timeOfDay") or body.get("time_of_day")
    new_dow = body.get("dayOfWeek") or body.get("day_of_week")
    new_dom = body.get("dayOfMonth") or body.get("day_of_month")

    if new_freq and new_freq in ("daily", "weekly", "monthly"):
        schedule.frequency = new_freq
        changed_fields.append("frequency")
    if new_time:
        schedule.time_of_day = new_time
        changed_fields.append("timeOfDay")
    if new_dow is not None:
        schedule.day_of_week = int(new_dow)
        changed_fields.append("dayOfWeek")
    if new_dom is not None:
        schedule.day_of_month = int(new_dom)
        changed_fields.append("dayOfMonth")

    new_profile_id = body.get("profileId") or body.get("profile_id")
    if new_profile_id is not None:
        if new_profile_id:
            profile = ScanProfile.query.filter_by(id=int(new_profile_id)).first()
            if not profile:
                return jsonify(error="Profile not found"), 404
            schedule.profile_id = profile.id
        else:
            schedule.profile_id = None
        changed_fields.append("profileId")

    if changed_fields:
        schedule.next_run_at = _compute_next_run(
            schedule.frequency,
            schedule.time_of_day,
            schedule.day_of_week,
            schedule.day_of_month,
        )

        log_audit(
            organization_id=org_id,
            user_id=current_user_id(),
            action="scan.schedule_updated",
            category="scan",
            target_type="scan_schedule",
            target_id=str(schedule.id),
            target_label=_schedule_label(schedule),
            description=f"Updated scan schedule '{_schedule_label(schedule)}'",
            metadata={"fields": changed_fields},
        )

        db.session.commit()

    return jsonify(_to_dict(schedule)), 200


# -- DELETE -- analyst+
@scan_schedules_bp.delete("/<int:schedule_id>")
@require_auth
@require_role("analyst")
def delete_schedule(schedule_id):
    org_id = current_organization_id()
    schedule = ScanSchedule.query.filter_by(id=schedule_id, organization_id=org_id).first()
    if not schedule:
        return jsonify(error="Schedule not found"), 404

    label = _schedule_label(schedule)

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="scan.schedule_deleted",
        category="scan",
        target_type="scan_schedule",
        target_id=str(schedule_id),
        target_label=label,
        description=f"Deleted scan schedule '{label}'",
    )

    db.session.delete(schedule)
    db.session.commit()
    return jsonify(message="deleted", scheduleId=str(schedule_id)), 200


# -- RUN NOW -- analyst+ with scans_per_month limit
@scan_schedules_bp.post("/<int:schedule_id>/run-now")
@require_auth
@require_role("analyst")
@check_limit("scans_per_month")
def run_schedule_now(schedule_id):
    org_id = current_organization_id()
    uid = current_user_id()
    schedule = ScanSchedule.query.filter_by(id=schedule_id, organization_id=org_id).first()
    if not schedule:
        return jsonify(error="Schedule not found"), 404

    job_ids = []

    if schedule.schedule_type == "group" and schedule.group_id:
        # Create a scan job for every asset in the group
        assets = Asset.query.filter_by(
            group_id=schedule.group_id, organization_id=org_id
        ).all()
        if not assets:
            return jsonify(error="No assets in group"), 400

        for asset in assets:
            job = ScanJob(
                asset_id=asset.id,
                status="queued",
                profile_id=schedule.profile_id,
                schedule_id=schedule.id,
            )
            db.session.add(job)
            db.session.flush()
            job_ids.append(str(job.id))

        schedule.last_scan_job_id = job.id  # last one created
    else:
        # Single asset schedule
        if not schedule.asset_id:
            return jsonify(error="Schedule has no asset assigned"), 400

        job = ScanJob(
            asset_id=schedule.asset_id,
            status="queued",
            profile_id=schedule.profile_id,
            schedule_id=schedule.id,
        )
        db.session.add(job)
        db.session.flush()
        job_ids.append(str(job.id))
        schedule.last_scan_job_id = job.id

    schedule.last_run_at = now_utc()
    schedule.next_run_at = _compute_next_run(
        schedule.frequency,
        schedule.time_of_day,
        schedule.day_of_week,
        schedule.day_of_month,
    )

    log_audit(
        organization_id=org_id,
        user_id=uid,
        action="scan.schedule_triggered",
        category="scan",
        target_type="scan_schedule",
        target_id=str(schedule_id),
        target_label=_schedule_label(schedule),
        description=f"Manually triggered schedule '{_schedule_label(schedule)}' — {len(job_ids)} job(s) queued",
        metadata={"job_ids": job_ids, "job_count": len(job_ids)},
    )

    db.session.commit()

    return jsonify(
        message="scan queued",
        jobIds=job_ids,
        jobId=job_ids[0] if job_ids else None,
        jobCount=len(job_ids),
        scheduleId=str(schedule_id),
    ), 200