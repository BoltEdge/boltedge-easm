# =============================================================================
# File: app/monitoring/routes.py
# Description: Monitoring routes — CRUD for monitors, alerts, settings, and
#   tuning rules. All routes are plan-gated behind the "monitoring" feature.
#
# Permissions Integration (based on permissions integration guide):
#   - All routes: require_feature("monitoring") — plan-gated
#   - GET /monitors: all roles can view
#   - POST /monitors: analyst+ (create monitors)
#   - PATCH /monitors/<id>: analyst+ (update monitors)
#   - DELETE /monitors/<id>: analyst+ (delete monitors)
#   - GET /monitors/alerts: all roles can view
#   - POST /monitors/alerts/<id>/acknowledge: analyst+
#   - POST /monitors/alerts/<id>/resolve: analyst+
#   - GET /monitors/alerts/export: admin+ (export_alerts permission) — not yet implemented
#   - GET /monitors/settings: all roles can view
#   - PUT /monitors/settings: analyst+ (configure_scan_settings permission)
#   - GET /monitors/tuning: all roles can view
#   - POST /monitors/tuning: analyst+ (create_tuning_rules permission)
#   - PATCH /monitors/tuning/<id>: analyst+ (edit_tuning_rules permission)
#   - DELETE /monitors/tuning/<id>: analyst+ (delete tuning rules)
#   - GET /monitors/dashboard-summary: all roles can view
# =============================================================================

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request, jsonify
from sqlalchemy import or_, func

from app.extensions import db
from app.models import (
    Monitor,
    MonitorAlert,
    MonitorSettings,
    TuningRule,
    Asset,
    AssetGroup,
    ScanJob,
    Organization,
)
from app.auth.decorators import require_auth, current_user_id, current_organization_id
from app.auth.permissions import require_role, require_feature, require_permission
from app.audit.routes import log_audit

logger = logging.getLogger(__name__)

monitoring_bp = Blueprint("monitoring", __name__, url_prefix="/monitors")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sid(x) -> str:
    return str(x) if x is not None else ""


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _compute_next_check(frequency: str, from_dt: datetime | None = None) -> datetime:
    """Compute the next check time based on frequency."""
    base = from_dt or _now()
    if frequency == "daily":
        return base + timedelta(days=1)
    elif frequency == "every_2_days":
        return base + timedelta(days=2)
    elif frequency == "weekly":
        return base + timedelta(weeks=1)
    return base + timedelta(days=2)  # default


def _allowed_frequency(org: Organization) -> str:
    """Return the monitoring frequency allowed by the org's plan."""
    plan = (org.plan or "free").lower()
    if plan == "enterprise":
        return "daily"
    # Pro and free-trial both get every_2_days
    return "every_2_days"


def _plan_allows_monitoring(org: Organization) -> bool:
    # Free trial: everyone gets Pro-level monitoring
    # TODO: Gate by plan when billing is wired up
    return True


def _monitor_to_ui(m: Monitor) -> dict:
    """Serialize a Monitor for the frontend."""
    asset = m.asset
    group = m.group

    # Count open alerts
    open_alerts = MonitorAlert.query.filter_by(
        monitor_id=m.id, status="open"
    ).count()

    target_name = None
    target_type = None
    if asset:
        target_name = asset.value
        target_type = "asset"
    elif group:
        target_name = group.name
        target_type = "group"

    return {
        "id": _sid(m.id),
        "targetType": target_type,
        "targetName": target_name,
        "assetId": _sid(m.asset_id),
        "groupId": _sid(m.group_id),
        "monitorTypes": m.monitor_types or ["all"],
        "frequency": m.frequency,
        "enabled": m.enabled,
        "lastCheckedAt": m.last_checked_at.isoformat() if m.last_checked_at else None,
        "nextCheckAt": m.next_check_at.isoformat() if m.next_check_at else None,
        "openAlerts": open_alerts,
        "createdAt": m.created_at.isoformat() if m.created_at else None,
    }


def _alert_to_ui(a: MonitorAlert) -> dict:
    """Serialize a MonitorAlert for the frontend."""
    return {
        "id": _sid(a.id),
        "monitorId": _sid(a.monitor_id),
        "findingId": _sid(a.finding_id),
        "alertType": a.alert_type,
        "templateId": a.template_id,
        "alertName": a.alert_name,
        "title": a.title,
        "summary": a.summary,
        "severity": a.severity,
        "assetValue": a.asset_value,
        "groupName": a.group_name,
        "status": a.status,
        "notifiedVia": a.notified_via or [],
        "createdAt": a.created_at.isoformat() if a.created_at else None,
        "acknowledgedAt": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        "resolvedAt": a.resolved_at.isoformat() if a.resolved_at else None,
    }


def _settings_to_ui(s: MonitorSettings) -> dict:
    return {
        "emailEnabled": s.email_enabled,
        "inAppEnabled": s.in_app_enabled,
        "webhookEnabled": s.webhook_enabled,
        "webhookUrl": s.webhook_url or "",
        "emailRecipients": s.email_recipients or [],
        "notifyOnSeverity": s.notify_on_severity or ["critical", "high", "medium", "low", "info"],
        "digestFrequency": s.digest_frequency or "immediate",
    }


def _tuning_rule_to_ui(r: TuningRule) -> dict:
    # Resolve asset/group names for display
    asset_value = None
    group_name = None
    if r.asset_id:
        asset = Asset.query.get(r.asset_id)
        if asset:
            asset_value = asset.value
    if r.group_id:
        group = AssetGroup.query.get(r.group_id)
        if group:
            group_name = group.name

    return {
        "id": _sid(r.id),
        "enabled": r.enabled,
        "templateId": r.template_id,
        "category": r.category,
        "severityMatch": r.severity_match,
        "assetId": _sid(r.asset_id),
        "assetValue": asset_value,
        "groupId": _sid(r.group_id),
        "groupName": group_name,
        "assetPattern": r.asset_pattern,
        "port": r.port,
        "serviceName": r.service_name,
        "cwe": r.cwe,
        "titleContains": r.title_contains,
        "action": r.action,
        "targetSeverity": r.target_severity,
        "snoozeUntil": r.snooze_until.isoformat() if r.snooze_until else None,
        "reason": r.reason,
        "createdAt": r.created_at.isoformat() if r.created_at else None,
    }


def _compute_dedupe_key(data: dict) -> str:
    """Hash the match condition fields to prevent duplicate rules."""
    fields = [
        data.get("templateId", ""),
        data.get("category", ""),
        data.get("severityMatch", ""),
        str(data.get("assetId", "")),
        str(data.get("groupId", "")),
        data.get("assetPattern", ""),
        str(data.get("port", "")),
        data.get("serviceName", ""),
        data.get("cwe", ""),
        data.get("titleContains", ""),
        data.get("action", ""),
    ]
    raw = "|".join(fields)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


from app.integrations.routes import dispatch_event as _dispatch_event


def dispatch_monitor_alert(alert: MonitorAlert, org_id: int):
    """Dispatch a notification when a new monitor alert is created."""
    try:
        _dispatch_event(org_id, "monitor.alert", {
            "alert_id": str(alert.id),
            "title": alert.title or alert.alert_name or "Monitor Alert",
            "severity": alert.severity or "high",
            "asset": alert.asset_value or "",
            "group": alert.group_name or "",
            "description": (alert.summary or "")[:500],
            "alert_type": alert.alert_type or "",
        })
    except Exception as e:
        logger.warning(f"Failed to dispatch monitor alert notification: {e}")


# ===========================================================================
# MONITORS CRUD
# ===========================================================================

# GET /monitors — all roles can view (plan-gated)
@monitoring_bp.get("")
@require_auth
@require_feature("monitoring")
def list_monitors():
    org_id = current_organization_id()
    monitors = Monitor.query.filter_by(organization_id=org_id).order_by(Monitor.created_at.desc()).all()
    return jsonify([_monitor_to_ui(m) for m in monitors])


# POST /monitors — analyst+ (plan-gated)
@monitoring_bp.post("")
@require_auth
@require_feature("monitoring")
@require_role("analyst")
def create_monitor():
    org_id = current_organization_id()
    user_id = current_user_id()
    data = request.get_json(silent=True) or {}

    # Plan gating
    org = Organization.query.get(org_id)
    if not org or not _plan_allows_monitoring(org):
        return jsonify({"error": "Monitoring requires a Pro or Enterprise plan."}), 403

    asset_id = data.get("assetId")
    group_id = data.get("groupId")
    target_type = data.get("targetType", "asset")

    if target_type == "asset":
        if not asset_id:
            return jsonify({"error": "assetId is required for asset monitors."}), 400
        asset = Asset.query.filter_by(id=int(asset_id), organization_id=org_id).first()
        if not asset:
            return jsonify({"error": "Asset not found."}), 404

        # Must have at least one completed scan for baseline
        baseline = ScanJob.query.filter_by(
            asset_id=asset.id, status="completed"
        ).order_by(ScanJob.finished_at.desc()).first()
        if not baseline:
            return jsonify({"error": "Asset must have at least one completed scan before monitoring."}), 400

        # Check for duplicate
        existing = Monitor.query.filter_by(organization_id=org_id, asset_id=asset.id).first()
        if existing:
            return jsonify({"error": "A monitor already exists for this asset."}), 409

        group_id_val = None
    elif target_type == "group":
        if not group_id:
            return jsonify({"error": "groupId is required for group monitors."}), 400
        group = AssetGroup.query.filter_by(id=int(group_id), organization_id=org_id).first()
        if not group:
            return jsonify({"error": "Group not found."}), 404

        # At least one asset in the group must have a completed scan
        group_assets = Asset.query.filter_by(group_id=group.id).all()
        has_baseline = any(
            ScanJob.query.filter_by(asset_id=a.id, status="completed").first()
            for a in group_assets
        )
        if not has_baseline:
            return jsonify({"error": "At least one asset in the group must have a completed scan."}), 400

        # Check for duplicate
        existing = Monitor.query.filter_by(organization_id=org_id, group_id=group.id).first()
        if existing:
            return jsonify({"error": "A monitor already exists for this group."}), 409

        asset_id = None
        group_id_val = group.id
    else:
        return jsonify({"error": "targetType must be 'asset' or 'group'."}), 400

    # Monitor types
    monitor_types = data.get("monitorTypes", ["all"])
    valid_types = {"dns", "ssl", "ports", "headers", "tech", "cve", "all"}
    if not isinstance(monitor_types, list) or not all(t in valid_types for t in monitor_types):
        return jsonify({"error": f"Invalid monitor types. Allowed: {sorted(valid_types)}"}), 400

    # Frequency is determined by plan
    frequency = _allowed_frequency(org)

    # Find baseline scan job for asset monitors
    baseline_id = None
    if target_type == "asset":
        baseline_id = baseline.id

    monitor = Monitor(
        organization_id=org_id,
        created_by=user_id,
        asset_id=int(asset_id) if asset_id else None,
        group_id=group_id_val if target_type == "group" else None,
        monitor_types=monitor_types,
        frequency=frequency,
        enabled=True,
        baseline_scan_job_id=baseline_id,
        next_check_at=_compute_next_check(frequency),
    )

    db.session.add(monitor)
    db.session.commit()

    # Resolve target label for audit
    if target_type == "asset":
        target_label = asset.value
    else:
        target_label = group.name

    log_audit(
        organization_id=org_id,
        user_id=user_id,
        action="monitor.created",
        category="monitor",
        target_type="monitor",
        target_id=str(monitor.id),
        target_label=target_label,
        description=f"Created {target_type} monitor for {target_label}",
        metadata={"target_type": target_type, "monitor_types": monitor_types, "frequency": frequency},
    )

    logger.info("Monitor created: id=%s org=%s target=%s", monitor.id, org_id, target_type)
    return jsonify(_monitor_to_ui(monitor)), 201


# PATCH /monitors/<id> — analyst+ (plan-gated)
@monitoring_bp.patch("/<int:monitor_id>")
@require_auth
@require_feature("monitoring")
@require_role("analyst")
def update_monitor(monitor_id: int):
    org_id = current_organization_id()
    monitor = Monitor.query.filter_by(id=monitor_id, organization_id=org_id).first()
    if not monitor:
        return jsonify({"error": "Monitor not found."}), 404

    data = request.get_json(silent=True) or {}
    changes = {}

    # Toggle enabled
    if "enabled" in data:
        old_enabled = monitor.enabled
        monitor.enabled = bool(data["enabled"])
        if monitor.enabled and not monitor.next_check_at:
            monitor.next_check_at = _compute_next_check(monitor.frequency)
        if old_enabled != monitor.enabled:
            changes["enabled"] = {"old": old_enabled, "new": monitor.enabled}

    # Update monitor types
    if "monitorTypes" in data:
        valid_types = {"dns", "ssl", "ports", "headers", "tech", "cve", "all"}
        types = data["monitorTypes"]
        if isinstance(types, list) and all(t in valid_types for t in types):
            old_types = monitor.monitor_types
            monitor.monitor_types = types
            changes["monitorTypes"] = {"old": old_types, "new": types}

    monitor.updated_at = _now()
    db.session.commit()

    if changes:
        target_label = None
        if monitor.asset:
            target_label = monitor.asset.value
        elif monitor.group:
            target_label = monitor.group.name

        log_audit(
            organization_id=org_id,
            user_id=current_user_id(),
            action="monitor.updated",
            category="monitor",
            target_type="monitor",
            target_id=str(monitor.id),
            target_label=target_label,
            description=f"Updated monitor for {target_label or monitor_id}",
            metadata={"changes": changes},
        )

    return jsonify(_monitor_to_ui(monitor))


# DELETE /monitors/<id> — analyst+ (plan-gated)
@monitoring_bp.delete("/<int:monitor_id>")
@require_auth
@require_feature("monitoring")
@require_role("analyst")
def delete_monitor(monitor_id: int):
    org_id = current_organization_id()
    monitor = Monitor.query.filter_by(id=monitor_id, organization_id=org_id).first()
    if not monitor:
        return jsonify({"error": "Monitor not found."}), 404

    target_label = None
    if monitor.asset:
        target_label = monitor.asset.value
    elif monitor.group:
        target_label = monitor.group.name

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="monitor.deleted",
        category="monitor",
        target_type="monitor",
        target_id=str(monitor_id),
        target_label=target_label,
        description=f"Deleted monitor for {target_label or monitor_id}",
    )

    db.session.delete(monitor)
    db.session.commit()
    logger.info("Monitor deleted: id=%s org=%s", monitor_id, org_id)
    return jsonify({"ok": True})


# ===========================================================================
# ALERTS
# ===========================================================================

# GET /monitors/alerts — all roles can view (plan-gated)
@monitoring_bp.get("/alerts")
@require_auth
@require_feature("monitoring")
def list_alerts():
    org_id = current_organization_id()

    q = MonitorAlert.query.filter_by(organization_id=org_id)

    # Filters
    status = request.args.get("status")
    if status and status != "all":
        q = q.filter_by(status=status)

    severity = request.args.get("severity")
    if severity:
        q = q.filter_by(severity=severity)

    search = request.args.get("search", "").strip()
    if search:
        like = f"%{search}%"
        q = q.filter(
            or_(
                MonitorAlert.title.ilike(like),
                MonitorAlert.summary.ilike(like),
                MonitorAlert.asset_value.ilike(like),
                MonitorAlert.alert_name.ilike(like),
            )
        )

    limit = min(int(request.args.get("limit", 50)), 200)
    alerts = q.order_by(MonitorAlert.created_at.desc()).limit(limit).all()

    # Also return status counts for filter pills
    counts = dict(
        db.session.query(MonitorAlert.status, func.count(MonitorAlert.id))
        .filter_by(organization_id=org_id)
        .group_by(MonitorAlert.status)
        .all()
    )

    return jsonify({
        "alerts": [_alert_to_ui(a) for a in alerts],
        "counts": {
            "open": counts.get("open", 0),
            "acknowledged": counts.get("acknowledged", 0),
            "resolved": counts.get("resolved", 0),
            "total": sum(counts.values()),
        },
    })


# POST /monitors/alerts/<id>/acknowledge — analyst+ (plan-gated)
@monitoring_bp.post("/alerts/<int:alert_id>/acknowledge")
@require_auth
@require_feature("monitoring")
@require_role("analyst")
def acknowledge_alert(alert_id: int):
    org_id = current_organization_id()
    user_id = current_user_id()

    alert = MonitorAlert.query.filter_by(id=alert_id, organization_id=org_id).first()
    if not alert:
        return jsonify({"error": "Alert not found."}), 404

    if alert.status not in ("open",):
        return jsonify({"error": f"Cannot acknowledge alert with status '{alert.status}'."}), 400

    alert.status = "acknowledged"
    alert.acknowledged_at = _now()
    alert.acknowledged_by = user_id
    alert.updated_at = _now()
    db.session.commit()

    log_audit(
        organization_id=org_id,
        user_id=user_id,
        action="monitor.alert_acknowledged",
        category="monitor",
        target_type="monitor_alert",
        target_id=str(alert.id),
        target_label=alert.title or alert.alert_name,
        description=f"Acknowledged alert: {alert.title or alert.alert_name or alert_id}",
    )

    return jsonify(_alert_to_ui(alert))


# POST /monitors/alerts/<id>/resolve — analyst+ (plan-gated)
@monitoring_bp.post("/alerts/<int:alert_id>/resolve")
@require_auth
@require_feature("monitoring")
@require_role("analyst")
def resolve_alert(alert_id: int):
    org_id = current_organization_id()
    user_id = current_user_id()

    alert = MonitorAlert.query.filter_by(id=alert_id, organization_id=org_id).first()
    if not alert:
        return jsonify({"error": "Alert not found."}), 404

    if alert.status not in ("open", "acknowledged"):
        return jsonify({"error": f"Cannot resolve alert with status '{alert.status}'."}), 400

    old_status = alert.status
    alert.status = "resolved"
    alert.resolved_at = _now()
    alert.resolved_by = user_id
    alert.updated_at = _now()
    db.session.commit()

    log_audit(
        organization_id=org_id,
        user_id=user_id,
        action="monitor.alert_resolved",
        category="monitor",
        target_type="monitor_alert",
        target_id=str(alert.id),
        target_label=alert.title or alert.alert_name,
        description=f"Resolved alert: {alert.title or alert.alert_name or alert_id}",
        metadata={"old_status": old_status},
    )

    return jsonify(_alert_to_ui(alert))


# ===========================================================================
# SETTINGS
# ===========================================================================

# GET /monitors/settings — all roles can view (plan-gated)
@monitoring_bp.get("/settings")
@require_auth
@require_feature("monitoring")
def get_settings():
    org_id = current_organization_id()

    settings = MonitorSettings.query.filter_by(organization_id=org_id).first()
    if not settings:
        # Return defaults — we'll create on first save
        return jsonify({
            "emailEnabled": True,
            "inAppEnabled": True,
            "webhookEnabled": False,
            "webhookUrl": "",
            "emailRecipients": [],
            "notifyOnSeverity": ["critical", "high", "medium", "low", "info"],
            "digestFrequency": "immediate",
        })

    return jsonify(_settings_to_ui(settings))


# PUT /monitors/settings — analyst+ (configure_scan_settings permission, plan-gated)
@monitoring_bp.put("/settings")
@require_auth
@require_feature("monitoring")
@require_permission("configure_scan_settings")
def update_settings():
    org_id = current_organization_id()
    data = request.get_json(silent=True) or {}

    settings = MonitorSettings.query.filter_by(organization_id=org_id).first()
    is_new = not settings
    if not settings:
        settings = MonitorSettings(organization_id=org_id)
        db.session.add(settings)

    updated_fields = []

    # Update channels
    if "emailEnabled" in data:
        settings.email_enabled = bool(data["emailEnabled"])
        updated_fields.append("emailEnabled")
    if "inAppEnabled" in data:
        settings.in_app_enabled = bool(data["inAppEnabled"])
        updated_fields.append("inAppEnabled")
    if "webhookEnabled" in data:
        settings.webhook_enabled = bool(data["webhookEnabled"])
        updated_fields.append("webhookEnabled")
    if "webhookUrl" in data:
        settings.webhook_url = str(data["webhookUrl"]).strip()[:500]
        updated_fields.append("webhookUrl")

    # Email recipients
    if "emailRecipients" in data:
        recipients = data["emailRecipients"]
        if isinstance(recipients, list):
            # Basic email validation
            settings.email_recipients = [
                r.strip()[:255] for r in recipients
                if isinstance(r, str) and "@" in r
            ]
            updated_fields.append("emailRecipients")

    # Severity filter
    if "notifyOnSeverity" in data:
        valid = {"critical", "high", "medium", "low", "info"}
        severities = data["notifyOnSeverity"]
        if isinstance(severities, list):
            settings.notify_on_severity = [s for s in severities if s in valid]
            updated_fields.append("notifyOnSeverity")

    # Digest
    if "digestFrequency" in data:
        valid_freq = {"immediate", "daily_digest", "weekly_digest"}
        if data["digestFrequency"] in valid_freq:
            settings.digest_frequency = data["digestFrequency"]
            updated_fields.append("digestFrequency")

    settings.updated_at = _now()
    db.session.commit()

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="settings.monitoring_updated",
        category="settings",
        target_type="monitor_settings",
        description=f"{'Created' if is_new else 'Updated'} monitoring notification settings",
        metadata={"fields": updated_fields},
    )

    return jsonify(_settings_to_ui(settings))


# ===========================================================================
# TUNING RULES
# ===========================================================================

# GET /monitors/tuning — all roles can view (plan-gated)
@monitoring_bp.get("/tuning")
@require_auth
@require_feature("monitoring")
def list_tuning_rules():
    org_id = current_organization_id()

    rules = TuningRule.query.filter_by(organization_id=org_id).order_by(
        TuningRule.created_at.desc()
    ).all()

    return jsonify([_tuning_rule_to_ui(r) for r in rules])


# POST /monitors/tuning — analyst+ (create_tuning_rules permission, plan-gated)
@monitoring_bp.post("/tuning")
@require_auth
@require_feature("monitoring")
@require_permission("create_tuning_rules")
def create_tuning_rule():
    org_id = current_organization_id()
    user_id = current_user_id()
    data = request.get_json(silent=True) or {}

    # Validate action
    action = data.get("action")
    valid_actions = {"suppress", "downgrade", "upgrade", "snooze"}
    if action not in valid_actions:
        return jsonify({"error": f"action must be one of: {sorted(valid_actions)}"}), 400

    # Validate at least one match condition
    match_fields = [
        "templateId", "category", "severityMatch", "assetId", "groupId",
        "assetPattern", "port", "serviceName", "cwe", "titleContains",
    ]
    has_condition = any(data.get(f) for f in match_fields)
    if not has_condition:
        return jsonify({"error": "At least one match condition is required."}), 400

    # For downgrade/upgrade — require target severity
    if action in ("downgrade", "upgrade") and not data.get("targetSeverity"):
        return jsonify({"error": f"targetSeverity is required for {action}."}), 400

    # For snooze — require snooze_until
    if action == "snooze" and not data.get("snoozeUntil"):
        return jsonify({"error": "snoozeUntil is required for snooze."}), 400

    # Validate references
    asset_id = None
    if data.get("assetId"):
        asset = Asset.query.filter_by(id=int(data["assetId"]), organization_id=org_id).first()
        if not asset:
            return jsonify({"error": "Asset not found."}), 404
        asset_id = asset.id

    group_id = None
    if data.get("groupId"):
        group = AssetGroup.query.filter_by(id=int(data["groupId"]), organization_id=org_id).first()
        if not group:
            return jsonify({"error": "Group not found."}), 404
        group_id = group.id

    # Dedupe check
    dedupe_key = _compute_dedupe_key(data)
    existing = TuningRule.query.filter_by(organization_id=org_id, dedupe_key=dedupe_key).first()
    if existing:
        return jsonify({"error": "A rule with these exact match conditions already exists."}), 409

    # Parse snooze_until
    snooze_until = None
    if data.get("snoozeUntil"):
        try:
            snooze_until = datetime.fromisoformat(data["snoozeUntil"].replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, AttributeError):
            return jsonify({"error": "Invalid snoozeUntil date format."}), 400

    # Validate severities
    valid_severities = {"critical", "high", "medium", "low", "info"}
    target_severity = data.get("targetSeverity")
    if target_severity and target_severity not in valid_severities:
        return jsonify({"error": f"Invalid targetSeverity. Allowed: {sorted(valid_severities)}"}), 400
    severity_match = data.get("severityMatch")
    if severity_match and severity_match not in valid_severities:
        return jsonify({"error": f"Invalid severityMatch. Allowed: {sorted(valid_severities)}"}), 400

    # Validate category
    valid_categories = {"dns", "ssl", "ports", "headers", "technology", "cve"}
    category = data.get("category")
    if category and category not in valid_categories:
        return jsonify({"error": f"Invalid category. Allowed: {sorted(valid_categories)}"}), 400

    rule = TuningRule(
        organization_id=org_id,
        created_by=user_id,
        enabled=True,
        template_id=data.get("templateId", "").strip()[:100] or None,
        category=category,
        severity_match=severity_match,
        asset_id=asset_id,
        group_id=group_id,
        asset_pattern=data.get("assetPattern", "").strip()[:255] or None,
        port=int(data["port"]) if data.get("port") else None,
        service_name=data.get("serviceName", "").strip()[:100] or None,
        cwe=data.get("cwe", "").strip()[:20] or None,
        title_contains=data.get("titleContains", "").strip()[:255] or None,
        action=action,
        target_severity=target_severity,
        snooze_until=snooze_until,
        reason=data.get("reason", "").strip()[:500] or None,
        dedupe_key=dedupe_key,
    )

    db.session.add(rule)
    db.session.commit()

    log_audit(
        organization_id=org_id,
        user_id=user_id,
        action="monitor.tuning_rule_created",
        category="monitor",
        target_type="tuning_rule",
        target_id=str(rule.id),
        description=f"Created tuning rule: {action}" + (f" (reason: {rule.reason})" if rule.reason else ""),
        metadata={"action": action, "category": category, "severity_match": severity_match, "reason": rule.reason},
    )

    logger.info("Tuning rule created: id=%s org=%s action=%s", rule.id, org_id, action)
    return jsonify(_tuning_rule_to_ui(rule)), 201


# PATCH /monitors/tuning/<id> — analyst+ (edit_tuning_rules permission, plan-gated)
@monitoring_bp.patch("/tuning/<int:rule_id>")
@require_auth
@require_feature("monitoring")
@require_permission("edit_tuning_rules")
def update_tuning_rule(rule_id: int):
    org_id = current_organization_id()
    rule = TuningRule.query.filter_by(id=rule_id, organization_id=org_id).first()
    if not rule:
        return jsonify({"error": "Tuning rule not found."}), 404

    data = request.get_json(silent=True) or {}
    changes = {}

    if "enabled" in data:
        old_enabled = rule.enabled
        rule.enabled = bool(data["enabled"])
        if old_enabled != rule.enabled:
            changes["enabled"] = {"old": old_enabled, "new": rule.enabled}

    rule.updated_at = _now()
    db.session.commit()

    if changes:
        log_audit(
            organization_id=org_id,
            user_id=current_user_id(),
            action="monitor.tuning_rule_updated",
            category="monitor",
            target_type="tuning_rule",
            target_id=str(rule.id),
            description=f"{'Enabled' if rule.enabled else 'Disabled'} tuning rule {rule.id}",
            metadata={"changes": changes},
        )

    return jsonify(_tuning_rule_to_ui(rule))


# DELETE /monitors/tuning/<id> — analyst+ (plan-gated)
@monitoring_bp.delete("/tuning/<int:rule_id>")
@require_auth
@require_feature("monitoring")
@require_role("analyst")
def delete_tuning_rule(rule_id: int):
    org_id = current_organization_id()
    rule = TuningRule.query.filter_by(id=rule_id, organization_id=org_id).first()
    if not rule:
        return jsonify({"error": "Tuning rule not found."}), 404

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="monitor.tuning_rule_deleted",
        category="monitor",
        target_type="tuning_rule",
        target_id=str(rule_id),
        description=f"Deleted tuning rule {rule_id} (action: {rule.action})",
        metadata={"action": rule.action, "reason": rule.reason},
    )

    db.session.delete(rule)
    db.session.commit()

    logger.info("Tuning rule deleted: id=%s org=%s", rule_id, org_id)
    return jsonify({"ok": True})


# ===========================================================================
# DASHBOARD SUMMARY
# ===========================================================================

# GET /monitors/dashboard-summary — all roles can view (plan-gated)
@monitoring_bp.get("/dashboard-summary")
@require_auth
@require_feature("monitoring")
def dashboard_summary():
    """Returns monitoring stats for the main dashboard."""
    org_id = current_organization_id()

    total_monitors = Monitor.query.filter_by(organization_id=org_id).count()
    active_monitors = Monitor.query.filter_by(organization_id=org_id, enabled=True).count()
    open_alerts = MonitorAlert.query.filter_by(organization_id=org_id, status="open").count()

    # Count monitored assets (direct + via groups)
    direct_asset_ids = db.session.query(Monitor.asset_id).filter(
        Monitor.organization_id == org_id,
        Monitor.asset_id.isnot(None),
    ).all()

    group_ids = db.session.query(Monitor.group_id).filter(
        Monitor.organization_id == org_id,
        Monitor.group_id.isnot(None),
    ).all()

    group_asset_count = 0
    if group_ids:
        gids = [g[0] for g in group_ids]
        group_asset_count = Asset.query.filter(Asset.group_id.in_(gids)).count()

    monitored = len(direct_asset_ids) + group_asset_count

    return jsonify({
        "totalMonitors": total_monitors,
        "activeMonitors": active_monitors,
        "openAlerts": open_alerts,
        "monitored": monitored,
    })