# =============================================================================
# File: app/integrations/routes.py
# Description: Integration management and notification dispatch.
#   CRUD for integration connections and notification rules.
#   Dispatch engine that sends to Slack, Jira, PagerDuty, Webhook, Email.
#
# Permissions:
#   - GET /integrations: viewer+ (list integrations)
#   - POST /integrations: admin+ (create)
#   - PATCH /integrations/<id>: admin+ (update)
#   - DELETE /integrations/<id>: admin+ (delete)
#   - POST /integrations/<id>/test: admin+ (test connection)
#   - GET /integrations/rules: viewer+ (list rules)
#   - POST /integrations/rules: admin+ (create rule)
#   - PATCH /integrations/rules/<id>: admin+ (update rule)
#   - DELETE /integrations/rules/<id>: admin+ (delete rule)
# =============================================================================

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import requests
from flask import Blueprint, request, jsonify

from app.extensions import db
from app.models import Integration, NotificationRule
from app.auth.decorators import require_auth, current_user_id, current_organization_id
from app.auth.permissions import require_role
from app.audit.routes import log_audit

logger = logging.getLogger(__name__)

integrations_bp = Blueprint("integrations", __name__, url_prefix="/integrations")


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _sid(x):
    return str(x) if x is not None else ""


# ════════════════════════════════════════════════════════════════════
# Serializers
# ════════════════════════════════════════════════════════════════════

# Fields to mask in config when returning to frontend
_SENSITIVE_FIELDS = {"api_token", "secret", "smtp_pass", "routing_key"}


def _safe_config(config: dict) -> dict:
    """Return config with sensitive fields masked."""
    out = {}
    for k, v in (config or {}).items():
        if k in _SENSITIVE_FIELDS and v:
            out[k] = "••••" + str(v)[-4:] if len(str(v)) > 4 else "••••"
        else:
            out[k] = v
    return out


def _integration_to_dict(i: Integration) -> dict:
    return {
        "id": _sid(i.id),
        "type": i.integration_type,
        "name": i.name,
        "config": _safe_config(i.config_json or {}),
        "enabled": bool(i.enabled),
        "lastTestAt": i.last_test_at.isoformat() if i.last_test_at else None,
        "lastTestOk": i.last_test_ok,
        "lastError": i.last_error,
        "createdBy": _sid(i.created_by),
        "createdAt": i.created_at.isoformat() if i.created_at else None,
        "updatedAt": i.updated_at.isoformat() if i.updated_at else None,
    }


def _rule_to_dict(r: NotificationRule) -> dict:
    return {
        "id": _sid(r.id),
        "integrationId": _sid(r.integration_id),
        "integrationName": r.integration.name if r.integration else None,
        "integrationType": r.integration.integration_type if r.integration else None,
        "name": r.name,
        "eventType": r.event_type,
        "filters": r.filters_json or {},
        "actionMode": r.action_mode,
        "actionConfig": r.action_config_json or {},
        "enabled": bool(r.enabled),
        "lastTriggeredAt": r.last_triggered_at.isoformat() if r.last_triggered_at else None,
        "triggerCount": r.trigger_count or 0,
        "createdAt": r.created_at.isoformat() if r.created_at else None,
    }


# ════════════════════════════════════════════════════════════════════
# Integration CRUD
# ════════════════════════════════════════════════════════════════════

VALID_TYPES = {"slack", "jira", "pagerduty", "webhook", "email"}

REQUIRED_CONFIG = {
    "slack": ["webhook_url"],
    "jira": ["base_url", "project_key", "email", "api_token"],
    "pagerduty": ["routing_key"],
    "webhook": ["url"],
    "email": ["recipients"],
}


@integrations_bp.get("")
@require_auth
def list_integrations():
    org_id = current_organization_id()
    rows = (
        Integration.query
        .filter_by(organization_id=org_id)
        .order_by(Integration.created_at.desc())
        .all()
    )
    return jsonify(integrations=[_integration_to_dict(r) for r in rows]), 200


@integrations_bp.post("")
@require_auth
@require_role("admin")
def create_integration():
    org_id = current_organization_id()
    uid = current_user_id()
    body = request.get_json(silent=True) or {}

    itype = (body.get("type") or "").lower().strip()
    name = (body.get("name") or "").strip()
    config = body.get("config") or {}

    if itype not in VALID_TYPES:
        return jsonify(error=f"Invalid type. Must be one of: {', '.join(sorted(VALID_TYPES))}"), 400
    if not name:
        return jsonify(error="name is required"), 400

    # Validate required config fields
    missing = [f for f in REQUIRED_CONFIG.get(itype, []) if not config.get(f)]
    if missing:
        return jsonify(error=f"Missing required config: {', '.join(missing)}"), 400

    i = Integration(
        organization_id=org_id,
        integration_type=itype,
        name=name,
        config_json=config,
        enabled=body.get("enabled", True),
        created_by=uid,
    )
    db.session.add(i)
    db.session.flush()  # get i.id

    log_audit(
        organization_id=org_id,
        user_id=uid,
        action="settings.integration_created",
        category="settings",
        target_type="integration",
        target_id=str(i.id),
        target_label=name,
        description=f"Created {itype} integration '{name}'",
        metadata={"type": itype},
    )

    db.session.commit()

    return jsonify(_integration_to_dict(i)), 201


@integrations_bp.patch("/<int:integration_id>")
@require_auth
@require_role("admin")
def update_integration(integration_id: int):
    org_id = current_organization_id()
    i = Integration.query.filter_by(id=integration_id, organization_id=org_id).first()
    if not i:
        return jsonify(error="integration not found"), 404

    body = request.get_json(silent=True) or {}
    updated_fields = []

    if "name" in body:
        name = (body["name"] or "").strip()
        if not name:
            return jsonify(error="name cannot be empty"), 400
        i.name = name
        updated_fields.append("name")

    if "enabled" in body:
        i.enabled = bool(body["enabled"])
        updated_fields.append("enabled")

    if "config" in body:
        new_config = body["config"] or {}
        # Merge: keep existing sensitive values if masked
        old_config = i.config_json or {}
        for k, v in new_config.items():
            if k in _SENSITIVE_FIELDS and isinstance(v, str) and v.startswith("••••"):
                # Keep old value — user didn't change it
                new_config[k] = old_config.get(k, "")
        i.config_json = new_config
        updated_fields.append("config")

    i.updated_at = _now()

    if updated_fields:
        log_audit(
            organization_id=org_id,
            user_id=current_user_id(),
            action="settings.integration_updated",
            category="settings",
            target_type="integration",
            target_id=str(i.id),
            target_label=i.name,
            description=f"Updated integration '{i.name}'",
            metadata={"fields": updated_fields},
        )

    db.session.commit()

    return jsonify(_integration_to_dict(i)), 200


@integrations_bp.delete("/<int:integration_id>")
@require_auth
@require_role("admin")
def delete_integration(integration_id: int):
    org_id = current_organization_id()
    i = Integration.query.filter_by(id=integration_id, organization_id=org_id).first()
    if not i:
        return jsonify(error="integration not found"), 404

    integration_name = i.name
    integration_type = i.integration_type

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="settings.integration_deleted",
        category="settings",
        target_type="integration",
        target_id=str(integration_id),
        target_label=integration_name,
        description=f"Deleted {integration_type} integration '{integration_name}'",
        metadata={"type": integration_type},
    )

    db.session.delete(i)
    db.session.commit()

    return jsonify(message="deleted", id=_sid(integration_id)), 200


# ════════════════════════════════════════════════════════════════════
# Test Connection
# ════════════════════════════════════════════════════════════════════

@integrations_bp.post("/<int:integration_id>/test")
@require_auth
@require_role("admin")
def test_integration(integration_id: int):
    org_id = current_organization_id()
    i = Integration.query.filter_by(id=integration_id, organization_id=org_id).first()
    if not i:
        return jsonify(error="integration not found"), 404

    test_payload = {
        "event": "test",
        "message": f"Test notification from BoltEdge EASM — integration '{i.name}' is working.",
        "severity": "info",
        "timestamp": _now().isoformat(),
    }

    ok, error = _dispatch_to_integration(i, test_payload)

    i.last_test_at = _now()
    i.last_test_ok = ok
    i.last_error = error if not ok else None

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="settings.integration_tested",
        category="settings",
        target_type="integration",
        target_id=str(i.id),
        target_label=i.name,
        description=f"Tested integration '{i.name}': {'success' if ok else 'failed'}",
        metadata={"success": ok, "error": error},
    )

    db.session.commit()

    if ok:
        return jsonify(success=True, message="Test notification sent successfully"), 200
    else:
        return jsonify(success=False, error=error or "Unknown error"), 422


# ════════════════════════════════════════════════════════════════════
# Notification Rules CRUD
# ════════════════════════════════════════════════════════════════════

VALID_EVENTS = {
    "finding.critical", "finding.high", "finding.medium", "finding.any",
    "scan.completed", "scan.failed",
    "exposure.threshold",
    "monitor.alert",
}

VALID_ACTION_MODES = {"notify", "create_ticket"}


@integrations_bp.get("/rules")
@require_auth
def list_rules():
    org_id = current_organization_id()
    rows = (
        NotificationRule.query
        .filter_by(organization_id=org_id)
        .order_by(NotificationRule.created_at.desc())
        .all()
    )
    return jsonify(rules=[_rule_to_dict(r) for r in rows]), 200


@integrations_bp.post("/rules")
@require_auth
@require_role("admin")
def create_rule():
    org_id = current_organization_id()
    uid = current_user_id()
    body = request.get_json(silent=True) or {}

    integration_id = body.get("integrationId")
    name = (body.get("name") or "").strip()
    event_type = (body.get("eventType") or "").strip()
    action_mode = (body.get("actionMode") or "notify").strip()

    if not name:
        return jsonify(error="name is required"), 400
    if event_type not in VALID_EVENTS:
        return jsonify(error=f"Invalid event type. Must be one of: {', '.join(sorted(VALID_EVENTS))}"), 400
    if action_mode not in VALID_ACTION_MODES:
        return jsonify(error=f"Invalid action mode. Must be: {', '.join(VALID_ACTION_MODES)}"), 400

    # Validate integration exists and belongs to org
    integration = Integration.query.filter_by(id=int(integration_id), organization_id=org_id).first()
    if not integration:
        return jsonify(error="integration not found"), 404

    # create_ticket only valid for Jira
    if action_mode == "create_ticket" and integration.integration_type != "jira":
        return jsonify(error="create_ticket action is only available for Jira integrations"), 400

    rule = NotificationRule(
        organization_id=org_id,
        integration_id=integration.id,
        name=name,
        event_type=event_type,
        filters_json=body.get("filters") or {},
        action_mode=action_mode,
        action_config_json=body.get("actionConfig") or {},
        enabled=body.get("enabled", True),
    )
    db.session.add(rule)
    db.session.flush()  # get rule.id

    log_audit(
        organization_id=org_id,
        user_id=uid,
        action="settings.notification_rule_created",
        category="settings",
        target_type="notification_rule",
        target_id=str(rule.id),
        target_label=name,
        description=f"Created notification rule '{name}' for {integration.name}",
        metadata={"event_type": event_type, "action_mode": action_mode, "integration": integration.name},
    )

    db.session.commit()

    return jsonify(_rule_to_dict(rule)), 201


@integrations_bp.patch("/rules/<int:rule_id>")
@require_auth
@require_role("admin")
def update_rule(rule_id: int):
    org_id = current_organization_id()
    rule = NotificationRule.query.filter_by(id=rule_id, organization_id=org_id).first()
    if not rule:
        return jsonify(error="rule not found"), 404

    body = request.get_json(silent=True) or {}
    updated_fields = []

    if "name" in body:
        n = (body["name"] or "").strip()
        if not n:
            return jsonify(error="name cannot be empty"), 400
        rule.name = n
        updated_fields.append("name")

    if "eventType" in body:
        et = body["eventType"]
        if et not in VALID_EVENTS:
            return jsonify(error=f"Invalid event type"), 400
        rule.event_type = et
        updated_fields.append("eventType")

    if "enabled" in body:
        rule.enabled = bool(body["enabled"])
        updated_fields.append("enabled")

    if "filters" in body:
        rule.filters_json = body["filters"] or {}
        updated_fields.append("filters")

    if "actionMode" in body:
        am = body["actionMode"]
        if am not in VALID_ACTION_MODES:
            return jsonify(error="Invalid action mode"), 400
        rule.action_mode = am
        updated_fields.append("actionMode")

    if "actionConfig" in body:
        rule.action_config_json = body["actionConfig"] or {}
        updated_fields.append("actionConfig")

    if "integrationId" in body:
        iid = body["integrationId"]
        integration = Integration.query.filter_by(id=int(iid), organization_id=org_id).first()
        if not integration:
            return jsonify(error="integration not found"), 404
        rule.integration_id = integration.id
        updated_fields.append("integrationId")

    rule.updated_at = _now()

    if updated_fields:
        log_audit(
            organization_id=org_id,
            user_id=current_user_id(),
            action="settings.notification_rule_updated",
            category="settings",
            target_type="notification_rule",
            target_id=str(rule.id),
            target_label=rule.name,
            description=f"Updated notification rule '{rule.name}'",
            metadata={"fields": updated_fields},
        )

    db.session.commit()

    return jsonify(_rule_to_dict(rule)), 200


@integrations_bp.delete("/rules/<int:rule_id>")
@require_auth
@require_role("admin")
def delete_rule(rule_id: int):
    org_id = current_organization_id()
    rule = NotificationRule.query.filter_by(id=rule_id, organization_id=org_id).first()
    if not rule:
        return jsonify(error="rule not found"), 404

    rule_name = rule.name

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="settings.notification_rule_deleted",
        category="settings",
        target_type="notification_rule",
        target_id=str(rule_id),
        target_label=rule_name,
        description=f"Deleted notification rule '{rule_name}'",
    )

    db.session.delete(rule)
    db.session.commit()

    return jsonify(message="deleted", id=_sid(rule_id)), 200


# ════════════════════════════════════════════════════════════════════
# Dispatch Engine
# ════════════════════════════════════════════════════════════════════

def dispatch_event(org_id: int, event_type: str, payload: dict):
    """
    Called from other parts of the app when an event occurs.
    Finds all matching enabled rules and dispatches to their integrations.

    Usage:
        from app.integrations.routes import dispatch_event
        dispatch_event(org_id, "finding.critical", {
            "finding_id": "123",
            "title": "Critical SQL Injection",
            "severity": "critical",
            "asset": "api.example.com",
            "group": "Production",
        })
    """
    rules = (
        NotificationRule.query
        .join(Integration)
        .filter(
            NotificationRule.organization_id == org_id,
            NotificationRule.event_type == event_type,
            NotificationRule.enabled.is_(True),
            Integration.enabled.is_(True),
        )
        .all()
    )

    # Also match wildcard rules (e.g. finding.any matches finding.critical)
    if event_type.startswith("finding.") and event_type != "finding.any":
        wildcard_rules = (
            NotificationRule.query
            .join(Integration)
            .filter(
                NotificationRule.organization_id == org_id,
                NotificationRule.event_type == "finding.any",
                NotificationRule.enabled.is_(True),
                Integration.enabled.is_(True),
            )
            .all()
        )
        rules.extend(wildcard_rules)

    for rule in rules:
        # Check filters
        if not _matches_filters(rule, payload):
            continue

        try:
            integration = rule.integration
            dispatch_payload = _build_dispatch_payload(rule, payload)

            if rule.action_mode == "create_ticket" and integration.integration_type == "jira":
                ok, error = _create_jira_ticket(integration, rule, payload)
            else:
                ok, error = _dispatch_to_integration(integration, dispatch_payload)

            # Update stats
            rule.last_triggered_at = _now()
            rule.trigger_count = (rule.trigger_count or 0) + 1

            if not ok:
                logger.warning(f"Dispatch failed for rule {rule.id} -> integration {integration.id}: {error}")
                integration.last_error = error

        except Exception as e:
            logger.exception(f"Error dispatching rule {rule.id}: {e}")

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()


def _matches_filters(rule: NotificationRule, payload: dict) -> bool:
    """Check if the payload matches the rule's filters."""
    filters = rule.filters_json or {}

    # Group filter
    group_ids = filters.get("group_ids")
    if group_ids and payload.get("group_id"):
        if str(payload["group_id"]) not in [str(g) for g in group_ids]:
            return False

    # Min severity filter
    min_sev = filters.get("min_severity")
    if min_sev:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        payload_sev = sev_order.get((payload.get("severity") or "info").lower(), 4)
        min_sev_val = sev_order.get(min_sev.lower(), 4)
        if payload_sev > min_sev_val:
            return False

    # Exposure threshold filter
    threshold = filters.get("threshold")
    if threshold and rule.event_type == "exposure.threshold":
        score = payload.get("exposure_score", 0)
        if score < threshold:
            return False

    return True


def _build_dispatch_payload(rule: NotificationRule, payload: dict) -> dict:
    """Build a standardized payload for dispatch."""
    return {
        "event": rule.event_type,
        "rule_name": rule.name,
        "timestamp": _now().isoformat(),
        **payload,
    }


# ────────────────────────────────────────────────────────────────
# Slack
# ────────────────────────────────────────────────────────────────

def _send_slack(config: dict, payload: dict) -> tuple[bool, str | None]:
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return False, "No webhook_url configured"

    event = payload.get("event", "notification")
    severity = payload.get("severity", "info")
    title = payload.get("title") or payload.get("message") or "BoltEdge EASM Notification"

    # Color based on severity
    color_map = {
        "critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
        "low": "#3b82f6", "info": "#94a3b8",
    }
    color = color_map.get(severity, "#14b8a6")

    # Build Slack blocks
    blocks = {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*{title}*"
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"Event: `{event}` | Severity: `{severity}`"},
                    ]
                },
            ]
        }]
    }

    # Add details fields
    fields = []
    if payload.get("asset"):
        fields.append({"type": "mrkdwn", "text": f"*Asset:* {payload['asset']}"})
    if payload.get("group"):
        fields.append({"type": "mrkdwn", "text": f"*Group:* {payload['group']}"})
    if payload.get("description"):
        fields.append({"type": "mrkdwn", "text": f"*Details:* {payload['description'][:200]}"})

    if fields:
        blocks["attachments"][0]["blocks"].append({
            "type": "section",
            "fields": fields[:10],
        })

    try:
        resp = requests.post(webhook_url, json=blocks, timeout=10)
        if resp.status_code == 200:
            return True, None
        return False, f"Slack returned {resp.status_code}: {resp.text[:200]}"
    except requests.RequestException as e:
        return False, f"Slack request failed: {str(e)[:200]}"


# ────────────────────────────────────────────────────────────────
# PagerDuty (Events API v2)
# ────────────────────────────────────────────────────────────────

def _send_pagerduty(config: dict, payload: dict) -> tuple[bool, str | None]:
    routing_key = config.get("routing_key", "")
    if not routing_key:
        return False, "No routing_key configured"

    severity = payload.get("severity", "info")
    pd_severity_map = {
        "critical": "critical", "high": "error", "medium": "warning",
        "low": "info", "info": "info",
    }

    title = payload.get("title") or payload.get("message") or "BoltEdge EASM Alert"

    pd_payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": title[:1024],
            "source": "BoltEdge EASM",
            "severity": pd_severity_map.get(severity, "info"),
            "component": payload.get("asset"),
            "group": payload.get("group"),
            "custom_details": {
                k: v for k, v in payload.items()
                if k not in ("routing_key",) and isinstance(v, (str, int, float, bool))
            },
        },
    }

    try:
        resp = requests.post(
            "https://events.pagerduty.com/v2/enqueue",
            json=pd_payload,
            timeout=10,
        )
        if resp.status_code in (200, 201, 202):
            return True, None
        return False, f"PagerDuty returned {resp.status_code}: {resp.text[:200]}"
    except requests.RequestException as e:
        return False, f"PagerDuty request failed: {str(e)[:200]}"


# ────────────────────────────────────────────────────────────────
# Webhook (generic)
# ────────────────────────────────────────────────────────────────

def _send_webhook(config: dict, payload: dict) -> tuple[bool, str | None]:
    url = config.get("url", "")
    if not url:
        return False, "No URL configured"

    method = (config.get("method") or "POST").upper()
    secret = config.get("secret", "")

    body = json.dumps(payload, default=str)
    headers = {"Content-Type": "application/json"}

    # HMAC signature if secret is set
    if secret:
        sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        headers["X-BoltEdge-Signature"] = f"sha256={sig}"

    try:
        resp = requests.request(method, url, data=body, headers=headers, timeout=15)
        if 200 <= resp.status_code < 300:
            return True, None
        return False, f"Webhook returned {resp.status_code}: {resp.text[:200]}"
    except requests.RequestException as e:
        return False, f"Webhook request failed: {str(e)[:200]}"


# ────────────────────────────────────────────────────────────────
# Email (SMTP)
# ────────────────────────────────────────────────────────────────

def _send_email(config: dict, payload: dict) -> tuple[bool, str | None]:
    recipients = config.get("recipients", "")
    if not recipients:
        return False, "No recipients configured"

    to_list = [r.strip() for r in recipients.split(",") if r.strip()]
    if not to_list:
        return False, "No valid recipients"

    from_email = config.get("from_email") or "noreply@boltedge.co"

    event = payload.get("event", "notification")
    severity = payload.get("severity", "info")
    title = payload.get("title") or payload.get("message") or "BoltEdge EASM Notification"

    subject = f"[BoltEdge EASM] [{severity.upper()}] {title[:100]}"

    # Build HTML body
    html = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: #0f1729; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
            <h2 style="margin: 0; font-size: 18px;">BoltEdge EASM Alert</h2>
            <p style="margin: 5px 0 0; opacity: 0.7; font-size: 13px;">Event: {event}</p>
        </div>
        <div style="background: #1a2332; color: #e2e8f0; padding: 20px; border-radius: 0 0 8px 8px; border: 1px solid #2d3748; border-top: none;">
            <h3 style="margin: 0 0 10px; color: white;">{title}</h3>
            <table style="width: 100%; font-size: 14px; border-collapse: collapse;">
    """

    detail_fields = [
        ("Severity", severity.upper()),
        ("Asset", payload.get("asset")),
        ("Group", payload.get("group")),
        ("Description", payload.get("description")),
        ("Timestamp", payload.get("timestamp")),
    ]
    for label, value in detail_fields:
        if value:
            html += f"""
                <tr>
                    <td style="padding: 6px 0; color: #94a3b8; width: 100px;">{label}</td>
                    <td style="padding: 6px 0;">{str(value)[:300]}</td>
                </tr>
            """

    html += """
            </table>
        </div>
        <p style="text-align: center; font-size: 11px; color: #64748b; margin-top: 15px;">
            Sent by BoltEdge EASM
        </p>
    </div>
    """

    try:
        import sendgrid
        from sendgrid.helpers.mail import Mail, Email, To, Content

        sg = sendgrid.SendGridAPIClient(api_key=app_config.SENDGRID_API_KEY)
        message = Mail(
            from_email=Email(from_email),
            to_emails=[To(r) for r in to_list],
            subject=subject,
            html_content=Content("text/html", html),
        )
        response = sg.send(message)

        if response.status_code in (200, 201, 202):
            return True, None
        return False, f"SendGrid returned {response.status_code}"
    except ImportError:
        return False, "SendGrid not installed (pip install sendgrid)"
    except Exception as e:
        return False, f"Email send failed: {str(e)[:200]}"


# ────────────────────────────────────────────────────────────────
# Jira (REST API v3)
# ────────────────────────────────────────────────────────────────

def _send_jira_notification(config: dict, payload: dict) -> tuple[bool, str | None]:
    """Send a comment or webhook-style notification to Jira (via webhook or just validate connection)."""
    base_url = config.get("base_url", "").rstrip("/")
    email = config.get("email", "")
    api_token = config.get("api_token", "")

    if not all([base_url, email, api_token]):
        return False, "Incomplete Jira configuration"

    # For notify mode, we validate the connection by fetching project info
    project_key = config.get("project_key", "")
    try:
        resp = requests.get(
            f"{base_url}/rest/api/3/project/{project_key}",
            auth=(email, api_token),
            timeout=10,
        )
        if resp.status_code == 200:
            return True, None
        return False, f"Jira returned {resp.status_code}: {resp.text[:200]}"
    except requests.RequestException as e:
        return False, f"Jira request failed: {str(e)[:200]}"


def _create_jira_ticket(integration: Integration, rule: NotificationRule, payload: dict) -> tuple[bool, str | None]:
    """Create a Jira issue from a finding."""
    config = integration.config_json or {}
    action_config = rule.action_config_json or {}

    base_url = config.get("base_url", "").rstrip("/")
    email = config.get("email", "")
    api_token = config.get("api_token", "")
    project_key = config.get("project_key", "")

    if not all([base_url, email, api_token, project_key]):
        return False, "Incomplete Jira configuration"

    # Map severity to Jira priority
    severity = payload.get("severity", "info")
    priority_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"}
    priority = action_config.get("priority") or priority_map.get(severity, "Medium")

    issue_type = action_config.get("issue_type") or "Bug"
    labels = action_config.get("labels") or ["security", "BoltEdge EASM"]
    if isinstance(labels, str):
        labels = [l.strip() for l in labels.split(",") if l.strip()]

    title = payload.get("title") or "BoltEdge EASM Finding"
    description = payload.get("description") or ""
    asset = payload.get("asset") or ""
    group = payload.get("group") or ""

    # Build Jira description in ADF (Atlassian Document Format)
    adf_content = [
        {
            "type": "paragraph",
            "content": [{"type": "text", "text": description[:2000] if description else "No description provided."}]
        },
        {
            "type": "table",
            "attrs": {"layout": "default"},
            "content": []
        }
    ]

    # Add detail rows to table
    detail_rows = [
        ("Severity", severity.upper()),
        ("Asset", asset),
        ("Group", group),
        ("Source", "BoltEdge EASM"),
    ]
    for label, value in detail_rows:
        if value:
            adf_content[1]["content"].append({
                "type": "tableRow",
                "content": [
                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": label, "marks": [{"type": "strong"}]}]}]},
                    {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": str(value)}]}]},
                ]
            })

    # Remove empty table if no rows
    if not adf_content[1]["content"]:
        adf_content.pop(1)

    issue_data = {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[BoltEdge EASM] {title[:250]}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": adf_content,
            },
            "issuetype": {"name": issue_type},
            "priority": {"name": priority},
            "labels": labels,
        }
    }

    # Optional assignee
    assignee = action_config.get("assignee")
    if assignee:
        issue_data["fields"]["assignee"] = {"accountId": assignee}

    try:
        resp = requests.post(
            f"{base_url}/rest/api/3/issue",
            json=issue_data,
            auth=(email, api_token),
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        if resp.status_code in (200, 201):
            issue = resp.json()
            issue_key = issue.get("key", "")
            logger.info(f"Created Jira issue {issue_key} for rule {rule.id}")
            return True, None
        return False, f"Jira returned {resp.status_code}: {resp.text[:300]}"
    except requests.RequestException as e:
        return False, f"Jira request failed: {str(e)[:200]}"


# ────────────────────────────────────────────────────────────────
# Dispatcher Router
# ────────────────────────────────────────────────────────────────

def _dispatch_to_integration(integration: Integration, payload: dict) -> tuple[bool, str | None]:
    """Route a payload to the correct integration sender."""
    itype = integration.integration_type
    config = integration.config_json or {}

    if itype == "slack":
        return _send_slack(config, payload)
    elif itype == "jira":
        return _send_jira_notification(config, payload)
    elif itype == "pagerduty":
        return _send_pagerduty(config, payload)
    elif itype == "webhook":
        return _send_webhook(config, payload)
    elif itype == "email":
        return _send_email(config, payload)
    else:
        return False, f"Unknown integration type: {itype}"