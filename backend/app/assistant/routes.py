# =============================================================================
# File: app/assistant/routes.py
# Description: Nano EASM Security AI Assistant (NESAA) — Phase 1 endpoints.
#
# Phase 1 is template-based, tenant-scoped, read-only. No external AI
# providers are called. See app/assistant/__init__.py for the rationale.
# =============================================================================

from __future__ import annotations

import logging

from flask import Blueprint, request, jsonify

from app.extensions import db
from app.models import Finding, Asset, MonitorAlert
from app.auth.decorators import (
    require_auth, allow_api_key, current_user_id, current_organization_id,
)
from app.audit.routes import log_audit
from app.utils.display_id import resolve_id

from .explainer import explain_finding, explain_unbound, _SAFE_EVIDENCE_KEYS
from .alert_explainer import explain_alert


assistant_bp = Blueprint("assistant", __name__, url_prefix="/assistant")
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# POST /assistant/finding-explainer
# ─────────────────────────────────────────────────────────────────────────────
#
# Returns a structured 5-section explanation for a finding the user owns:
#   summary, technicalExplanation, evidence, remediation, clientSummary
#
# Read-only. Uses the same tenant-scoping pattern as findings/routes.py
# (Finding → Asset.organization_id == current_organization_id).
#
# Accepts both numeric ids and display ids (e.g. "FN0042").
# ─────────────────────────────────────────────────────────────────────────────

@assistant_bp.post("/finding-explainer")
@require_auth
@allow_api_key
def finding_explainer():
    body = request.get_json(silent=True) or {}
    raw = body.get("findingId") or body.get("finding_id")
    if raw is None:
        return jsonify(error="findingId is required.", code="INVALID_FINDING_ID"), 400

    int_id = resolve_id(raw, "FN")
    if int_id is None:
        return jsonify(error="Invalid finding id.", code="INVALID_FINDING_ID"), 400

    org_id = current_organization_id()
    user_id = current_user_id()

    # Tenant-scoped fetch: identical pattern to findings/routes.py update_finding.
    # Joining through Asset.organization_id makes cross-org access impossible
    # — a finding owned by another org returns 404 (not 403, so existence
    # isn't leaked).
    finding = (
        db.session.query(Finding)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Finding.id == int_id, Asset.organization_id == org_id)
        .options(db.joinedload(Finding.asset).joinedload(Asset.group))
        .first()
    )

    if not finding:
        return jsonify(error="Finding not found.", code="NOT_FOUND"), 404

    try:
        explanation = explain_finding(finding)
    except Exception:
        logger.exception("Finding explainer failed for finding id %s", finding.id)
        return jsonify(
            error="Could not generate an explanation for this finding.",
            code="EXPLAINER_ERROR",
        ), 500

    # Audit log: finding id only, no explanation content. The content is
    # derived deterministically from the finding row itself, so logging it
    # would just duplicate state already in the DB.
    log_audit(
        organization_id=org_id,
        user_id=user_id,
        action="assistant.finding_explained",
        category="assistant",
        target_type="finding",
        target_id=str(finding.id),
        target_label=finding.title,
        description=f"Generated AI explanation for finding {finding.public_id or finding.id}",
        metadata={"template_id": finding.template_id},
    )
    db.session.commit()

    return jsonify(
        findingId=finding.public_id or str(finding.id),
        explanation=explanation,
        # Source label so the frontend can show "Powered by..." attribution
        # if you ever want to. For Phase 1 it's our own knowledge base.
        source="nano-easm-knowledge-base",
    ), 200


# ─────────────────────────────────────────────────────────────────────────────
# POST /assistant/alert-explainer
# ─────────────────────────────────────────────────────────────────────────────
#
# Returns the same 5-section explanation shape as /finding-explainer, but
# for a MonitorAlert row. Reuses explain_finding() when the alert is linked
# to a finding (richer content), otherwise synthesises an alert-only
# explanation from the alert's own metadata.
#
# Tenant-scoped via MonitorAlert.organization_id.
# Accepts both numeric ids and display ids (e.g. "AL0042").
# ─────────────────────────────────────────────────────────────────────────────

@assistant_bp.post("/alert-explainer")
@require_auth
@allow_api_key
def alert_explainer():
    body = request.get_json(silent=True) or {}
    raw = body.get("alertId") or body.get("alert_id")
    if raw is None:
        return jsonify(error="alertId is required.", code="INVALID_ALERT_ID"), 400

    int_id = resolve_id(raw, "AL")
    if int_id is None:
        return jsonify(error="Invalid alert id.", code="INVALID_ALERT_ID"), 400

    org_id = current_organization_id()
    user_id = current_user_id()

    # Tenant-scoped fetch — eager-load the linked finding (and its asset)
    # so explain_finding() can run without a second roundtrip when present.
    alert = (
        db.session.query(MonitorAlert)
        .filter(MonitorAlert.id == int_id, MonitorAlert.organization_id == org_id)
        .options(
            db.joinedload(MonitorAlert.finding).joinedload(Finding.asset).joinedload(Asset.group),
        )
        .first()
    )

    if not alert:
        return jsonify(error="Alert not found.", code="NOT_FOUND"), 404

    try:
        explanation = explain_alert(alert)
    except Exception:
        logger.exception("Alert explainer failed for alert id %s", alert.id)
        return jsonify(
            error="Could not generate an explanation for this alert.",
            code="EXPLAINER_ERROR",
        ), 500

    log_audit(
        organization_id=org_id,
        user_id=user_id,
        action="assistant.alert_explained",
        category="assistant",
        target_type="monitor_alert",
        target_id=str(alert.id),
        target_label=alert.title,
        description=f"Generated AI explanation for alert {alert.public_id or alert.id}",
        metadata={
            "alert_type": alert.alert_type,
            "source": alert.source,
            "linked_finding_id": alert.finding_id,
        },
    )
    db.session.commit()

    return jsonify(
        alertId=alert.public_id or str(alert.id),
        explanation=explanation,
        # Tells the UI whether we delegated to the finding explainer — useful
        # if the panel ever wants to show a "Based on linked finding" hint.
        linkedFinding=bool(alert.finding_id),
        source="nano-easm-knowledge-base",
    ), 200


# ─────────────────────────────────────────────────────────────────────────────
# POST /assistant/public-explain
# ─────────────────────────────────────────────────────────────────────────────
#
# Unauthenticated explainer for the public quick-scan card on the landing
# page. The unified quick-scan engine emits a coarse finding taxonomy
# (service_exposure / risky_port / cve) and never persists findings to the
# database, so this route accepts the raw finding shape and renders an
# explanation directly from the FindingTemplate registry.
#
# Threat model is identical to /quick-scan itself: rate-limited per IP via
# QuickScanLog, block-list aware, no auth, no DB writes beyond the abuse
# log. The details_json input is filtered through _SAFE_EVIDENCE_KEYS before
# substitution to keep accidental internal fields out of the response.
# ─────────────────────────────────────────────────────────────────────────────

_PUBLIC_EXPLAIN_RATE_LIMIT = 20  # per IP per hour
_PUBLIC_EXPLAIN_ALLOWED_TYPES = {"service_exposure", "risky_port", "cve"}


@assistant_bp.post("/public-explain")
def public_explain():
    from datetime import datetime, timezone, timedelta

    from app.extensions import db
    from app.models import BlockedIP, QuickScanLog
    from app.quick_scan.routes import _get_ip, _log_scan

    body = request.get_json(silent=True) or {}
    finding_type = (body.get("finding_type") or "").strip().lower()
    asset_value = (body.get("asset_value") or "").strip()
    details = body.get("details_json") or {}

    if finding_type not in _PUBLIC_EXPLAIN_ALLOWED_TYPES:
        return jsonify(
            error="finding_type must be one of: service_exposure, risky_port, cve",
            code="INVALID_TYPE",
        ), 400
    if not isinstance(details, dict):
        return jsonify(
            error="details_json must be an object",
            code="INVALID_DETAILS",
        ), 400

    ip = _get_ip()
    ua = request.headers.get("User-Agent", "")
    target = asset_value[:200] or "-"
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    # Block list check (mirrors /quick-scan)
    block = BlockedIP.query.filter_by(ip_address=ip).first()
    if block and (block.expires_at is None or block.expires_at > now):
        _log_scan(ip=ip, user_agent=ua, target=target, asset_type="-",
                  source="explain", status="blocked")
        return jsonify(
            error="Your IP address has been blocked from using this service.",
            code="IP_BLOCKED",
        ), 403

    # Rate limit (separate bucket from /quick-scan via source="explain")
    window_start = now - timedelta(hours=1)
    recent = QuickScanLog.query.filter(
        QuickScanLog.ip_address == ip,
        QuickScanLog.source == "explain",
        QuickScanLog.created_at >= window_start,
        QuickScanLog.status.notin_(["blocked", "rate_limited"]),
    ).count()
    if recent >= _PUBLIC_EXPLAIN_RATE_LIMIT:
        _log_scan(ip=ip, user_agent=ua, target=target, asset_type="-",
                  source="explain", status="rate_limited")
        return jsonify(
            error=f"Too many explanation requests. You can run up to {_PUBLIC_EXPLAIN_RATE_LIMIT} per hour. Try again later.",
            code="RATE_LIMITED",
        ), 429

    # Whitelist details_json keys before substitution. Anything outside
    # _SAFE_EVIDENCE_KEYS is silently dropped — keeps accidental internal
    # fields out of the user-facing response even if a future caller
    # passes additional keys.
    safe_details = {k: v for k, v in details.items() if k in _SAFE_EVIDENCE_KEYS}

    try:
        explanation = explain_unbound(
            finding_type=finding_type,
            asset_value=asset_value or None,
            details=safe_details,
        )
    except Exception:
        logger.exception("Public explainer failed for type %s", finding_type)
        _log_scan(ip=ip, user_agent=ua, target=target, asset_type="-",
                  source="explain", status="failed")
        return jsonify(
            error="Could not generate an explanation.",
            code="EXPLAINER_ERROR",
        ), 500

    _log_scan(ip=ip, user_agent=ua, target=target, asset_type="-",
              source="explain", status="completed")

    return jsonify(
        findingType=finding_type,
        explanation=explanation,
        source="nano-easm-knowledge-base",
    ), 200
