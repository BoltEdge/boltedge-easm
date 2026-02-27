# =============================================================================
# File: app/audit/routes.py
# Description: Audit log helper + API endpoints.
#
# Helper:
#   log_audit(...) — call from any route to record an action
#
# Endpoints:
#   GET /audit-log         — admin+ can view
#   GET /audit-log/export  — admin+ can export as CSV
#
# Categories & Actions:
#   finding:  finding.status_changed, finding.bulk_status_changed
#   asset:    asset.created, asset.updated, asset.deleted, asset.bulk_added, asset.bulk_deleted
#   group:    group.created, group.updated, group.deleted
#   scan:     scan.started, scan.completed, scan.failed, scan.deleted
#   user:     user.invited, user.role_changed, user.removed
#   settings: settings.updated, integration.created, integration.deleted,
#             api_key.created, api_key.deleted
#   auth:     auth.login, auth.logout, auth.register
#   export:   export.findings, export.report
# =============================================================================

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, Response

from app.extensions import db
from app.models import AuditLog
from app.auth.decorators import require_auth, current_user_id, current_organization_id
from app.auth.permissions import require_role

logger = logging.getLogger(__name__)

audit_bp = Blueprint("audit", __name__, url_prefix="/audit-log")


# ---------------------------------------------------------------------------
# Helper — call this from any route to log an action
# ---------------------------------------------------------------------------

def log_audit(
    *,
    organization_id: int,
    user_id: int | None = None,
    user_email: str | None = None,
    action: str,
    category: str,
    target_type: str | None = None,
    target_id: str | int | None = None,
    target_label: str | None = None,
    description: str | None = None,
    metadata: dict | None = None,
    ip_address: str | None = None,
):
    """
    Record an audit log entry. Safe to call from anywhere — catches and logs
    any errors without raising.

    Usage:
        from app.audit.routes import log_audit

        log_audit(
            organization_id=org_id,
            user_id=uid,
            action="finding.resolved",
            category="finding",
            target_type="finding",
            target_id=str(f.id),
            target_label=f.title,
            description=f"Resolved finding '{f.title}' on {asset.value}",
            metadata={"old_status": "open", "new_status": "resolved", "notes": notes},
        )
    """
    try:
        # Try to get IP from request context if not provided
        if ip_address is None:
            try:
                ip_address = request.remote_addr
            except RuntimeError:
                ip_address = None

        # Auto-resolve user email from user_id if not provided
        if not user_email and user_id:
            from app.models import User
            user = User.query.get(user_id)
            if user:
                user_email = user.email

        entry = AuditLog(
            organization_id=organization_id,
            user_id=user_id,
            user_email=user_email,
            action=action,
            category=category,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            target_label=(str(target_label)[:500]) if target_label else None,
            description=(str(description)[:2000]) if description else None,
            metadata_json=metadata,
            ip_address=ip_address,
        )
        db.session.add(entry)
        # Don't commit here — let the caller's commit handle it.
        # If the caller doesn't commit, flush to ensure it's in the transaction.
        db.session.flush()

    except Exception as e:
        logger.warning(f"Failed to write audit log: {e}")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@audit_bp.get("")
@require_auth
@require_role("admin")
def list_audit_log():
    """
    List audit log entries with filters and pagination.
    Admin+ only.
    """
    org_id = current_organization_id()

    # Query params
    category = request.args.get("category")         # finding, asset, scan, etc.
    action = request.args.get("action")              # finding.resolved, etc.
    user_id = request.args.get("user_id", type=int)
    target_type = request.args.get("target_type")
    target_id = request.args.get("target_id")
    search = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)

    query = AuditLog.query.filter_by(organization_id=org_id)

    if category:
        query = query.filter(AuditLog.category == category)
    if action:
        query = query.filter(AuditLog.action == action)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if target_type:
        query = query.filter(AuditLog.target_type == target_type)
    if target_id:
        query = query.filter(AuditLog.target_id == target_id)
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            db.or_(
                AuditLog.description.ilike(pattern),
                AuditLog.target_label.ilike(pattern),
                AuditLog.action.ilike(pattern),
            )
        )

    total = query.count()
    rows = query.order_by(AuditLog.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

    # Category counts for filter badges
    category_counts = {}
    cat_rows = (
        db.session.query(AuditLog.category, db.func.count(AuditLog.id))
        .filter_by(organization_id=org_id)
        .group_by(AuditLog.category)
        .all()
    )
    for cat, count in cat_rows:
        category_counts[cat] = count

    return jsonify(
        entries=[_entry_to_ui(e) for e in rows],
        total=total,
        page=page,
        perPage=per_page,
        categoryCounts=category_counts,
    ), 200


@audit_bp.get("/export")
@require_auth
@require_role("admin")
def export_audit_log():
    """Export audit log as CSV. Admin+ only."""
    org_id = current_organization_id()

    category = request.args.get("category")
    search = request.args.get("q", "").strip()

    query = AuditLog.query.filter_by(organization_id=org_id)

    if category:
        query = query.filter(AuditLog.category == category)
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            db.or_(
                AuditLog.description.ilike(pattern),
                AuditLog.target_label.ilike(pattern),
            )
        )

    rows = query.order_by(AuditLog.created_at.desc()).limit(5000).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Timestamp", "User", "Action", "Category",
        "Target Type", "Target ID", "Target Label",
        "Description", "IP Address",
    ])

    for e in rows:
        writer.writerow([
            e.created_at.isoformat() if e.created_at else "",
            e.user_email or str(e.user_id or "system"),
            e.action or "",
            e.category or "",
            e.target_type or "",
            e.target_id or "",
            e.target_label or "",
            e.description or "",
            e.ip_address or "",
        ])

    csv_data = output.getvalue()
    output.close()

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=audit-log-{datetime.now().strftime('%Y%m%d')}.csv"},
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def _entry_to_ui(e: AuditLog) -> dict:
    return {
        "id": str(e.id),
        "userId": str(e.user_id) if e.user_id else None,
        "userEmail": e.user_email,
        "action": e.action,
        "category": e.category,
        "targetType": e.target_type,
        "targetId": e.target_id,
        "targetLabel": e.target_label,
        "description": e.description,
        "metadata": e.metadata_json,
        "ipAddress": e.ip_address,
        "createdAt": e.created_at.isoformat() if e.created_at else None,
    }