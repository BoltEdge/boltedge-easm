# =============================================================================
# File: app/findings/routes.py
# Description: Findings routes for listing, viewing, status transitions,
#   bulk actions, and exporting security findings.
#   Logs FindingEvents for historical trending and MTTR calculation.
#
# F2 Update: Full status workflow
#   Status derivation (priority order — highest wins):
#     1. resolved == True       → "resolved"
#     2. accepted_risk == True  → "accepted_risk"
#     3. ignored == True        → "suppressed"
#     4. in_progress == True    → "in_progress"
#     5. otherwise              → "open"
#
#   Only "open" findings count toward exposure score and severity metrics.
#
# Permissions:
#   - GET /findings: all roles can view
#   - GET /findings/<id>: all roles can view
#   - PATCH /findings/<id>: analyst+ (status transitions)
#   - POST /findings/bulk-ignore: analyst+ (bulk suppress/unsuppress)
#   - POST /findings/bulk-resolve: analyst+ (bulk resolve/reopen)
#   - POST /findings/bulk-status: analyst+ (bulk set any status)
#   - GET /findings/export: admin+ (export_scan_results permission)
# =============================================================================

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, Response
from sqlalchemy import or_, and_, func, case
from app.extensions import db
from app.models import Finding, Asset, AssetGroup
from app.auth.decorators import require_auth, current_user_id, current_organization_id
from app.auth.permissions import require_role, require_permission
from app.audit.routes import log_audit

# Finding event logging for historical trending
try:
    from app.trending.routes import log_finding_event
except ImportError:
    def log_finding_event(**kwargs):
        pass

# Template registry for summary lookups
try:
    from app.scanner.templates import get_template as _get_template
except ImportError:
    _get_template = None

findings_bp = Blueprint("findings", __name__, url_prefix="/findings")


def _sid(x) -> str:
    return str(x) if x is not None else ""


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _lookup_summary(template_id: str) -> str | None:
    """Look up the human-readable summary from the template registry."""
    if not _get_template or not template_id:
        return None
    tmpl = _get_template(template_id)
    return tmpl.summary if tmpl else None


def _derive_status(f: Finding) -> str:
    """
    Derive display status from boolean flags.
    Priority order (highest wins):
      1. resolved       → "resolved"
      2. accepted_risk  → "accepted_risk"
      3. ignored        → "suppressed"
      4. in_progress    → "in_progress"
      5. otherwise      → "open"
    """
    if getattr(f, "resolved", False):
        return "resolved"
    if getattr(f, "accepted_risk", False):
        return "accepted_risk"
    if f.ignored:
        return "suppressed"
    if getattr(f, "in_progress", False):
        return "in_progress"
    return "open"


def _is_open_filter():
    """Filter for pure 'open' findings — the only status counting toward risk."""
    return and_(
        or_(Finding.ignored == False, Finding.ignored == None),
        or_(Finding.resolved == False, Finding.resolved == None),
        or_(Finding.in_progress == False, Finding.in_progress == None),
        or_(Finding.accepted_risk == False, Finding.accepted_risk == None),
    )


def _clear_all_status_flags(f: Finding):
    """Reset all status booleans and their metadata to False/None."""
    f.ignored = False
    f.ignored_at = None
    f.ignored_by = None
    f.ignored_reason = None

    f.resolved = False
    f.resolved_at = None
    f.resolved_by = None
    f.resolved_reason = None

    f.in_progress = False
    f.in_progress_at = None
    f.in_progress_by = None
    f.in_progress_notes = None

    f.accepted_risk = False
    f.accepted_risk_at = None
    f.accepted_risk_by = None
    f.accepted_risk_justification = None


def _set_status(f: Finding, new_status: str, uid: int, notes: str | None = None, org_id: int | None = None):
    """
    Transition a finding to a new status. Clears all flags first, then sets the target.
    Logs a FindingEvent for the transition.
    """
    old_status = _derive_status(f)
    now = _now()

    if old_status == new_status:
        return  # No-op

    _clear_all_status_flags(f)

    if new_status == "resolved":
        f.resolved = True
        f.resolved_at = now
        f.resolved_by = uid
        f.resolved_reason = notes

    elif new_status == "accepted_risk":
        f.accepted_risk = True
        f.accepted_risk_at = now
        f.accepted_risk_by = uid
        f.accepted_risk_justification = notes

    elif new_status == "suppressed":
        f.ignored = True
        f.ignored_at = now
        f.ignored_by = uid
        f.ignored_reason = notes

    elif new_status == "in_progress":
        f.in_progress = True
        f.in_progress_at = now
        f.in_progress_by = uid
        f.in_progress_notes = notes

    elif new_status == "open":
        pass  # All flags already cleared

    # Log finding event
    log_finding_event(
        finding_id=f.id,
        organization_id=org_id or 0,
        event_type=new_status if new_status != "open" else "reopened",
        old_value=old_status,
        new_value=new_status,
        user_id=uid,
        notes=notes,
    )


def _status_count_cases():
    """SQLAlchemy case expressions for counting findings by derived status."""
    return {
        "open": func.sum(case(
            (and_(
                or_(Finding.resolved == False, Finding.resolved == None),
                or_(Finding.accepted_risk == False, Finding.accepted_risk == None),
                or_(Finding.ignored == False, Finding.ignored == None),
                or_(Finding.in_progress == False, Finding.in_progress == None),
            ), 1),
            else_=0,
        )),
        "in_progress": func.sum(case(
            (and_(
                or_(Finding.resolved == False, Finding.resolved == None),
                or_(Finding.accepted_risk == False, Finding.accepted_risk == None),
                or_(Finding.ignored == False, Finding.ignored == None),
                Finding.in_progress == True,
            ), 1),
            else_=0,
        )),
        "accepted_risk": func.sum(case(
            (and_(
                or_(Finding.resolved == False, Finding.resolved == None),
                Finding.accepted_risk == True,
            ), 1),
            else_=0,
        )),
        "suppressed": func.sum(case(
            (and_(
                or_(Finding.resolved == False, Finding.resolved == None),
                or_(Finding.accepted_risk == False, Finding.accepted_risk == None),
                Finding.ignored == True,
            ), 1),
            else_=0,
        )),
        "resolved": func.sum(case(
            (Finding.resolved == True, 1),
            else_=0,
        )),
    }


def finding_to_ui(f: Finding) -> dict:
    a = f.asset
    g = a.group if a else None
    template_id = getattr(f, "template_id", None)
    status = _derive_status(f)

    result = {
        "id": _sid(f.id),
        "assetId": _sid(f.asset_id),
        "assetValue": a.value if a else None,
        "assetType": a.asset_type if a else None,
        "groupId": _sid(g.id) if g else None,
        "groupName": g.name if g else None,
        "severity": f.severity or "info",
        "title": f.title,
        "description": f.description or "",
        "findingType": f.finding_type,
        "dedupeKey": f.dedupe_key,
        "firstSeenAt": f.first_seen_at.isoformat() if f.first_seen_at else None,
        "lastSeenAt": f.last_seen_at.isoformat() if f.last_seen_at else None,
        "detectedAt": f.created_at.isoformat() if f.created_at else None,
        # Derived status
        "status": status,
        # Suppress fields
        "ignored": bool(f.ignored),
        "ignoredAt": f.ignored_at.isoformat() if f.ignored_at else None,
        "ignoredReason": f.ignored_reason,
        # Resolve fields
        "resolved": bool(getattr(f, "resolved", False)),
        "resolvedAt": f.resolved_at.isoformat() if getattr(f, "resolved_at", None) else None,
        "resolvedBy": _sid(f.resolved_by) if getattr(f, "resolved_by", None) else None,
        "resolvedReason": getattr(f, "resolved_reason", None),
        # In Progress fields
        "inProgress": bool(getattr(f, "in_progress", False)),
        "inProgressAt": getattr(f, "in_progress_at", None).isoformat() if getattr(f, "in_progress_at", None) else None,
        "inProgressBy": _sid(getattr(f, "in_progress_by", None)) if getattr(f, "in_progress_by", None) else None,
        "inProgressNotes": getattr(f, "in_progress_notes", None),
        # Accepted Risk fields
        "acceptedRisk": bool(getattr(f, "accepted_risk", False)),
        "acceptedRiskAt": getattr(f, "accepted_risk_at", None).isoformat() if getattr(f, "accepted_risk_at", None) else None,
        "acceptedRiskBy": _sid(getattr(f, "accepted_risk_by", None)) if getattr(f, "accepted_risk_by", None) else None,
        "acceptedRiskJustification": getattr(f, "accepted_risk_justification", None),
        # Other
        "details": f.details_json,
        "scanJobId": _sid(f.scan_job_id),
        "source": f.source or "engine",
        # M7: Enrichment fields
        "category": getattr(f, "category", None),
        "remediation": getattr(f, "remediation", None),
        "cwe": getattr(f, "cwe", None),
        "confidence": getattr(f, "confidence", None),
        "tags": getattr(f, "tags_json", None),
        "references": getattr(f, "references_json", None),
        # Human-readable summary from template registry
        "summary": _lookup_summary(template_id),
    }

    return result


def _base_query(org_id: int):
    """Build the base query with eager loading."""
    return (
        db.session.query(Finding)
        .join(Asset, Finding.asset_id == Asset.id)
        .join(AssetGroup, Asset.group_id == AssetGroup.id)
        .filter(Asset.organization_id == org_id)
        .options(
            db.joinedload(Finding.asset).joinedload(Asset.group)
        )
    )


def _apply_status_filter(query, status: str | None):
    """Apply status filter to a query. Returns the filtered query."""
    if not status or status == "all":
        return query

    if status == "open":
        return query.filter(_is_open_filter())
    elif status == "in_progress":
        return query.filter(
            or_(Finding.resolved == False, Finding.resolved == None),
            or_(Finding.accepted_risk == False, Finding.accepted_risk == None),
            or_(Finding.ignored == False, Finding.ignored == None),
            Finding.in_progress == True,
        )
    elif status == "accepted_risk":
        return query.filter(
            or_(Finding.resolved == False, Finding.resolved == None),
            Finding.accepted_risk == True,
        )
    elif status == "suppressed":
        return query.filter(
            or_(Finding.resolved == False, Finding.resolved == None),
            or_(Finding.accepted_risk == False, Finding.accepted_risk == None),
            Finding.ignored == True,
        )
    elif status == "resolved":
        return query.filter(Finding.resolved == True)

    return query


# GET /findings — all roles can view
@findings_bp.get("")
@require_auth
def list_findings():
    org_id = current_organization_id()

    # Query params
    severity = request.args.get("severity")
    category = request.args.get("category")
    group_id = request.args.get("group_id")
    asset_id = request.args.get("asset_id")
    search = request.args.get("q", "").strip()
    ignored = request.args.get("ignored")
    status = request.args.get("status")           # open, in_progress, accepted_risk, suppressed, resolved, all
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 100, type=int), 500)

    query = _base_query(org_id)

    # Filters
    if severity and severity != "all":
        query = query.filter(Finding.severity == severity)

    if category and category != "all":
        if hasattr(Finding, "category"):
            query = query.filter(Finding.category == category)

    if group_id and group_id != "all":
        query = query.filter(Asset.group_id == int(group_id))

    if asset_id:
        query = query.filter(Finding.asset_id == int(asset_id))

    # Status filter
    if status and status != "all":
        query = _apply_status_filter(query, status)
    elif ignored == "true":
        query = query.filter(Finding.ignored == True)
    elif ignored == "false" or (ignored is None and not status):
        # Default: show only open findings
        query = query.filter(_is_open_filter())

    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                Finding.title.ilike(pattern),
                Finding.description.ilike(pattern),
                Finding.finding_type.ilike(pattern),
            )
        )

    # Total count for pagination
    total = query.count()

    # Sort: critical first, then by date
    severity_order = db.case(
        (Finding.severity == "critical", 0),
        (Finding.severity == "high", 1),
        (Finding.severity == "medium", 2),
        (Finding.severity == "low", 3),
        (Finding.severity == "info", 4),
        else_=5,
    )
    query = query.order_by(severity_order, Finding.id.desc())

    # Pagination
    rows = query.offset((page - 1) * per_page).limit(per_page).all()

    # ── Shared base for badge counts ──
    # Severity and category counts should NOT be filtered by the current
    # severity or category selection so that the pills remain stable
    # (same pattern: show counts for all options regardless of which is active).
    # They DO respect group, search, and status filters.
    badge_base = _base_query(org_id).filter(_is_open_filter())
    if group_id and group_id != "all":
        badge_base = badge_base.filter(Asset.group_id == int(group_id))
    if search:
        pattern = f"%{search}%"
        badge_base = badge_base.filter(
            or_(Finding.title.ilike(pattern), Finding.description.ilike(pattern))
        )

    # Severity counts (for the filter badges — open findings only, not filtered by severity)
    severity_counts = {}
    for sev in ["critical", "high", "medium", "low", "info"]:
        severity_counts[sev] = badge_base.filter(Finding.severity == sev).count()

    # Category counts (for the filter badges — open findings only, not filtered by category)
    category_counts = {}
    if hasattr(Finding, "category"):
        cat_rows = (
            badge_base
            .with_entities(Finding.category, func.count(Finding.id))
            .group_by(Finding.category)
            .all()
        )
        for cat_val, cnt in cat_rows:
            key = (cat_val or "other").lower().strip()
            if not key:
                key = "other"
            category_counts[key] = category_counts.get(key, 0) + int(cnt)

    # Status counts (all findings, respecting group + search filters)
    status_base = _base_query(org_id)
    if group_id and group_id != "all":
        status_base = status_base.filter(Asset.group_id == int(group_id))
    if search:
        pattern = f"%{search}%"
        status_base = status_base.filter(
            or_(Finding.title.ilike(pattern), Finding.description.ilike(pattern))
        )

    sc = _status_count_cases()
    status_row = (
        status_base.with_entities(
            sc["open"].label("open_count"),
            sc["in_progress"].label("in_progress_count"),
            sc["accepted_risk"].label("accepted_risk_count"),
            sc["suppressed"].label("suppressed_count"),
            sc["resolved"].label("resolved_count"),
        ).first()
    )

    status_counts = {
        "open": int(status_row.open_count or 0) if status_row else 0,
        "in_progress": int(status_row.in_progress_count or 0) if status_row else 0,
        "accepted_risk": int(status_row.accepted_risk_count or 0) if status_row else 0,
        "suppressed": int(status_row.suppressed_count or 0) if status_row else 0,
        "resolved": int(status_row.resolved_count or 0) if status_row else 0,
    }

    return jsonify(
        findings=[finding_to_ui(r) for r in rows],
        total=total,
        page=page,
        perPage=per_page,
        severityCounts=severity_counts,
        categoryCounts=category_counts,
        statusCounts=status_counts,
    ), 200


# GET /findings/<id> — all roles can view
@findings_bp.get("/<int:finding_id>")
@require_auth
def get_finding(finding_id: int):
    org_id = current_organization_id()
    f = _base_query(org_id).filter(Finding.id == finding_id).first()
    if not f:
        return jsonify(error="finding not found"), 404
    return jsonify(finding_to_ui(f)), 200


# PATCH /findings/<id> — analyst+ (status transitions)
@findings_bp.patch("/<int:finding_id>")
@require_auth
@require_role("analyst")
def update_finding(finding_id: int):
    org_id = current_organization_id()
    uid = current_user_id()

    f = (
        db.session.query(Finding)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Finding.id == finding_id, Asset.organization_id == org_id)
        .options(db.joinedload(Finding.asset).joinedload(Asset.group))
        .first()
    )

    if not f:
        return jsonify(error="finding not found"), 404

    body = request.get_json(silent=True) or {}

    # ── New unified status transition ──
    # Accepts: { "status": "open|in_progress|accepted_risk|suppressed|resolved", "notes": "..." }
    if "status" in body:
        new_status = body["status"]
        valid_statuses = {"open", "in_progress", "accepted_risk", "suppressed", "resolved"}
        if new_status not in valid_statuses:
            return jsonify(error=f"status must be one of: {', '.join(sorted(valid_statuses))}"), 400

        notes = (body.get("notes") or body.get("reason") or body.get("justification") or "").strip() or None

        # Require justification for accepted_risk
        if new_status == "accepted_risk" and not notes:
            return jsonify(error="justification is required when accepting risk"), 400

        old_status = _derive_status(f)
        _set_status(f, new_status, uid, notes=notes, org_id=org_id)

        log_audit(
            organization_id=org_id,
            user_id=uid,
            action=f"finding.{new_status}",
            category="finding",
            target_type="finding",
            target_id=str(f.id),
            target_label=f.title,
            description=f"Changed finding '{f.title}' status to {new_status}",
            metadata={"old_status": old_status, "new_status": new_status, "notes": notes},
        )
        db.session.commit()
        return jsonify(finding_to_ui(f)), 200

    # ── Legacy boolean-based transitions (backward compatible) ──

    if "ignored" in body:
        ignored_val = bool(body["ignored"])
        reason = (body.get("ignoredReason") or body.get("ignored_reason") or "").strip() or None

        if ignored_val:
            _set_status(f, "suppressed", uid, notes=reason, org_id=org_id)
        else:
            # Unsuppress → go back to open
            if _derive_status(f) == "suppressed":
                _set_status(f, "open", uid, org_id=org_id)

    if "resolved" in body:
        resolved_val = bool(body["resolved"])
        reason = (body.get("resolvedReason") or body.get("resolved_reason") or "").strip() or None

        if resolved_val:
            _set_status(f, "resolved", uid, notes=reason, org_id=org_id)
        else:
            # Reopen → go back to open
            if _derive_status(f) == "resolved":
                _set_status(f, "open", uid, org_id=org_id)

    db.session.commit()
    return jsonify(finding_to_ui(f)), 200


# POST /findings/bulk-ignore — analyst+ (bulk suppress/unsuppress)
@findings_bp.post("/bulk-ignore")
@require_auth
@require_role("analyst")
def bulk_ignore():
    """Suppress or unsuppress multiple findings at once."""
    org_id = current_organization_id()
    uid = current_user_id()
    body = request.get_json(silent=True) or {}

    ids = body.get("ids", [])
    ignored_val = bool(body.get("ignored", True))
    reason = (body.get("reason") or "").strip() or None

    if not ids:
        return jsonify(error="ids array is required"), 400

    updated = 0
    for fid in ids:
        f = (
            db.session.query(Finding)
            .join(Asset, Finding.asset_id == Asset.id)
            .filter(Finding.id == int(fid), Asset.organization_id == org_id)
            .first()
        )
        if f:
            if ignored_val:
                _set_status(f, "suppressed", uid, notes=reason, org_id=org_id)
            else:
                if _derive_status(f) == "suppressed":
                    _set_status(f, "open", uid, org_id=org_id)
            updated += 1

    log_audit(
        organization_id=org_id,
        user_id=uid,
        action="finding.bulk_status_changed",
        category="finding",
        description=f"Bulk {'suppressed' if ignored_val else 'unsuppressed'} {updated} finding(s)",
        metadata={"status": "suppressed" if ignored_val else "open", "count": updated, "notes": reason},
    )

    db.session.commit()

    return jsonify(message=f"{updated} finding(s) updated", updated=updated), 200


# POST /findings/bulk-resolve — analyst+ (bulk resolve/reopen)
@findings_bp.post("/bulk-resolve")
@require_auth
@require_role("analyst")
def bulk_resolve():
    """Resolve or reopen multiple findings at once."""
    org_id = current_organization_id()
    uid = current_user_id()
    body = request.get_json(silent=True) or {}

    ids = body.get("ids", [])
    resolved_val = bool(body.get("resolved", True))
    reason = (body.get("reason") or "").strip() or None

    if not ids:
        return jsonify(error="ids array is required"), 400

    updated = 0
    for fid in ids:
        f = (
            db.session.query(Finding)
            .join(Asset, Finding.asset_id == Asset.id)
            .filter(Finding.id == int(fid), Asset.organization_id == org_id)
            .first()
        )
        if f:
            if resolved_val:
                _set_status(f, "resolved", uid, notes=reason, org_id=org_id)
            else:
                if _derive_status(f) == "resolved":
                    _set_status(f, "open", uid, org_id=org_id)
            updated += 1

    log_audit(
        organization_id=org_id,
        user_id=uid,
        action="finding.bulk_status_changed",
        category="finding",
        description=f"Bulk {'resolved' if resolved_val else 'reopened'} {updated} finding(s)",
        metadata={"status": "resolved" if resolved_val else "open", "count": updated, "notes": reason},
    )

    db.session.commit()

    return jsonify(message=f"{updated} finding(s) updated", updated=updated), 200


# POST /findings/bulk-status — analyst+ (bulk set any status)
@findings_bp.post("/bulk-status")
@require_auth
@require_role("analyst")
def bulk_status():
    """Set status on multiple findings at once. Supports all F2 statuses."""
    org_id = current_organization_id()
    uid = current_user_id()
    body = request.get_json(silent=True) or {}

    ids = body.get("ids", [])
    new_status = body.get("status", "").strip()
    notes = (body.get("notes") or body.get("reason") or body.get("justification") or "").strip() or None

    valid_statuses = {"open", "in_progress", "accepted_risk", "suppressed", "resolved"}
    if new_status not in valid_statuses:
        return jsonify(error=f"status must be one of: {', '.join(sorted(valid_statuses))}"), 400

    if not ids:
        return jsonify(error="ids array is required"), 400

    if new_status == "accepted_risk" and not notes:
        return jsonify(error="justification is required when accepting risk"), 400

    updated = 0
    for fid in ids:
        f = (
            db.session.query(Finding)
            .join(Asset, Finding.asset_id == Asset.id)
            .filter(Finding.id == int(fid), Asset.organization_id == org_id)
            .first()
        )
        if f:
            _set_status(f, new_status, uid, notes=notes, org_id=org_id)
            updated += 1

    log_audit(
        organization_id=org_id,
        user_id=uid,
        action="finding.bulk_status_changed",
        category="finding",
        description=f"Bulk changed {updated} finding(s) to {new_status}",
        metadata={"status": new_status, "count": updated, "notes": notes},
    )

    db.session.commit()

    return jsonify(message=f"{updated} finding(s) updated", updated=updated), 200


# GET /findings/export — admin+ (export_scan_results permission)
@findings_bp.get("/export")
@require_auth
@require_permission("export_scan_results")
def export_findings():
    """Export findings as CSV with M7 enrichment fields and F2 status fields."""
    org_id = current_organization_id()

    severity = request.args.get("severity")
    category = request.args.get("category")
    group_id = request.args.get("group_id")
    search = request.args.get("q", "").strip()
    status = request.args.get("status")
    ignored = request.args.get("ignored")

    query = _base_query(org_id)

    if severity and severity != "all":
        query = query.filter(Finding.severity == severity)
    if category and category != "all" and hasattr(Finding, "category"):
        query = query.filter(Finding.category == category)
    if group_id and group_id != "all":
        query = query.filter(Asset.group_id == int(group_id))
    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(Finding.title.ilike(pattern), Finding.description.ilike(pattern))
        )

    # Status filter
    if status and status != "all":
        query = _apply_status_filter(query, status)
    elif ignored == "true":
        query = query.filter(Finding.ignored == True)
    elif ignored == "false":
        query = query.filter(Finding.ignored == False)

    rows = query.order_by(Finding.id.desc()).all()

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="export.findings",
        category="export",
        description=f"Exported {len(rows)} findings as CSV",
        metadata={"format": "csv", "count": len(rows), "filters": {"severity": severity, "status": status}},
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Severity", "Status", "Category", "Title", "Description", "Remediation",
        "Asset", "Asset Type", "Asset Group", "Engine", "Analyzer",
        "CWE", "Confidence", "Template ID",
        "Detected", "Status Changed At", "Status Notes",
        "Source",
    ])

    for f in rows:
        a = f.asset
        g = a.group if a else None
        st = _derive_status(f)

        # Get the most recent status timestamp and notes
        status_at = None
        status_notes = None
        if st == "resolved":
            status_at = f.resolved_at
            status_notes = f.resolved_reason
        elif st == "accepted_risk":
            status_at = getattr(f, "accepted_risk_at", None)
            status_notes = getattr(f, "accepted_risk_justification", None)
        elif st == "suppressed":
            status_at = f.ignored_at
            status_notes = f.ignored_reason
        elif st == "in_progress":
            status_at = getattr(f, "in_progress_at", None)
            status_notes = getattr(f, "in_progress_notes", None)

        writer.writerow([
            f.id,
            f.severity or "info",
            st,
            getattr(f, "category", "") or "",
            f.title or "",
            (f.description or "")[:500],
            (getattr(f, "remediation", "") or "")[:500],
            a.value if a else "",
            a.asset_type if a else "",
            g.name if g else "",
            getattr(f, "engine", "") or "",
            getattr(f, "analyzer", "") or "",
            getattr(f, "cwe", "") or "",
            getattr(f, "confidence", "") or "",
            getattr(f, "template_id", "") or "",
            f.created_at.isoformat() if f.created_at else "",
            status_at.isoformat() if status_at else "",
            status_notes or "",
            f.source or "engine",
        ])

    csv_data = output.getvalue()
    output.close()

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=findings-export-{datetime.now().strftime('%Y%m%d')}.csv"}
    )