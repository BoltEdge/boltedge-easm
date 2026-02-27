# =============================================================================
# File: app/groups/routes.py
# Description: Asset group routes for listing, creating, renaming, and deleting
#   groups, plus group summary with asset counts, finding severity breakdown,
#   top risky assets, and scan stats.
#
# F2 Update: Finding queries now account for all statuses:
#   - open: not ignored, not resolved, not in_progress, not accepted_risk
#   - in_progress: analyst is working on it
#   - accepted_risk: risk acknowledged with justification
#   - suppressed: risk-accepted / false positive (hidden from default views)
#   - resolved: remediated
#
#   Only "open" findings count toward exposure score and severity metrics.
#   Status counts for all states are included in responses for UI display.
#
# Permissions Integration:
#   - GET /groups: all roles can view
#   - GET /groups/<id>/summary: all roles can view
#   - POST /groups: admin+ only
#   - PATCH /groups/<id>: admin+ only
#   - DELETE /groups/<id>: admin+ only
# =============================================================================

from __future__ import annotations

import math

from flask import Blueprint, request, jsonify
from sqlalchemy import func, case, or_, and_

from app.extensions import db
from app.models import Asset, AssetGroup, Finding, ScanJob
from app.auth.decorators import require_auth, current_user_id, current_organization_id
from app.auth.permissions import require_role
from app.audit.routes import log_audit

groups_bp = Blueprint("groups", __name__, url_prefix="/groups")


def _sid(x) -> str:
    return str(x) if x is not None else ""


def _calc_exposure_score(severity_counts: dict) -> dict:
    """Calculate exposure score from severity counts using the centralized formula."""
    from app.utils.scoring import calc_exposure_score, exposure_label_and_color

    score = calc_exposure_score(
        critical=severity_counts.get("critical", 0),
        high=severity_counts.get("high", 0),
        medium=severity_counts.get("medium", 0),
        low=severity_counts.get("low", 0),
        info=severity_counts.get("info", 0),
    )
    label, color = exposure_label_and_color(score)
    return {"score": score, "label": label, "color": color}


def _is_open_filter():
    """
    Filter expression for 'open' findings — the only status that counts
    toward exposure score and severity metrics.

    A finding is 'open' when ALL of these are false/null:
      - ignored (suppressed)
      - resolved
      - in_progress
      - accepted_risk
    """
    return and_(
        or_(Finding.ignored == False, Finding.ignored == None),
        or_(Finding.resolved == False, Finding.resolved == None),
        or_(Finding.in_progress == False, Finding.in_progress == None),
        or_(Finding.accepted_risk == False, Finding.accepted_risk == None),
    )


def _status_count_cases():
    """
    SQLAlchemy case expressions for counting findings by derived status.
    Priority order: resolved > accepted_risk > suppressed > in_progress > open
    """
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


def group_to_ui(g1: AssetGroup) -> dict:
    return {
        "id": _sid(g1.id),
        "name": g1.name,
        "createdAt": g1.created_at.isoformat() if g1.created_at else None,
        "assetCount": 0,
        "ipCount": 0,
        "domainCount": 0,
        "emailCount": 0,
        "cloudCount": 0,
    }


# GET /groups — all roles can view
@groups_bp.get("")
@require_auth
def list_groups():
    org_id = current_organization_id()

    rows = (
        db.session.query(
            AssetGroup,
            func.count(Asset.id).label("asset_count"),
            func.sum(case((Asset.asset_type == "ip", 1), else_=0)).label("ip_count"),
            func.sum(case((Asset.asset_type == "domain", 1), else_=0)).label("domain_count"),
            func.sum(case((Asset.asset_type == "email", 1), else_=0)).label("email_count"),
            func.sum(case((Asset.asset_type == "cloud", 1), else_=0)).label("cloud_count"),
        )
        .outerjoin(Asset, Asset.group_id == AssetGroup.id)
        .filter(
            AssetGroup.organization_id == org_id,
            AssetGroup.is_active.is_(True),
        )
        .group_by(AssetGroup.id)
        .order_by(AssetGroup.id.desc())
        .all()
    )

    # Finding severity counts per group — ONLY open findings count toward risk
    finding_counts = (
        db.session.query(
            Asset.group_id,
            Finding.severity,
            func.count(Finding.id),
        )
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(
            Asset.organization_id == org_id,
            _is_open_filter(),
        )
        .group_by(Asset.group_id, Finding.severity)
        .all()
    )

    # Build severity map per group (open findings only)
    group_findings = {}
    for gid, sev, cnt in finding_counts:
        gid_str = str(gid)
        if gid_str not in group_findings:
            group_findings[gid_str] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        s = (sev or "info").lower()
        if s not in group_findings[gid_str]:
            s = "info"
        group_findings[gid_str][s] += int(cnt)
        group_findings[gid_str]["total"] += int(cnt)

    # Status counts per group (all findings, for the status breakdown)
    status_cases = _status_count_cases()
    status_rows = (
        db.session.query(
            Asset.group_id,
            status_cases["open"].label("open_count"),
            status_cases["in_progress"].label("in_progress_count"),
            status_cases["accepted_risk"].label("accepted_risk_count"),
            status_cases["suppressed"].label("suppressed_count"),
            status_cases["resolved"].label("resolved_count"),
        )
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Asset.organization_id == org_id)
        .group_by(Asset.group_id)
        .all()
    )

    group_status_counts = {}
    for gid, open_c, ip_c, ar_c, sup_c, res_c in status_rows:
        group_status_counts[str(gid)] = {
            "open": int(open_c or 0),
            "in_progress": int(ip_c or 0),
            "accepted_risk": int(ar_c or 0),
            "suppressed": int(sup_c or 0),
            "resolved": int(res_c or 0),
        }

    # Get last scan time per group
    last_scans = (
        db.session.query(
            Asset.group_id,
            func.max(Asset.last_scan_at).label("last_scan"),
        )
        .filter(Asset.organization_id == org_id)
        .group_by(Asset.group_id)
        .all()
    )
    last_scan_map = {str(gid): ls for gid, ls in last_scans if ls}

    out = []
    for g, asset_c, ip_c, domain_c, email_c, cloud_c in rows:
        gid = _sid(g.id)
        findings_data = group_findings.get(gid, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0})
        status_data = group_status_counts.get(gid, {"open": 0, "in_progress": 0, "accepted_risk": 0, "suppressed": 0, "resolved": 0})
        last_scan = last_scan_map.get(gid)

        # Determine max severity (from open findings only)
        max_sev = "clean"
        for s in ["critical", "high", "medium", "low", "info"]:
            if findings_data.get(s, 0) > 0:
                max_sev = s
                break

        # Exposure score (from open findings only)
        exposure = _calc_exposure_score(findings_data)

        out.append({
            "id": gid,
            "name": g.name,
            "createdAt": g.created_at.isoformat() if g.created_at else None,
            "assetCount": int(asset_c or 0),
            "ipCount": int(ip_c or 0),
            "domainCount": int(domain_c or 0),
            "emailCount": int(email_c or 0),
            "cloudCount": int(cloud_c or 0),
            "findings": findings_data,
            "statusCounts": status_data,
            "maxSeverity": max_sev,
            "lastScanAt": last_scan.isoformat() if last_scan else None,
            "exposureScore": exposure,
        })

    return jsonify(out), 200


# GET /groups/<id>/summary — all roles can view
@groups_bp.get("/<int:group_id>/summary")
@require_auth
def group_summary(group_id: int):
    """Mini-dashboard data for a specific group."""
    org_id = current_organization_id()

    g = AssetGroup.query.filter_by(id=group_id, organization_id=org_id, is_active=True).first()
    if not g:
        return jsonify(error="group not found"), 404

    # Asset counts
    asset_counts = (
        db.session.query(
            func.count(Asset.id).label("total"),
            func.sum(case((Asset.asset_type == "ip", 1), else_=0)).label("ip"),
            func.sum(case((Asset.asset_type == "domain", 1), else_=0)).label("domain"),
            func.sum(case((Asset.asset_type == "email", 1), else_=0)).label("email"),
            func.sum(case((Asset.asset_type == "cloud", 1), else_=0)).label("cloud"),
            func.sum(case((Asset.last_scan_at != None, 1), else_=0)).label("scanned"),
        )
        .filter(Asset.group_id == group_id, Asset.organization_id == org_id)
        .first()
    )

    total_assets = int(asset_counts.total or 0) if asset_counts else 0
    scanned_assets = int(asset_counts.scanned or 0) if asset_counts else 0

    # Finding severity counts — ONLY open findings count toward risk
    severity_rows = (
        db.session.query(Finding.severity, func.count(Finding.id))
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(
            Asset.group_id == group_id,
            Asset.organization_id == org_id,
            _is_open_filter(),
        )
        .group_by(Finding.severity)
        .all()
    )

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sev, cnt in severity_rows:
        s = (sev or "info").lower()
        if s in severity_counts:
            severity_counts[s] = int(cnt)
    total_open_findings = sum(severity_counts.values())

    # Status counts (all findings in group)
    status_cases = _status_count_cases()
    status_row = (
        db.session.query(
            status_cases["open"].label("open_count"),
            status_cases["in_progress"].label("in_progress_count"),
            status_cases["accepted_risk"].label("accepted_risk_count"),
            status_cases["suppressed"].label("suppressed_count"),
            status_cases["resolved"].label("resolved_count"),
        )
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(
            Asset.group_id == group_id,
            Asset.organization_id == org_id,
        )
        .first()
    )

    status_counts = {
        "open": int(status_row.open_count or 0) if status_row else 0,
        "in_progress": int(status_row.in_progress_count or 0) if status_row else 0,
        "accepted_risk": int(status_row.accepted_risk_count or 0) if status_row else 0,
        "suppressed": int(status_row.suppressed_count or 0) if status_row else 0,
        "resolved": int(status_row.resolved_count or 0) if status_row else 0,
    }
    total_all_findings = sum(status_counts.values())

    # Exposure score (open findings only)
    exposure = _calc_exposure_score(severity_counts)

    # Top risky assets (by OPEN finding count, critical first)
    risky_assets = (
        db.session.query(
            Asset.id,
            Asset.value,
            Asset.asset_type,
            func.count(Finding.id).label("finding_count"),
            func.sum(case((Finding.severity == "critical", 1), else_=0)).label("critical_count"),
            func.sum(case((Finding.severity == "high", 1), else_=0)).label("high_count"),
            func.sum(case((Finding.severity == "medium", 1), else_=0)).label("medium_count"),
            func.sum(case((Finding.severity == "low", 1), else_=0)).label("low_count"),
        )
        .join(Finding, Finding.asset_id == Asset.id)
        .filter(
            Asset.group_id == group_id,
            Asset.organization_id == org_id,
            _is_open_filter(),
        )
        .group_by(Asset.id, Asset.value, Asset.asset_type)
        .order_by(
            db.desc("critical_count"),
            db.desc("high_count"),
            db.desc("finding_count"),
        )
        .limit(5)
        .all()
    )

    top_risky = []
    for aid, val, atype, fc, cc, hc, mc, lc in risky_assets:
        max_s = "info"
        if int(cc or 0) > 0:
            max_s = "critical"
        elif int(hc or 0) > 0:
            max_s = "high"
        elif int(mc or 0) > 0:
            max_s = "medium"
        elif int(lc or 0) > 0:
            max_s = "low"
        top_risky.append({
            "assetId": str(aid),
            "value": val,
            "type": atype,
            "findingCount": int(fc or 0),
            "criticalCount": int(cc or 0),
            "highCount": int(hc or 0),
            "maxSeverity": max_s,
        })

    # Scan stats
    scan_stats = (
        db.session.query(
            func.count(ScanJob.id).label("total"),
            func.sum(case((ScanJob.status == "completed", 1), else_=0)).label("completed"),
            func.sum(case((ScanJob.status == "running", 1), else_=0)).label("running"),
            func.sum(case((ScanJob.status == "failed", 1), else_=0)).label("failed"),
            func.max(ScanJob.finished_at).label("last_scan"),
        )
        .join(Asset, ScanJob.asset_id == Asset.id)
        .filter(Asset.group_id == group_id, Asset.organization_id == org_id)
        .first()
    )

    return jsonify(
        groupId=str(group_id),
        groupName=g.name,
        exposureScore=exposure,
        assets={
            "total": total_assets,
            "scanned": scanned_assets,
            "notScanned": total_assets - scanned_assets,
            "ip": int(asset_counts.ip or 0) if asset_counts else 0,
            "domain": int(asset_counts.domain or 0) if asset_counts else 0,
            "email": int(asset_counts.email or 0) if asset_counts else 0,
            "cloud": int(asset_counts.cloud or 0) if asset_counts else 0,
        },
        findings={
            "total": total_all_findings,
            "openCount": total_open_findings,
            "bySeverity": severity_counts,
        },
        statusCounts=status_counts,
        topRiskyAssets=top_risky,
        scans={
            "total": int(scan_stats.total or 0) if scan_stats else 0,
            "completed": int(scan_stats.completed or 0) if scan_stats else 0,
            "running": int(scan_stats.running or 0) if scan_stats else 0,
            "failed": int(scan_stats.failed or 0) if scan_stats else 0,
            "lastScanAt": scan_stats.last_scan.isoformat() if scan_stats and scan_stats.last_scan else None,
        },
    ), 200


# POST /groups — admin+ only
@groups_bp.post("")
@require_auth
@require_role("admin")
def create_group():
    uid = current_user_id()
    org_id = current_organization_id()

    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()

    if not name:
        return jsonify(error="name is required"), 400

    existing = AssetGroup.query.filter(
        AssetGroup.organization_id == org_id,
        func.lower(AssetGroup.name) == name.lower(),
    ).first()

    if existing:
        return jsonify(error="group already exists"), 409

    g1 = AssetGroup(name=name, user_id=uid, organization_id=org_id)
    db.session.add(g1)
    db.session.flush()  # get g1.id before logging

    log_audit(
        organization_id=org_id,
        user_id=uid,
        action="group.created",
        category="group",
        target_type="asset_group",
        target_id=str(g1.id),
        target_label=g1.name,
        description=f"Created asset group '{g1.name}'",
    )

    db.session.commit()

    return jsonify(group_to_ui(g1)), 201


# PATCH /groups/<id> — admin+ only
@groups_bp.patch("/<group_id>")
@require_auth
@require_role("admin")
def rename_group(group_id: str):
    uid = current_user_id()
    org_id = current_organization_id()

    g1 = AssetGroup.query.filter_by(id=int(group_id), organization_id=org_id).first()

    if not g1 or not g1.is_active:
        return jsonify(error="group not found"), 404

    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()

    if not name:
        return jsonify(error="name is required"), 400

    clash = AssetGroup.query.filter(
        AssetGroup.organization_id == org_id,
        AssetGroup.id != g1.id,
        func.lower(AssetGroup.name) == name.lower(),
    ).first()

    if clash:
        return jsonify(error="another group already uses that name"), 409

    old_name = g1.name
    g1.name = name
    g1.user_id = uid

    log_audit(
        organization_id=org_id,
        user_id=uid,
        action="group.updated",
        category="group",
        target_type="asset_group",
        target_id=str(g1.id),
        target_label=g1.name,
        description=f"Renamed asset group '{old_name}' to '{name}'",
        metadata={"old_name": old_name, "new_name": name},
    )

    db.session.commit()

    return jsonify(group_to_ui(g1)), 200


# DELETE /groups/<id> — admin+ only
@groups_bp.delete("/<group_id>")
@require_auth
@require_role("admin")
def delete_group(group_id: str):
    org_id = current_organization_id()

    g1 = AssetGroup.query.filter_by(id=int(group_id), organization_id=org_id).first()

    if not g1:
        return jsonify(error="group not found"), 404

    group_name = g1.name
    group_id_str = str(g1.id)

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="group.deleted",
        category="group",
        target_type="asset_group",
        target_id=group_id_str,
        target_label=group_name,
        description=f"Deleted asset group '{group_name}'",
    )

    db.session.delete(g1)
    db.session.commit()

    return jsonify(message="deleted", groupId=_sid(group_id)), 200