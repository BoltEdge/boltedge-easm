# =============================================================================
# File: app/admin/routes.py
# Description: Platform admin routes — superadmin only.
#   All endpoints return 404 for non-superadmins (do not reveal existence).
#   No org scoping — operates across all tenants.
#
# Endpoints:
#   GET    /admin/stats                       — platform-wide counts + plan breakdown
#   GET    /admin/organizations               — paginated list of all orgs
#   GET    /admin/organizations/<id>          — single org detail + usage
#   POST   /admin/organizations/<id>/plan     — change any org's plan
#   POST   /admin/organizations/<id>/archive  — toggle org active/archived
#   DELETE /admin/organizations/<id>          — hard-delete org + all data (DB cascade)
#   GET    /admin/users                       — paginated list of all users
#   DELETE /admin/users/<id>                  — hard-delete user (DB cascade)
# =============================================================================

from __future__ import annotations

import os
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
from sqlalchemy import text

from app.extensions import db
from app.models import User, Organization, OrganizationMember
from app.auth.decorators import require_superadmin
from app.audit.routes import log_audit

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

ENABLE_BILLING = os.environ.get("ENABLE_BILLING", "false").lower() == "true"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _org_row(org: Organization) -> dict:
    """Serialise an org to a lightweight row for the list view."""
    member_count = OrganizationMember.query.filter_by(
        organization_id=org.id, is_active=True
    ).count()
    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "plan": org.effective_plan,
        "planStatus": org.plan_status,
        "assetsCount": org.assets_count,
        "assetLimit": org.asset_limit,
        "scansThisMonth": org.scans_this_month,
        "memberCount": member_count,
        "isActive": org.is_active,
        "createdAt": org.created_at.isoformat() + "Z" if org.created_at else None,
    }


# ════════════════════════════════════════════════════════════════
# PLATFORM STATS
# ════════════════════════════════════════════════════════════════

@admin_bp.get("/stats")
@require_superadmin
def get_stats():
    total_orgs = Organization.query.filter_by(is_active=True).count()
    total_users = User.query.count()
    total_members = OrganizationMember.query.filter_by(is_active=True).count()

    # Plan distribution
    from sqlalchemy import func
    plan_rows = (
        db.session.query(Organization.plan, func.count(Organization.id))
        .filter_by(is_active=True)
        .group_by(Organization.plan)
        .all()
    )
    plan_distribution = {row[0]: row[1] for row in plan_rows}

    # New orgs last 30 days
    from datetime import timedelta
    cutoff = _now_utc() - timedelta(days=30)
    new_orgs_30d = Organization.query.filter(
        Organization.is_active == True,
        Organization.created_at >= cutoff,
    ).count()

    # Total assets and scans this month across all orgs
    from sqlalchemy import func as sqlfunc
    asset_total = db.session.query(sqlfunc.sum(Organization.assets_count)).scalar() or 0
    scans_total = db.session.query(sqlfunc.sum(Organization.scans_this_month)).scalar() or 0

    return jsonify(
        totalOrgs=total_orgs,
        totalUsers=total_users,
        totalMembers=total_members,
        newOrgs30d=new_orgs_30d,
        totalAssets=int(asset_total),
        totalScansThisMonth=int(scans_total),
        planDistribution=plan_distribution,
    ), 200


# ════════════════════════════════════════════════════════════════
# ORGANIZATIONS
# ════════════════════════════════════════════════════════════════

@admin_bp.get("/organizations")
@require_superadmin
def list_organizations():
    page = max(1, int(request.args.get("page", 1)))
    limit = min(100, max(1, int(request.args.get("limit", 50))))
    search = (request.args.get("search") or "").strip().lower()
    plan_filter = (request.args.get("plan") or "").strip().lower()
    show_archived = request.args.get("showArchived", "false").lower() == "true"

    q = Organization.query
    if not show_archived:
        q = q.filter(Organization.is_active == True)

    if search:
        q = q.filter(
            db.or_(
                Organization.name.ilike(f"%{search}%"),
                Organization.slug.ilike(f"%{search}%"),
            )
        )
    if plan_filter:
        q = q.filter(Organization.plan == plan_filter)

    q = q.order_by(Organization.created_at.desc())

    total = q.count()
    orgs = q.offset((page - 1) * limit).limit(limit).all()

    return jsonify(
        organizations=[_org_row(o) for o in orgs],
        total=total,
        page=page,
        limit=limit,
        pages=(total + limit - 1) // limit,
    ), 200


@admin_bp.get("/organizations/<int:org_id>")
@require_superadmin
def get_organization(org_id: int):
    org = Organization.query.get(org_id)
    if not org:
        return jsonify(error="not found"), 404

    members = OrganizationMember.query.filter_by(
        organization_id=org.id, is_active=True
    ).all()

    member_list = []
    for m in members:
        u = User.query.get(m.user_id)
        if u:
            member_list.append({
                "id": u.id,
                "email": u.email,
                "name": u.name,
                "role": m.role,
                "joinedAt": m.joined_at.isoformat() + "Z" if m.joined_at else None,
                "isSuperadmin": bool(u.is_superadmin),
            })

    from app.models import ScanSchedule, ApiKey
    schedule_count = ScanSchedule.query.filter_by(organization_id=org.id, enabled=True).count()
    api_key_count = ApiKey.query.filter_by(organization_id=org.id, is_active=True).count()

    return jsonify(
        id=org.id,
        name=org.name,
        slug=org.slug,
        industry=org.industry,
        companySize=org.company_size,
        website=org.website,
        country=org.country,
        plan=org.effective_plan,
        planStatus=org.plan_status,
        planStartedAt=org.plan_started_at.isoformat() + "Z" if org.plan_started_at else None,
        planExpiresAt=org.plan_expires_at.isoformat() + "Z" if org.plan_expires_at else None,
        isActive=org.is_active,
        createdAt=org.created_at.isoformat() + "Z" if org.created_at else None,
        usage={
            "assets": org.assets_count,
            "assetLimit": org.asset_limit,
            "scansThisMonth": org.scans_this_month,
            "scheduledScans": schedule_count,
            "apiKeys": api_key_count,
            "members": len(member_list),
        },
        members=member_list,
    ), 200


@admin_bp.post("/organizations/<int:org_id>/plan")
@require_superadmin
def set_org_plan(org_id: int):
    org = Organization.query.get(org_id)
    if not org:
        return jsonify(error="not found"), 404

    body = request.get_json(silent=True) or {}
    target_plan = (body.get("plan") or "").strip().lower()

    from app.billing.routes import PLAN_CONFIG, PLAN_ORDER
    if target_plan not in PLAN_CONFIG:
        return jsonify(error=f"Invalid plan. Must be one of: {', '.join(PLAN_ORDER)}"), 400

    old_plan = org.plan
    config = PLAN_CONFIG[target_plan]
    now = _now_utc()

    org.plan = target_plan
    org.plan_status = "active"
    org.plan_started_at = now
    org.plan_expires_at = None  # admin grants never expire
    org.trial_ends_at = None
    org.billing_cycle = None
    org.asset_limit = config["limits"]["assets"]

    log_audit(
        organization_id=org.id,
        user_id=g.current_user.id,
        action="admin.plan_changed",
        category="admin",
        target_type="organization",
        target_id=str(org.id),
        target_label=org.name,
        description=f"Admin changed plan from {old_plan} to {target_plan}",
        metadata={"old_plan": old_plan, "new_plan": target_plan, "changed_by": g.current_user.email},
    )

    db.session.commit()

    return jsonify(
        message=f"Plan updated to {config['label']}.",
        org=_org_row(org),
    ), 200


@admin_bp.post("/organizations/<int:org_id>/archive")
@require_superadmin
def toggle_org_archive(org_id: int):
    org = Organization.query.get(org_id)
    if not org:
        return jsonify(error="not found"), 404

    org.is_active = not org.is_active
    action_label = "archived" if not org.is_active else "restored"

    log_audit(
        organization_id=org.id,
        user_id=g.current_user.id,
        action=f"admin.org_{action_label}",
        category="admin",
        target_type="organization",
        target_id=str(org.id),
        target_label=org.name,
        description=f"Admin {action_label} organization",
        metadata={"changed_by": g.current_user.email},
    )

    db.session.commit()
    return jsonify(message=f"Organization {action_label}.", org=_org_row(org)), 200


@admin_bp.delete("/organizations/<int:org_id>")
@require_superadmin
def delete_organization(org_id: int):
    org = Organization.query.get(org_id)
    if not org:
        return jsonify(error="not found"), 404

    org_name = org.name

    # All child tables have ondelete="CASCADE" at DB level — a direct SQL
    # DELETE bypasses SQLAlchemy ORM cascade and lets Postgres handle it.
    db.session.execute(text("DELETE FROM organization WHERE id = :oid"), {"oid": org_id})
    db.session.commit()

    return jsonify(message=f'Organization "{org_name}" permanently deleted.'), 200


# ════════════════════════════════════════════════════════════════
# USERS
# ════════════════════════════════════════════════════════════════

@admin_bp.get("/users")
@require_superadmin
def list_users():
    page = max(1, int(request.args.get("page", 1)))
    limit = min(100, max(1, int(request.args.get("limit", 50))))
    search = (request.args.get("search") or "").strip().lower()

    q = User.query

    if search:
        q = q.filter(
            db.or_(
                User.email.ilike(f"%{search}%"),
                User.name.ilike(f"%{search}%"),
            )
        )

    q = q.order_by(User.created_at.desc())

    total = q.count()
    users = q.offset((page - 1) * limit).limit(limit).all()

    rows = []
    for u in users:
        membership = OrganizationMember.query.filter_by(
            user_id=u.id, is_active=True
        ).first()
        org = membership.organization if membership else None
        rows.append({
            "id": u.id,
            "email": u.email,
            "name": u.name,
            "isSuperadmin": bool(u.is_superadmin),
            "createdAt": u.created_at.isoformat() + "Z" if u.created_at else None,
            "organization": {"id": org.id, "name": org.name, "plan": org.effective_plan} if org else None,
            "role": membership.role if membership else None,
        })

    return jsonify(
        users=rows,
        total=total,
        page=page,
        limit=limit,
        pages=(total + limit - 1) // limit,
    ), 200


@admin_bp.delete("/users/<int:user_id>")
@require_superadmin
def delete_user(user_id: int):
    if user_id == g.current_user.id:
        return jsonify(error="Cannot delete your own account."), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify(error="not found"), 404

    if user.is_superadmin:
        return jsonify(error="Cannot delete another superadmin account."), 400

    user_email = user.email

    # FK references to user.id use ondelete="CASCADE" or ondelete="SET NULL"
    # at the DB level — bypass ORM and let Postgres handle cascades directly.
    db.session.execute(text('DELETE FROM "user" WHERE id = :uid'), {"uid": user_id})
    db.session.commit()

    return jsonify(message=f'User "{user_email}" permanently deleted.'), 200
