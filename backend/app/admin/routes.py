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
#   POST   /admin/organizations/<id>/suspend  — toggle org suspended
#   DELETE /admin/organizations/<id>          — hard-delete org + all data (DB cascade)
#   GET    /admin/users                       — paginated list of all users
#   POST   /admin/users/<id>/suspend          — toggle user suspended
#   POST   /admin/users/<id>/impersonate      — issue a session token for the user (admin acts as them)
#   DELETE /admin/users/<id>                  — hard-delete user (DB cascade)
#   GET    /admin/audit-log                   — platform-wide audit log (all orgs)
#   GET    /admin/scans                       — active + recent scan/discovery jobs (all orgs)
#   GET    /admin/announcements               — list all platform announcements
#   POST   /admin/announcements               — create announcement
#   DELETE /admin/announcements/<id>          — delete announcement
#   GET    /admin/health                      — platform health stats
# =============================================================================

from __future__ import annotations

import os
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g, current_app
from sqlalchemy import text

from app.extensions import db
from app.models import User, Organization, OrganizationMember, AuditLog, ScanJob, Asset, DiscoveryJob, PlatformAnnouncement, QuickScanLog, BlockedIP
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
        "isSuspended": org.is_suspended,
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
    from app.billing.routes import get_effective_limits, PLAN_CONFIG
    schedule_count = ScanSchedule.query.filter_by(organization_id=org.id, enabled=True).count()
    api_key_count = ApiKey.query.filter_by(organization_id=org.id, is_active=True).count()
    effective_limits = get_effective_limits(org)
    plan_defaults = PLAN_CONFIG.get(org.plan, PLAN_CONFIG["free"])["limits"]

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
        isSuspended=org.is_suspended,
        limitOverrides=org.limit_overrides or {},
        effectiveLimits=effective_limits,
        planDefaults=plan_defaults,
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


@admin_bp.post("/organizations/<int:org_id>/limits")
@require_superadmin
def set_org_limits(org_id: int):
    org = Organization.query.get(org_id)
    if not org:
        return jsonify(error="not found"), 404

    body = request.get_json(silent=True) or {}

    NUMERIC = ("assets", "scans_per_month", "team_members", "scheduled_scans", "api_keys")
    BOOLEAN = ("monitoring", "deep_discovery", "webhooks")
    VALID_KEYS = set(NUMERIC) | set(BOOLEAN)

    overrides = dict(org.limit_overrides or {})

    for key, val in body.items():
        if key not in VALID_KEYS:
            continue
        if val is None:
            # None = remove override, fall back to plan default
            overrides.pop(key, None)
        elif key in NUMERIC:
            try:
                int_val = int(val)
                if int_val < -1:
                    return jsonify(error=f"Invalid value for {key}: must be -1 (unlimited) or >= 0"), 400
                overrides[key] = int_val
            except (TypeError, ValueError):
                return jsonify(error=f"Invalid value for {key}: must be an integer"), 400
        elif key in BOOLEAN:
            overrides[key] = bool(val)

    org.limit_overrides = overrides if overrides else None

    # Keep asset_limit column in sync (it's the value enforcement code reads directly)
    if "assets" in overrides:
        org.asset_limit = overrides["assets"]
    else:
        # Restore plan default
        from app.billing.routes import PLAN_CONFIG
        org.asset_limit = PLAN_CONFIG.get(org.plan, PLAN_CONFIG["free"])["limits"]["assets"]

    log_audit(
        organization_id=org.id,
        user_id=g.current_user.id,
        action="admin.limits_changed",
        category="admin",
        target_type="organization",
        target_id=str(org.id),
        target_label=org.name,
        description=f"Admin updated custom limits for {org.name}",
        metadata={"overrides": overrides, "changed_by": g.current_user.email},
    )

    db.session.commit()

    from app.billing.routes import get_effective_limits
    return jsonify(
        message="Limits updated.",
        limitOverrides=org.limit_overrides,
        effectiveLimits=get_effective_limits(org),
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


@admin_bp.post("/organizations/<int:org_id>/suspend")
@require_superadmin
def toggle_org_suspend(org_id: int):
    org = Organization.query.get(org_id)
    if not org:
        return jsonify(error="not found"), 404

    org.is_suspended = not org.is_suspended
    action_label = "suspended" if org.is_suspended else "unsuspended"

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
    search = (request.args.get("search") or "").strip()
    role_filter = (request.args.get("role") or "").strip().lower()
    org_id_filter = request.args.get("org_id", type=int)
    suspended_filter = request.args.get("suspended")   # "true" | "false" | ""
    superadmin_filter = request.args.get("superadmin") # "true" | ""

    # Outer-join membership so users without an org are still included
    q = (
        db.session.query(User, OrganizationMember, Organization)
        .outerjoin(
            OrganizationMember,
            db.and_(OrganizationMember.user_id == User.id, OrganizationMember.is_active == True)
        )
        .outerjoin(Organization, Organization.id == OrganizationMember.organization_id)
    )

    if search:
        pattern = f"%{search}%"
        q = q.filter(db.or_(User.email.ilike(pattern), User.name.ilike(pattern)))
    if role_filter:
        q = q.filter(OrganizationMember.role == role_filter)
    if org_id_filter:
        q = q.filter(OrganizationMember.organization_id == org_id_filter)
    if suspended_filter == "true":
        q = q.filter(User.is_suspended == True)
    elif suspended_filter == "false":
        q = q.filter(User.is_suspended == False)
    if superadmin_filter == "true":
        q = q.filter(User.is_superadmin == True)

    q = q.order_by(User.created_at.desc())

    total = q.count()
    results = q.offset((page - 1) * limit).limit(limit).all()

    rows = []
    for u, membership, org in results:
        rows.append({
            "id": u.id,
            "email": u.email,
            "name": u.name,
            "isSuperadmin": bool(u.is_superadmin),
            "isSuspended": bool(u.is_suspended),
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


@admin_bp.post("/users/<int:user_id>/reset-password")
@require_superadmin
def send_password_reset(user_id: int):
    user = User.query.get(user_id)
    if not user:
        return jsonify(error="not found"), 404

    from app.auth.tokens import create_password_reset_token
    import os

    token = create_password_reset_token(
        secret_key=current_app.config["SECRET_KEY"],
        user_id=user.id,
        email=user.email,
    )

    frontend_url = os.environ.get("FRONTEND_URL", "https://nanoasm.com").rstrip("/")
    reset_link = f"{frontend_url}/reset-password/{token}"

    # Try to send via Resend if key is configured — fail gracefully
    email_sent = False
    resend_key = os.environ.get("RESEND_API_KEY", "")
    if resend_key:
        try:
            import resend
            resend.api_key = resend_key
            resend.Emails.send({
                "from": "Nano EASM <no-reply@nanoasm.com>",
                "to": [user.email],
                "subject": "Reset your Nano EASM password",
                "html": f"""
                <p>Hi {user.name or user.email},</p>
                <p>An admin has initiated a password reset for your account.</p>
                <p><a href="{reset_link}">Click here to set a new password</a></p>
                <p>This link expires in 24 hours.</p>
                <p>If you did not request this, you can ignore this email.</p>
                <p>— Nano EASM</p>
                """,
            })
            email_sent = True
        except Exception:
            pass  # Return the link regardless

    log_audit(
        organization_id=None,
        user_id=g.current_user.id,
        action="admin.password_reset_sent",
        category="admin",
        target_type="user",
        target_id=str(user.id),
        target_label=user.email,
        description=f"Admin generated password reset link for {user.email}",
        metadata={"changed_by": g.current_user.email, "email_sent": email_sent},
    )
    db.session.commit()

    return jsonify(
        link=reset_link,
        emailSent=email_sent,
        message=f"Reset link generated{'and emailed' if email_sent else ''}.",
    ), 200


@admin_bp.post("/users/<int:user_id>/suspend")
@require_superadmin
def toggle_user_suspend(user_id: int):
    if user_id == g.current_user.id:
        return jsonify(error="Cannot suspend your own account."), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify(error="not found"), 404

    if user.is_superadmin:
        return jsonify(error="Cannot suspend another superadmin account."), 400

    user.is_suspended = not user.is_suspended
    action_label = "suspended" if user.is_suspended else "unsuspended"

    membership = OrganizationMember.query.filter_by(user_id=user.id, is_active=True).first()
    log_audit(
        organization_id=membership.organization_id if membership else None,
        user_id=g.current_user.id,
        action=f"admin.user_{action_label}",
        category="admin",
        target_type="user",
        target_id=str(user.id),
        target_label=user.email,
        description=f"Admin {action_label} user {user.email}",
        metadata={"changed_by": g.current_user.email},
    )

    db.session.commit()
    return jsonify(
        message=f"User {action_label}.",
        isSuspended=user.is_suspended,
    ), 200


@admin_bp.post("/users/<int:user_id>/impersonate")
@require_superadmin
def impersonate_user(user_id: int):
    if user_id == g.current_user.id:
        return jsonify(error="Cannot impersonate yourself."), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify(error="not found"), 404

    if user.is_superadmin:
        return jsonify(error="Cannot impersonate another superadmin."), 400

    from app.auth.tokens import create_access_token

    token = create_access_token(secret_key=current_app.config["SECRET_KEY"], user_id=user.id)

    membership = OrganizationMember.query.filter_by(user_id=user.id, is_active=True).first()

    log_audit(
        organization_id=membership.organization_id if membership else None,
        user_id=g.current_user.id,
        action="admin.impersonate",
        category="admin",
        target_type="user",
        target_id=str(user.id),
        target_label=user.email,
        description=f"Admin impersonating user {user.email}",
        metadata={"impersonator": g.current_user.email},
    )
    db.session.commit()

    resp: dict = {
        "accessToken": token,
        "user": {
            "id": str(user.id),
            "email": user.email,
            "name": user.name,
            "isSuperadmin": False,
        },
    }
    if membership:
        org = membership.organization
        resp["organization"] = {
            "id": str(org.id),
            "name": org.name,
            "slug": org.slug,
            "plan": org.effective_plan,
        }
        resp["role"] = membership.role

    return jsonify(resp), 200


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


# ════════════════════════════════════════════════════════════════
# PLATFORM-WIDE AUDIT LOG
# ════════════════════════════════════════════════════════════════

@admin_bp.get("/audit-log")
@require_superadmin
def list_audit_log():
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(100, max(1, int(request.args.get("per_page", 50))))
    search = (request.args.get("q") or "").strip()
    category = (request.args.get("category") or "").strip()
    org_id = request.args.get("org_id", type=int)
    date_from = request.args.get("date_from") or None  # ISO date string
    date_to = request.args.get("date_to") or None

    q = AuditLog.query

    if org_id:
        q = q.filter(AuditLog.organization_id == org_id)
    if category:
        q = q.filter(AuditLog.category == category)
    if search:
        pattern = f"%{search}%"
        q = q.filter(db.or_(
            AuditLog.description.ilike(pattern),
            AuditLog.target_label.ilike(pattern),
            AuditLog.action.ilike(pattern),
            AuditLog.user_email.ilike(pattern),
        ))
    if date_from:
        try:
            q = q.filter(AuditLog.created_at >= datetime.fromisoformat(date_from))
        except ValueError:
            pass
    if date_to:
        try:
            q = q.filter(AuditLog.created_at <= datetime.fromisoformat(date_to))
        except ValueError:
            pass

    total = q.count()
    entries = q.order_by(AuditLog.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()

    # Category distribution (unfiltered by category so tabs always show totals)
    cat_q = AuditLog.query
    if org_id:
        cat_q = cat_q.filter(AuditLog.organization_id == org_id)
    from sqlalchemy import func as sqlfunc
    cat_rows = db.session.query(AuditLog.category, sqlfunc.count(AuditLog.id)).group_by(AuditLog.category).all()
    category_counts = {row[0]: row[1] for row in cat_rows}

    # Resolve org names for entries
    org_ids = {e.organization_id for e in entries if e.organization_id}
    orgs = {o.id: o.name for o in Organization.query.filter(Organization.id.in_(org_ids)).all()} if org_ids else {}

    def _row(e: AuditLog) -> dict:
        return {
            "id": str(e.id),
            "organizationId": str(e.organization_id) if e.organization_id else None,
            "organizationName": orgs.get(e.organization_id) if e.organization_id else None,
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
            "createdAt": e.created_at.isoformat() + "Z" if e.created_at else None,
        }

    return jsonify(
        entries=[_row(e) for e in entries],
        total=total,
        page=page,
        perPage=per_page,
        pages=(total + per_page - 1) // per_page,
        categoryCounts=category_counts,
    ), 200


# ════════════════════════════════════════════════════════════════
# ACTIVE SCANS MONITOR
# ════════════════════════════════════════════════════════════════

@admin_bp.get("/scans")
@require_superadmin
def list_active_scans():
    from datetime import timedelta

    limit = min(200, max(1, int(request.args.get("limit", 100))))
    status_filter = (request.args.get("status") or "").strip()   # active | recent | ""
    type_filter = (request.args.get("type") or "").strip()       # scan | discovery | ""
    org_id_filter = request.args.get("org_id", type=int)

    cutoff = _now_utc() - timedelta(hours=24)

    # ── ScanJobs (queued/running + finished last 24h) ──────────────
    sj_q = (
        db.session.query(ScanJob, Asset, Organization)
        .join(Asset, Asset.id == ScanJob.asset_id)
        .join(Organization, Organization.id == Asset.organization_id)
    )
    if org_id_filter:
        sj_q = sj_q.filter(Organization.id == org_id_filter)
    if status_filter == "active":
        sj_q = sj_q.filter(ScanJob.status.in_(["queued", "running"]))
    elif status_filter == "recent":
        sj_q = sj_q.filter(
            ScanJob.status.in_(["completed", "failed"]),
            ScanJob.finished_at >= cutoff,
        )
    else:
        sj_q = sj_q.filter(db.or_(
            ScanJob.status.in_(["queued", "running"]),
            db.and_(
                ScanJob.status.in_(["completed", "failed"]),
                ScanJob.finished_at >= cutoff,
            ),
        ))
    scan_rows = sj_q.order_by(ScanJob.created_at.desc()).limit(limit).all()

    # ── DiscoveryJobs (pending/running + finished last 24h) ────────
    dj_q = (
        db.session.query(DiscoveryJob, Organization)
        .join(Organization, Organization.id == DiscoveryJob.organization_id)
    )
    if org_id_filter:
        dj_q = dj_q.filter(Organization.id == org_id_filter)
    if status_filter == "active":
        dj_q = dj_q.filter(DiscoveryJob.status.in_(["pending", "running"]))
    elif status_filter == "recent":
        dj_q = dj_q.filter(
            DiscoveryJob.status.in_(["completed", "failed", "partial", "cancelled"]),
            DiscoveryJob.completed_at >= cutoff,
        )
    else:
        dj_q = dj_q.filter(db.or_(
            DiscoveryJob.status.in_(["pending", "running"]),
            db.and_(
                DiscoveryJob.status.in_(["completed", "failed", "partial", "cancelled"]),
                DiscoveryJob.completed_at >= cutoff,
            ),
        ))
    disc_rows = dj_q.order_by(DiscoveryJob.created_at.desc()).limit(limit).all()

    # ── Platform-wide stats ────────────────────────────────────────
    queued_total = ScanJob.query.filter(ScanJob.status == "queued").count()
    running_total = (
        ScanJob.query.filter(ScanJob.status == "running").count()
        + DiscoveryJob.query.filter(DiscoveryJob.status.in_(["pending", "running"])).count()
    )
    failed_today = (
        ScanJob.query.filter(ScanJob.status == "failed", ScanJob.finished_at >= cutoff).count()
        + DiscoveryJob.query.filter(DiscoveryJob.status == "failed", DiscoveryJob.completed_at >= cutoff).count()
    )
    completed_today = (
        ScanJob.query.filter(ScanJob.status == "completed", ScanJob.finished_at >= cutoff).count()
        + DiscoveryJob.query.filter(
            DiscoveryJob.status.in_(["completed", "partial"]),
            DiscoveryJob.completed_at >= cutoff,
        ).count()
    )

    def _scan_row(job: ScanJob, asset: Asset, org: Organization) -> dict:
        dur = None
        if job.started_at:
            end = job.finished_at or _now_utc()
            dur = int((end - job.started_at).total_seconds())
        return {
            "id": job.id,
            "type": "scan",
            "org": {"id": org.id, "name": org.name},
            "target": asset.value,
            "targetType": asset.asset_type,
            "status": job.status,
            "engines": job.scan_engines or [],
            "createdAt": job.created_at.isoformat() + "Z" if job.created_at else None,
            "startedAt": job.started_at.isoformat() + "Z" if job.started_at else None,
            "finishedAt": job.finished_at.isoformat() + "Z" if job.finished_at else None,
            "durationSeconds": dur,
            "errorMessage": job.error_message,
        }

    def _disc_row(job: DiscoveryJob, org: Organization) -> dict:
        dur = None
        if job.started_at:
            end = job.completed_at or _now_utc()
            dur = int((end - job.started_at).total_seconds())
        return {
            "id": job.id,
            "type": "discovery",
            "org": {"id": org.id, "name": org.name},
            "target": job.target,
            "targetType": job.target_type,
            "status": job.status,
            "modules": job.modules_run or [],
            "assetsFound": job.total_found,
            "newAssets": job.new_assets,
            "createdAt": job.created_at.isoformat() + "Z" if job.created_at else None,
            "startedAt": job.started_at.isoformat() + "Z" if job.started_at else None,
            "finishedAt": job.completed_at.isoformat() + "Z" if job.completed_at else None,
            "durationSeconds": dur,
        }

    jobs = []
    if type_filter != "discovery":
        jobs += [_scan_row(j, a, o) for j, a, o in scan_rows]
    if type_filter != "scan":
        jobs += [_disc_row(j, o) for j, o in disc_rows]
    jobs.sort(key=lambda x: x["createdAt"] or "", reverse=True)

    return jsonify(
        jobs=jobs[:limit],
        stats={
            "queued": queued_total,
            "running": running_total,
            "failedToday": failed_today,
            "completedToday": completed_today,
        },
    ), 200


# ════════════════════════════════════════════════════════════════
# BROADCAST ANNOUNCEMENTS
# ════════════════════════════════════════════════════════════════

def _ann_row(a: PlatformAnnouncement) -> dict:
    return {
        "id": a.id,
        "title": a.title,
        "body": a.body,
        "kind": a.kind,
        "targetOrgId": a.target_org_id,
        "targetOrgName": a.target_org.name if a.target_org else None,
        "createdBy": a.author.email if a.author else None,
        "createdAt": a.created_at.isoformat() + "Z" if a.created_at else None,
        "expiresAt": a.expires_at.isoformat() + "Z" if a.expires_at else None,
        "isActive": a.is_active,
    }


@admin_bp.get("/announcements")
@require_superadmin
def list_announcements():
    anns = (
        PlatformAnnouncement.query
        .order_by(PlatformAnnouncement.created_at.desc())
        .limit(100)
        .all()
    )
    return jsonify(announcements=[_ann_row(a) for a in anns]), 200


@admin_bp.post("/announcements")
@require_superadmin
def create_announcement():
    body = request.get_json(silent=True) or {}
    title = (body.get("title") or "").strip()
    if not title:
        return jsonify(error="title is required"), 400

    kind = body.get("kind", "info")
    if kind not in ("info", "warning", "critical"):
        kind = "info"

    expires_at = None
    if body.get("expiresAt"):
        try:
            expires_at = datetime.fromisoformat(body["expiresAt"].replace("Z", ""))
        except ValueError:
            pass

    ann = PlatformAnnouncement(
        title=title,
        body=(body.get("body") or "").strip() or None,
        kind=kind,
        target_org_id=body.get("targetOrgId") or None,
        created_by=g.current_user.id,
        created_at=_now_utc(),
        expires_at=expires_at,
        is_active=True,
    )
    db.session.add(ann)

    log_audit(
        organization_id=ann.target_org_id,
        user_id=g.current_user.id,
        action="admin.announcement_created",
        category="admin",
        target_type="announcement",
        target_id=None,
        target_label=title,
        description=f"Admin broadcast: {title}",
        metadata={"kind": kind, "target_org_id": ann.target_org_id},
    )
    db.session.commit()

    return jsonify(announcement=_ann_row(ann)), 201


@admin_bp.delete("/announcements/<int:ann_id>")
@require_superadmin
def delete_announcement(ann_id: int):
    ann = PlatformAnnouncement.query.get(ann_id)
    if not ann:
        return jsonify(error="not found"), 404
    db.session.delete(ann)
    db.session.commit()
    return jsonify(message="Announcement deleted."), 200


# ════════════════════════════════════════════════════════════════
# PLATFORM HEALTH
# ════════════════════════════════════════════════════════════════

@admin_bp.get("/health")
@require_superadmin
def platform_health():
    from datetime import timedelta
    from sqlalchemy import func as sqlfunc, text as sqtext

    now = _now_utc()
    cutoff_24h = now - timedelta(hours=24)
    cutoff_7d  = now - timedelta(days=7)

    # ── Uptime ────────────────────────────────────────────────────
    start_time = current_app.config.get("APP_START_TIME")
    if start_time:
        from datetime import timezone
        start_naive = start_time.replace(tzinfo=None)
        uptime_seconds = int((now - start_naive).total_seconds())
    else:
        uptime_seconds = None

    # ── DB pool stats ─────────────────────────────────────────────
    pool = db.engine.pool
    db_ping_ms = None
    db_ok = False
    try:
        import time as _time
        t0 = _time.monotonic()
        db.session.execute(sqtext("SELECT 1"))
        db_ping_ms = round((_time.monotonic() - t0) * 1000, 1)
        db_ok = True
    except Exception:
        pass

    try:
        pool_size     = pool.size()
        pool_checked  = pool.checkedout()
        pool_overflow = pool.overflow()
        pool_idle     = pool.checkedin()
    except Exception:
        pool_size = pool_checked = pool_overflow = pool_idle = None

    # ── Queue depths ──────────────────────────────────────────────
    queued_scans    = ScanJob.query.filter(ScanJob.status == "queued").count()
    running_scans   = ScanJob.query.filter(ScanJob.status == "running").count()
    pending_disc    = DiscoveryJob.query.filter(DiscoveryJob.status.in_(["pending", "running"])).count()

    # ── Error rates (last 24h) ────────────────────────────────────
    failed_scans_24h = ScanJob.query.filter(
        ScanJob.status == "failed", ScanJob.finished_at >= cutoff_24h).count()
    failed_disc_24h  = DiscoveryJob.query.filter(
        DiscoveryJob.status == "failed", DiscoveryJob.completed_at >= cutoff_24h).count()
    completed_scans_24h = ScanJob.query.filter(
        ScanJob.status == "completed", ScanJob.finished_at >= cutoff_24h).count()
    completed_disc_24h  = DiscoveryJob.query.filter(
        DiscoveryJob.status.in_(["completed", "partial"]),
        DiscoveryJob.completed_at >= cutoff_24h).count()

    total_jobs_24h = failed_scans_24h + failed_disc_24h + completed_scans_24h + completed_disc_24h
    error_rate_pct = round((failed_scans_24h + failed_disc_24h) / total_jobs_24h * 100, 1) if total_jobs_24h else 0.0

    # ── Platform totals ───────────────────────────────────────────
    from app.models import Finding
    total_orgs     = Organization.query.filter_by(is_active=True).count()
    total_users    = User.query.count()
    total_assets   = int(db.session.query(sqlfunc.sum(Organization.assets_count)).scalar() or 0)
    total_findings = Finding.query.count()

    # ── Recent activity ───────────────────────────────────────────
    new_orgs_7d   = Organization.query.filter(Organization.created_at >= cutoff_7d).count()
    new_users_7d  = User.query.filter(User.created_at >= cutoff_7d).count()
    scans_24h     = ScanJob.query.filter(ScanJob.created_at >= cutoff_24h).count()
    disc_24h      = DiscoveryJob.query.filter(DiscoveryJob.created_at >= cutoff_24h).count()

    # ── Overall status ────────────────────────────────────────────
    if not db_ok:
        status = "critical"
    elif error_rate_pct > 20 or queued_scans > 50:
        status = "degraded"
    else:
        status = "healthy"

    return jsonify(
        status=status,
        uptime={"seconds": uptime_seconds},
        db={
            "ok": db_ok,
            "pingMs": db_ping_ms,
            "poolSize": pool_size,
            "checkedOut": pool_checked,
            "idle": pool_idle,
            "overflow": pool_overflow,
        },
        queues={
            "queuedScans": queued_scans,
            "runningScans": running_scans,
            "activeDiscovery": pending_disc,
        },
        errors={
            "failedScans24h": failed_scans_24h,
            "failedDiscovery24h": failed_disc_24h,
            "completedJobs24h": completed_scans_24h + completed_disc_24h,
            "errorRatePct": error_rate_pct,
        },
        platform={
            "totalOrgs": total_orgs,
            "totalUsers": total_users,
            "totalAssets": total_assets,
            "totalFindings": total_findings,
        },
        recentActivity={
            "newOrgs7d": new_orgs_7d,
            "newUsers7d": new_users_7d,
            "scansStarted24h": scans_24h,
            "discoveryStarted24h": disc_24h,
        },
    ), 200


# ════════════════════════════════════════════════════════════════
# QUICK SCAN LOGS & IP BLOCK LIST
# ════════════════════════════════════════════════════════════════

@admin_bp.get("/quick-scans")
@require_superadmin
def list_quick_scans():
    from datetime import timedelta
    from sqlalchemy import func as sqlfunc

    page = max(1, int(request.args.get("page", 1)))
    limit = min(100, max(1, int(request.args.get("limit", 50))))
    search_ip = (request.args.get("ip") or "").strip()
    search_target = (request.args.get("target") or "").strip()
    status_filter = (request.args.get("status") or "").strip()
    source_filter = (request.args.get("source") or "").strip()

    q = QuickScanLog.query
    if search_ip:
        q = q.filter(QuickScanLog.ip_address.ilike(f"%{search_ip}%"))
    if search_target:
        q = q.filter(QuickScanLog.target.ilike(f"%{search_target}%"))
    if status_filter:
        q = q.filter(QuickScanLog.status == status_filter)
    if source_filter:
        q = q.filter(QuickScanLog.source == source_filter)

    total = q.count()
    logs = q.order_by(QuickScanLog.created_at.desc()).offset((page - 1) * limit).limit(limit).all()

    # Stats
    now = _now_utc()
    cutoff_24h = now - timedelta(hours=24)
    stats = {
        "total24h":        QuickScanLog.query.filter(QuickScanLog.created_at >= cutoff_24h).count(),
        "uniqueIPs24h":    db.session.query(sqlfunc.count(sqlfunc.distinct(QuickScanLog.ip_address)))
                              .filter(QuickScanLog.created_at >= cutoff_24h).scalar() or 0,
        "blocked24h":      QuickScanLog.query.filter(QuickScanLog.created_at >= cutoff_24h, QuickScanLog.status == "blocked").count(),
        "rateLimited24h":  QuickScanLog.query.filter(QuickScanLog.created_at >= cutoff_24h, QuickScanLog.status == "rate_limited").count(),
        "totalBlockedIPs": BlockedIP.query.count(),
    }

    # Top IPs last 24h (for repeat-offender detection)
    top_ips = (
        db.session.query(QuickScanLog.ip_address, sqlfunc.count(QuickScanLog.id).label("cnt"))
        .filter(QuickScanLog.created_at >= cutoff_24h)
        .group_by(QuickScanLog.ip_address)
        .order_by(sqlfunc.count(QuickScanLog.id).desc())
        .limit(10)
        .all()
    )

    def _row(log: QuickScanLog) -> dict:
        return {
            "id": log.id,
            "ip": log.ip_address,
            "userAgent": log.user_agent,
            "target": log.target,
            "assetType": log.asset_type,
            "source": getattr(log, "source", "scan"),
            "status": log.status,
            "durationMs": log.duration_ms,
            "riskScore": log.risk_score,
            "findingCounts": log.finding_counts,
            "errorMessage": log.error_message,
            "createdAt": log.created_at.isoformat() + "Z" if log.created_at else None,
        }

    return jsonify(
        logs=[_row(l) for l in logs],
        total=total,
        page=page,
        pages=(total + limit - 1) // limit,
        stats=stats,
        topIPs=[{"ip": row[0], "count": row[1]} for row in top_ips],
    ), 200


@admin_bp.get("/blocked-ips")
@require_superadmin
def list_blocked_ips():
    blocks = BlockedIP.query.order_by(BlockedIP.created_at.desc()).all()
    now = _now_utc()

    def _row(b: BlockedIP) -> dict:
        expired = bool(b.expires_at and b.expires_at <= now)
        return {
            "id": b.id,
            "ip": b.ip_address,
            "reason": b.reason,
            "blockedBy": b.admin.email if b.admin else None,
            "createdAt": b.created_at.isoformat() + "Z" if b.created_at else None,
            "expiresAt": b.expires_at.isoformat() + "Z" if b.expires_at else None,
            "expired": expired,
        }

    return jsonify(blocks=[_row(b) for b in blocks]), 200


@admin_bp.post("/blocked-ips")
@require_superadmin
def block_ip():
    body = request.get_json(silent=True) or {}
    ip = (body.get("ip") or "").strip()
    if not ip:
        return jsonify(error="ip is required"), 400

    existing = BlockedIP.query.filter_by(ip_address=ip).first()
    if existing:
        return jsonify(error="IP is already blocked"), 409

    expires_at = None
    if body.get("expiresAt"):
        try:
            expires_at = datetime.fromisoformat(body["expiresAt"].replace("Z", ""))
        except ValueError:
            pass

    block = BlockedIP(
        ip_address=ip,
        reason=(body.get("reason") or "").strip() or None,
        blocked_by=g.current_user.id,
        created_at=_now_utc(),
        expires_at=expires_at,
    )
    db.session.add(block)

    log_audit(
        organization_id=None,
        user_id=g.current_user.id,
        action="admin.ip_blocked",
        category="admin",
        target_type="ip",
        target_label=ip,
        description=f"Admin blocked IP {ip}",
        metadata={"reason": block.reason},
    )
    db.session.commit()
    return jsonify(message=f"IP {ip} blocked.", id=block.id), 201


@admin_bp.delete("/blocked-ips/<int:block_id>")
@require_superadmin
def unblock_ip(block_id: int):
    block = BlockedIP.query.get(block_id)
    if not block:
        return jsonify(error="not found"), 404
    ip = block.ip_address
    db.session.delete(block)

    log_audit(
        organization_id=None,
        user_id=g.current_user.id,
        action="admin.ip_unblocked",
        category="admin",
        target_type="ip",
        target_label=ip,
        description=f"Admin unblocked IP {ip}",
    )
    db.session.commit()
    return jsonify(message=f"IP {ip} unblocked."), 200
