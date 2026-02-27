# =============================================================================
# File: app/settings/routes.py
# Description: Settings routes for organization management, user/member
#   management (invite, role changes, removal), API key CRUD, billing/usage
#   overview, audit log, and current user role/permissions.
#
# Permissions Integration (based on permissions integration guide):
#   - GET /settings/organization: all roles can view
#   - PATCH /settings/organization: owner only (edit_organization permission)
#   - GET /settings/members: all roles can view
#   - POST /settings/members/invite: admin+ with team_members limit
#   - GET /settings/members/invitations: admin+
#   - DELETE /settings/members/invitations/<id>: admin+
#   - PATCH /settings/members/<id>/role: admin+ (cannot set to "owner" unless owner)
#   - DELETE /settings/members/<id>: admin+ (cannot remove someone with role "owner")
#   - GET /settings/api-keys: all roles can view
#   - POST /settings/api-keys: admin+ (manage_api_keys permission) with api_keys limit
#   - DELETE /settings/api-keys/<id>: admin+ (manage_api_keys permission)
#   - GET /settings/billing: all roles can view
#   - GET /settings/audit-log: admin+ (view_audit_log permission)
#   - GET /settings/audit-log/export: admin+ (export_audit_log permission)
#   - GET /settings/me: any authenticated user
#   - PATCH /settings/me: any authenticated user (own profile only)
#   - GET /settings/invitations/<token>: public (no auth)
#   - POST /settings/invitations/<token>/accept: any authenticated user
# =============================================================================

from __future__ import annotations

import csv
import hashlib
import io
import secrets
from datetime import datetime, timezone, timedelta, date

from flask import Blueprint, request, jsonify, g, Response
from app.extensions import db
from app.models import (
    Organization, OrganizationMember, User, ApiKey,
    PendingInvitation, AuditLog, OrganizationUsage,
    Asset, AssetGroup, ScanJob, ScanSchedule, Finding,
)
from app.auth.decorators import require_auth, current_user_id, current_organization_id
from app.auth.permissions import (
    require_role, require_permission, check_limit,
    get_user_role, get_permissions_for_role, ROLE_HIERARCHY,
)
from app.audit.routes import log_audit

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


def now_utc():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# =========================================================
# 1. ORGANIZATION SETTINGS
# =========================================================

# GET /settings/organization — all roles can view
@settings_bp.get("/organization")
@require_auth
def get_organization():
    org_id = current_organization_id()
    org = Organization.query.get(org_id)
    if not org:
        return jsonify(error="Organization not found"), 404

    user_role = get_user_role(current_user_id())

    return jsonify(
        id=str(org.id),
        name=org.name,
        slug=org.slug,
        country=org.country,
        industry=org.industry if hasattr(org, 'industry') else None,
        size=org.company_size if hasattr(org, 'company_size') else None,
        website=org.website if hasattr(org, 'website') else None,
        plan=org.plan,
        planStartedAt=org.plan_started_at.isoformat() if org.plan_started_at else None,
        planExpiresAt=org.plan_expires_at.isoformat() if org.plan_expires_at else None,
        assetLimit=org.asset_limit,
        assetsCount=org.assets_count,
        scansThisMonth=org.scans_this_month,
        isActive=org.is_active,
        createdAt=org.created_at.isoformat() if org.created_at else None,
        currentUserRole=user_role,
    ), 200


# PATCH /settings/organization — owner only (edit_organization permission)
@settings_bp.patch("/organization")
@require_auth
@require_permission("edit_organization")
def update_organization():
    org_id = current_organization_id()
    org = Organization.query.get(org_id)
    if not org:
        return jsonify(error="Organization not found"), 404

    body = request.get_json(silent=True) or {}

    if "name" in body:
        name = str(body["name"]).strip()
        if not name:
            return jsonify(error="Name cannot be empty"), 400
        org.name = name

    if "country" in body:
        org.country = body["country"] or None

    if "industry" in body:
        org.industry = str(body["industry"]).strip() or None

    if "size" in body:
        org.company_size = str(body["size"]).strip() or None

    if "website" in body:
        website = str(body["website"]).strip()
        if website and not website.startswith(("http://", "https://")):
            website = "https://" + website
        org.website = website or None

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="settings.organization_updated",
        category="settings",
        target_type="organization",
        target_id=str(org.id),
        target_label=org.name,
        description=f"Updated organization settings",
        metadata={"fields": list(body.keys())},
    )

    db.session.commit()

    return jsonify(message="Updated"), 200


# =========================================================
# 2. USER MANAGEMENT
# =========================================================

# GET /settings/members — all roles can view
@settings_bp.get("/members")
@require_auth
def list_members():
    org_id = current_organization_id()
    members = (
        OrganizationMember.query
        .filter_by(organization_id=org_id, is_active=True)
        .order_by(OrganizationMember.joined_at.desc())
        .all()
    )

    result = []
    for m in members:
        user = m.user
        invited_by = m.invited_by
        result.append({
            "id": str(m.id),
            "userId": str(m.user_id),
            "email": user.email if user else None,
            "name": user.name if user else None,
            "role": m.role,
            "joinedAt": m.joined_at.isoformat() if m.joined_at else None,
            "invitedAt": m.invited_at.isoformat() if m.invited_at else None,
            "invitedBy": invited_by.name if invited_by else None,
        })

    return jsonify(result), 200


# POST /settings/members/invite — admin+ with team_members limit
@settings_bp.post("/members/invite")
@require_auth
@require_role("admin")
@check_limit("team_members")
def invite_member():
    org_id = current_organization_id()
    user_id = current_user_id()
    body = request.get_json(silent=True) or {}

    email = str(body.get("email", "")).strip().lower()
    role = str(body.get("role", "analyst")).strip().lower()

    if not email:
        return jsonify(error="Email is required"), 400
    if role not in ROLE_HIERARCHY:
        return jsonify(error=f"Invalid role: {role}"), 400

    # Only owners can invite admins/owners
    inviter_role = get_user_role(user_id)
    if role in ("owner", "admin") and inviter_role != "owner":
        return jsonify(error="Only owners can assign admin/owner roles"), 403

    # Check if user already a member
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        existing_member = OrganizationMember.query.filter_by(
            user_id=existing_user.id, organization_id=org_id, is_active=True
        ).first()
        if existing_member:
            return jsonify(error="User is already a member"), 409

    # Check for existing pending invite
    existing_invite = PendingInvitation.query.filter_by(
        organization_id=org_id, email=email, status="pending"
    ).first()
    if existing_invite:
        return jsonify(error="An invitation is already pending for this email"), 409

    # Create invitation
    token = secrets.token_urlsafe(32)
    invite = PendingInvitation(
        organization_id=org_id,
        invited_by_user_id=user_id,
        email=email,
        role=role,
        token=token,
        status="pending",
        expires_at=now_utc() + timedelta(days=7),
    )
    db.session.add(invite)
    db.session.flush()  # get invite.id

    log_audit(
        organization_id=org_id,
        user_id=user_id,
        action="user.invited",
        category="user",
        target_type="invitation",
        target_id=str(invite.id),
        target_label=email,
        description=f"Invited {email} as {role}",
        metadata={"email": email, "role": role},
    )

    db.session.commit()

    return jsonify(
        id=str(invite.id),
        email=invite.email,
        role=invite.role,
        token=invite.token,
        expiresAt=invite.expires_at.isoformat(),
        message=f"Invitation sent to {email}",
    ), 201


# GET /settings/members/invitations — admin+
@settings_bp.get("/members/invitations")
@require_auth
@require_role("admin")
def list_invitations():
    org_id = current_organization_id()
    invites = (
        PendingInvitation.query
        .filter_by(organization_id=org_id, status="pending")
        .order_by(PendingInvitation.created_at.desc())
        .all()
    )

    result = []
    for inv in invites:
        inviter = inv.invited_by
        result.append({
            "id": str(inv.id),
            "email": inv.email,
            "role": inv.role,
            "status": inv.status,
            "token": inv.token,
            "invitedBy": inviter.name if inviter else None,
            "createdAt": inv.created_at.isoformat() if inv.created_at else None,
            "expiresAt": inv.expires_at.isoformat() if inv.expires_at else None,
        })

    return jsonify(result), 200


# DELETE /settings/members/invitations/<id> — admin+
@settings_bp.delete("/members/invitations/<int:invite_id>")
@require_auth
@require_role("admin")
def revoke_invitation(invite_id):
    org_id = current_organization_id()
    invite = PendingInvitation.query.filter_by(id=invite_id, organization_id=org_id).first()
    if not invite:
        return jsonify(error="Invitation not found"), 404

    invite.status = "revoked"

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="user.invitation_revoked",
        category="user",
        target_type="invitation",
        target_id=str(invite.id),
        target_label=invite.email,
        description=f"Revoked invitation for {invite.email}",
    )

    db.session.commit()

    return jsonify(message="Invitation revoked"), 200


# PATCH /settings/members/<id>/role — admin+
# Inside function: admin cannot set role to "owner", only owner can do that
@settings_bp.patch("/members/<int:member_id>/role")
@require_auth
@require_role("admin")
def update_member_role(member_id):
    org_id = current_organization_id()
    body = request.get_json(silent=True) or {}
    new_role = str(body.get("role", "")).strip().lower()

    if new_role not in ROLE_HIERARCHY:
        return jsonify(error=f"Invalid role: {new_role}"), 400

    member = OrganizationMember.query.filter_by(id=member_id, organization_id=org_id, is_active=True).first()
    if not member:
        return jsonify(error="Member not found"), 404

    # Can't change own role
    if member.user_id == current_user_id():
        return jsonify(error="You cannot change your own role"), 400

    # Only owner can set role to "owner"
    if new_role == "owner":
        current_member = g.current_member
        if not current_member or current_member.role != "owner":
            return jsonify(error="Only owners can assign the owner role"), 403

    # Can't change the last owner
    if member.role == "owner" and new_role != "owner":
        owner_count = OrganizationMember.query.filter_by(
            organization_id=org_id, role="owner", is_active=True
        ).count()
        if owner_count <= 1:
            return jsonify(error="Cannot remove the last owner"), 400

    old_role = member.role
    member.role = new_role

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="user.role_changed",
        category="user",
        target_type="user",
        target_id=str(member.user_id),
        target_label=member.user.email if member.user else None,
        description=f"Changed role from {old_role} to {new_role}",
        metadata={"old_role": old_role, "new_role": new_role},
    )

    db.session.commit()

    return jsonify(message=f"Role updated to {new_role}"), 200


# DELETE /settings/members/<id> — admin+
# Inside function: cannot remove someone with role "owner"
@settings_bp.delete("/members/<int:member_id>")
@require_auth
@require_role("admin")
def remove_member(member_id):
    org_id = current_organization_id()
    member = OrganizationMember.query.filter_by(id=member_id, organization_id=org_id, is_active=True).first()
    if not member:
        return jsonify(error="Member not found"), 404

    # Can't remove yourself
    if member.user_id == current_user_id():
        return jsonify(error="You cannot remove yourself"), 400

    # Can't remove someone with role "owner"
    if member.role == "owner":
        return jsonify(error="Cannot remove an owner. Transfer ownership first."), 403

    member_email = member.user.email if member.user else None

    member.is_active = False

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="user.removed",
        category="user",
        target_type="user",
        target_id=str(member.user_id),
        target_label=member_email,
        description=f"Removed member {member_email}",
    )

    db.session.commit()

    return jsonify(message="Member removed"), 200


# =========================================================
# 3. API KEYS
# =========================================================

def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


# GET /settings/api-keys — all roles can view
@settings_bp.get("/api-keys")
@require_auth
def list_api_keys():
    org_id = current_organization_id()
    keys = (
        ApiKey.query
        .filter_by(organization_id=org_id)
        .order_by(ApiKey.created_at.desc())
        .all()
    )

    result = []
    for k in keys:
        user = k.user
        result.append({
            "id": str(k.id),
            "name": k.name,
            "keyPrefix": k.key_prefix,
            "createdBy": user.name or user.email if user else None,
            "createdAt": k.created_at.isoformat() if k.created_at else None,
            "lastUsedAt": k.last_used_at.isoformat() if k.last_used_at else None,
            "expiresAt": k.expires_at.isoformat() if k.expires_at else None,
            "isActive": k.is_active,
            "revokedAt": k.revoked_at.isoformat() if k.revoked_at else None,
            "scopes": k.scopes,
        })

    return jsonify(result), 200


# POST /settings/api-keys — admin+ (manage_api_keys permission) with api_keys limit
@settings_bp.post("/api-keys")
@require_auth
@require_permission("manage_api_keys")
@check_limit("api_keys")
def create_api_key():
    org_id = current_organization_id()
    user_id = current_user_id()
    body = request.get_json(silent=True) or {}

    name = str(body.get("name", "")).strip()
    if not name:
        return jsonify(error="Name is required"), 400

    scopes = body.get("scopes")  # None = full access
    expires_in_days = body.get("expiresInDays")

    # Generate key: ag_sk_ + 40 random chars
    raw_key = "ag_sk_" + secrets.token_urlsafe(30)
    key_prefix = raw_key[:12]
    key_hash = _hash_key(raw_key)

    expires_at = None
    if expires_in_days:
        expires_at = now_utc() + timedelta(days=int(expires_in_days))

    api_key = ApiKey(
        organization_id=org_id,
        user_id=user_id,
        name=name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        scopes=scopes,
        expires_at=expires_at,
    )
    db.session.add(api_key)
    db.session.flush()  # get api_key.id

    log_audit(
        organization_id=org_id,
        user_id=user_id,
        action="settings.api_key_created",
        category="settings",
        target_type="api_key",
        target_id=str(api_key.id),
        target_label=name,
        description=f"Created API key '{name}'",
        metadata={"key_prefix": key_prefix},
    )

    db.session.commit()

    # Return the full key ONLY on creation — never again
    return jsonify(
        id=str(api_key.id),
        name=api_key.name,
        key=raw_key,  # Only time the full key is shown
        keyPrefix=key_prefix,
        createdAt=api_key.created_at.isoformat(),
        expiresAt=api_key.expires_at.isoformat() if api_key.expires_at else None,
        scopes=api_key.scopes,
    ), 201


# DELETE /settings/api-keys/<id> — admin+ (manage_api_keys permission)
@settings_bp.delete("/api-keys/<int:key_id>")
@require_auth
@require_permission("manage_api_keys")
def revoke_api_key(key_id):
    org_id = current_organization_id()
    key = ApiKey.query.filter_by(id=key_id, organization_id=org_id).first()
    if not key:
        return jsonify(error="API key not found"), 404

    key.is_active = False
    key.revoked_at = now_utc()

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="settings.api_key_revoked",
        category="settings",
        target_type="api_key",
        target_id=str(key.id),
        target_label=key.name,
        description=f"Revoked API key '{key.name}'",
    )

    db.session.commit()

    return jsonify(message="API key revoked"), 200


# =========================================================
# 4. BILLING & USAGE
# =========================================================

PLAN_LIMITS = {
    "free": {
        "name": "Free",
        "assetLimit": 10,
        "scansPerMonth": 50,
        "schedulesLimit": 2,
        "membersLimit": 2,
        "apiKeysLimit": 1,
        "features": ["Quick Scan", "Basic Findings"],
        "price": 0,
    },
    "starter": {
        "name": "Starter",
        "assetLimit": 50,
        "scansPerMonth": 500,
        "schedulesLimit": 10,
        "membersLimit": 5,
        "apiKeysLimit": 5,
        "features": ["All Scan Profiles", "Scheduled Scans", "API Access", "Email Alerts"],
        "price": 29,
    },
    "professional": {
        "name": "Professional",
        "assetLimit": 250,
        "scansPerMonth": 5000,
        "schedulesLimit": 50,
        "membersLimit": 20,
        "apiKeysLimit": 20,
        "features": ["Everything in Starter", "Priority Scanning", "Advanced Monitoring", "Integrations"],
        "price": 99,
    },
    "enterprise_silver": {
        "name": "Enterprise Silver",
        "assetLimit": 1000,
        "scansPerMonth": 20000,
        "schedulesLimit": 200,
        "membersLimit": 50,
        "apiKeysLimit": 50,
        "features": ["Everything in Professional", "Bulk Operations", "Audit Log", "Priority Support"],
        "price": 299,
    },
    "enterprise_gold": {
        "name": "Enterprise Gold",
        "assetLimit": -1,
        "scansPerMonth": -1,
        "schedulesLimit": -1,
        "membersLimit": -1,
        "apiKeysLimit": -1,
        "features": [
            "Everything in Enterprise Silver", "Unlimited Assets",
            "Custom Scan Profiles", "SSO", "Dedicated Support",
        ],
        "price": -1,
    },
    # Legacy alias — maps to enterprise_silver
    "enterprise": {
        "name": "Enterprise",
        "assetLimit": -1,
        "scansPerMonth": -1,
        "schedulesLimit": -1,
        "membersLimit": -1,
        "apiKeysLimit": -1,
        "features": [
            "Everything in Professional", "Unlimited Assets",
            "Custom Scan Profiles", "SSO", "Dedicated Support",
        ],
        "price": -1,
    },
}


# GET /settings/billing — all roles can view
@settings_bp.get("/billing")
@require_auth
def get_billing():
    org_id = current_organization_id()
    org = Organization.query.get(org_id)
    if not org:
        return jsonify(error="Organization not found"), 404

    plan_info = PLAN_LIMITS.get(org.plan, PLAN_LIMITS["free"])

    # Get actual counts
    assets_count = Asset.query.filter_by(organization_id=org_id).count()
    members_count = OrganizationMember.query.filter_by(organization_id=org_id, is_active=True).count()
    schedules_count = ScanSchedule.query.filter_by(organization_id=org_id, enabled=True).count()
    api_keys_count = ApiKey.query.filter_by(organization_id=org_id, is_active=True).count()

    # Get this month's scans
    first_of_month = date.today().replace(day=1)
    scans_this_month = ScanJob.query.filter(
        ScanJob.asset.has(organization_id=org_id),
        ScanJob.created_at >= datetime.combine(first_of_month, datetime.min.time()),
    ).count()

    return jsonify(
        plan=org.plan,
        planInfo=plan_info,
        planStartedAt=org.plan_started_at.isoformat() if org.plan_started_at else None,
        planExpiresAt=org.plan_expires_at.isoformat() if org.plan_expires_at else None,
        usage={
            "assets": {"current": assets_count, "limit": plan_info["assetLimit"]},
            "scansThisMonth": {"current": scans_this_month, "limit": plan_info["scansPerMonth"]},
            "schedules": {"current": schedules_count, "limit": plan_info["schedulesLimit"]},
            "members": {"current": members_count, "limit": plan_info["membersLimit"]},
            "apiKeys": {"current": api_keys_count, "limit": plan_info["apiKeysLimit"]},
        },
        allPlans=PLAN_LIMITS,
    ), 200


# =========================================================
# 5. AUDIT LOG
# =========================================================

# GET /settings/audit-log — admin+ (view_audit_log permission)
@settings_bp.get("/audit-log")
@require_auth
@require_permission("view_audit_log")
def get_audit_log():
    org_id = current_organization_id()
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 100)

    # Filters
    category_filter = request.args.get("category")
    action_filter = request.args.get("action")
    user_filter = request.args.get("user_id")
    target_type_filter = request.args.get("target_type")
    target_id_filter = request.args.get("target_id")
    search = request.args.get("q", "").strip()

    query = (
        AuditLog.query
        .filter_by(organization_id=org_id)
        .order_by(AuditLog.created_at.desc())
    )

    if category_filter and category_filter != "all":
        query = query.filter(AuditLog.category == category_filter)
    if action_filter:
        query = query.filter(AuditLog.action == action_filter)
    if user_filter:
        query = query.filter(AuditLog.user_id == int(user_filter))
    if target_type_filter:
        query = query.filter(AuditLog.target_type == target_type_filter)
    if target_id_filter:
        query = query.filter(AuditLog.target_id == target_id_filter)
    if search:
        pattern = f"%{search}%"
        from sqlalchemy import or_
        query = query.filter(or_(
            AuditLog.action.ilike(pattern),
            AuditLog.target_label.ilike(pattern),
            AuditLog.description.ilike(pattern),
            AuditLog.user_email.ilike(pattern),
        ))

    total = query.count()
    logs = query.offset((page - 1) * per_page).limit(per_page).all()

    result = []
    for log in logs:
        # Resolve user name if not stored
        user_name = None
        user_email = log.user_email
        if log.user_id and not user_email:
            user = User.query.get(log.user_id)
            if user:
                user_name = user.name
                user_email = user.email
        else:
            if log.user_id:
                user = User.query.get(log.user_id)
                user_name = user.name if user else None

        result.append({
            "id": str(log.id),
            "action": log.action,
            "category": log.category,
            "targetType": log.target_type,
            "targetId": log.target_id,
            "targetLabel": log.target_label,
            "description": log.description,
            "metadata": log.metadata_json if hasattr(log, 'metadata_json') else None,
            "userId": str(log.user_id) if log.user_id else None,
            "userName": user_name,
            "userEmail": user_email,
            "ipAddress": log.ip_address,
            "createdAt": log.created_at.isoformat() if log.created_at else None,
        })

    # Category counts for filter tabs
    category_counts = dict(
        db.session.query(AuditLog.category, db.func.count(AuditLog.id))
        .filter_by(organization_id=org_id)
        .group_by(AuditLog.category)
        .all()
    )

    return jsonify(
        logs=result,
        total=total,
        page=page,
        perPage=per_page,
        categoryCounts=category_counts,
    ), 200


# GET /settings/audit-log/export — admin+ (export_audit_log permission)
@settings_bp.get("/audit-log/export")
@require_auth
@require_permission("export_audit_log")
def export_audit_log():
    org_id = current_organization_id()

    # Optional date filters
    date_from = request.args.get("from")
    date_to = request.args.get("to")
    category_filter = request.args.get("category")

    query = (
        AuditLog.query
        .filter_by(organization_id=org_id)
        .order_by(AuditLog.created_at.desc())
    )

    if category_filter and category_filter != "all":
        query = query.filter(AuditLog.category == category_filter)

    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from)
            query = query.filter(AuditLog.created_at >= dt_from)
        except ValueError:
            pass

    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to)
            query = query.filter(AuditLog.created_at <= dt_to)
        except ValueError:
            pass

    # Cap at 10,000 rows for safety
    logs = query.limit(10000).all()

    # Build CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Timestamp", "Action", "Category", "User", "Email",
        "Target Type", "Target ID", "Target Label",
        "Description", "IP Address", "Metadata",
    ])

    for log in logs:
        user_name = None
        user_email = log.user_email
        if log.user_id:
            user = User.query.get(log.user_id)
            if user:
                user_name = user.name
                user_email = user_email or user.email

        writer.writerow([
            log.created_at.isoformat() if log.created_at else "",
            log.action or "",
            log.category or "",
            user_name or "",
            user_email or "",
            log.target_type or "",
            log.target_id or "",
            log.target_label or "",
            log.description or "",
            log.ip_address or "",
            str(log.metadata_json) if hasattr(log, 'metadata_json') and log.metadata_json else "",
        ])

    csv_content = output.getvalue()
    output.close()

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="export.audit_log",
        category="export",
        description=f"Exported {len(logs)} audit log entries as CSV",
        metadata={"format": "csv", "count": len(logs)},
    )
    db.session.commit()

    today = date.today().isoformat()
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=audit-log-{today}.csv"},
    )


# =========================================================
# 6. CURRENT USER SETTINGS (for frontend permission checks)
# =========================================================

# GET /settings/me — any authenticated user
@settings_bp.get("/me")
@require_auth
def get_current_user_settings():
    """Return current user's role, permissions, and plan context for the frontend."""
    org_id = current_organization_id()
    user_id = current_user_id()
    user = User.query.get(user_id)
    member = g.current_member
    org = Organization.query.get(org_id) if org_id else None

    role = member.role if member else None
    plan = org.plan if org else "free"

    return jsonify(
        userId=str(user_id),
        email=user.email if user else None,
        name=user.name if user else None,
        jobTitle=user.job_title if user else None,
        role=role,
        permissions=get_permissions_for_role(role) if role else {},
        plan=plan,
        organizationId=str(org_id) if org_id else None,
        organizationName=org.name if org else None,
        organizationIndustry=org.industry if org else None,
        organizationSize=org.company_size if org else None,
        organizationWebsite=org.website if org else None,
    ), 200


# PATCH /settings/me — any authenticated user (own profile only)
@settings_bp.patch("/me")
@require_auth
def update_current_user_settings():
    """Update current user's own profile fields."""
    user_id = current_user_id()
    org_id = current_organization_id()
    user = User.query.get(user_id)
    if not user:
        return jsonify(error="User not found"), 404

    body = request.get_json(silent=True) or {}
    updated_fields = []

    if "name" in body:
        name = str(body["name"]).strip()
        if not name:
            return jsonify(error="Name cannot be empty"), 400
        user.name = name
        updated_fields.append("name")

    if "jobTitle" in body:
        user.job_title = str(body["jobTitle"]).strip() or None
        updated_fields.append("jobTitle")

    if "country" in body:
        user.country = str(body["country"]).strip() or None
        updated_fields.append("country")

    if not updated_fields:
        return jsonify(error="No valid fields to update"), 400

    log_audit(
        organization_id=org_id,
        user_id=user_id,
        action="settings.profile_updated",
        category="settings",
        target_type="user",
        target_id=str(user_id),
        target_label=user.email,
        description=f"Updated profile: {', '.join(updated_fields)}",
        metadata={"fields": updated_fields},
    )

    db.session.commit()

    return jsonify(
        message="Profile updated",
        userId=str(user_id),
        name=user.name,
        email=user.email,
        jobTitle=user.job_title,
        country=user.country,
    ), 200


# =========================================================
# 7. ACCEPT INVITATION (public view, auth for accepting)
# =========================================================

# GET /settings/invitations/<token> — public (no auth required)
@settings_bp.get("/invitations/<token>")
def get_invitation_info(token):
    """Public endpoint - get invitation details by token."""
    invite = PendingInvitation.query.filter_by(token=token).first()
    if not invite:
        return jsonify(error="Invitation not found"), 404

    if invite.status != "pending":
        return jsonify(error=f"Invitation has been {invite.status}"), 410

    if invite.expires_at and invite.expires_at < now_utc():
        invite.status = "expired"
        db.session.commit()
        return jsonify(error="Invitation has expired"), 410

    org = Organization.query.get(invite.organization_id)

    return jsonify(
        id=str(invite.id),
        email=invite.email,
        role=invite.role,
        organizationName=org.name if org else "Unknown",
        expiresAt=invite.expires_at.isoformat() if invite.expires_at else None,
    ), 200


# POST /settings/invitations/<token>/accept — any authenticated user
@settings_bp.post("/invitations/<token>/accept")
@require_auth
def accept_invitation(token):
    """Accept an invitation - requires authenticated user."""
    user_id = current_user_id()
    user = User.query.get(user_id)

    invite = PendingInvitation.query.filter_by(token=token, status="pending").first()
    if not invite:
        return jsonify(error="Invitation not found or already used"), 404

    if invite.expires_at and invite.expires_at < now_utc():
        invite.status = "expired"
        db.session.commit()
        return jsonify(error="Invitation has expired"), 410

    # Check if already a member
    existing = OrganizationMember.query.filter_by(
        user_id=user_id, organization_id=invite.organization_id, is_active=True
    ).first()
    if existing:
        invite.status = "accepted"
        invite.accepted_at = now_utc()
        db.session.commit()
        return jsonify(message="You are already a member of this organization"), 200

    # Create membership
    member = OrganizationMember(
        user_id=user_id,
        organization_id=invite.organization_id,
        role=invite.role,
        invited_by_user_id=invite.invited_by_user_id,
        invited_at=invite.created_at,
        joined_at=now_utc(),
        is_active=True,
    )
    db.session.add(member)

    invite.status = "accepted"
    invite.accepted_at = now_utc()

    log_audit(
        organization_id=invite.organization_id,
        user_id=user_id,
        action="user.invitation_accepted",
        category="user",
        target_type="user",
        target_id=str(user_id),
        target_label=user.email if user else None,
        description=f"{user.email if user else 'User'} accepted invitation as {invite.role}",
        metadata={"role": invite.role},
    )

    db.session.commit()

    return jsonify(
        message="Welcome! You have joined the organization.",
        organizationId=str(invite.organization_id),
        role=invite.role,
    ), 200