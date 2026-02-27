# =============================================================================
# File: app/auth/routes.py
# Description: Authentication routes for user registration, login, and session.
#
# Permissions Integration (based on permissions integration guide):
#   - POST /auth/register: public (no auth required)
#   - POST /auth/login: public (no auth required)
#   - GET /auth/me: any authenticated user (@require_auth only)
#   - No role/permission/limit decorators needed for any route in this file.
# =============================================================================

from __future__ import annotations

from flask import Blueprint, request, jsonify, g, current_app
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash

from app.extensions import db
from app.models import User
from app.auth.decorators import require_auth
from app.auth.tokens import create_access_token
from app.audit.routes import log_audit


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _is_valid_email(email: str) -> bool:
    return "@" in (email or "") and "." in (email or "")


def _now_utc():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _build_org_payload(org, include_billing: bool = False) -> dict:
    """Build organization payload for auth responses."""
    payload = {
        "id": str(org.id),
        "name": org.name,
        "slug": org.slug,
        "plan": org.effective_plan,
        "planStatus": org.plan_status,
        "country": org.country,
        "asset_limit": org.asset_limit,
        "assets_count": org.assets_count,
        "scans_this_month": org.scans_this_month,
    }

    if include_billing:
        from app.billing.routes import _build_plan_response
        payload["billing"] = _build_plan_response(org)

    return payload


@auth_bp.post("/register")
def register():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = (body.get("password") or "").strip()
    name = (body.get("name") or "").strip() or None

    # Optional profile fields
    job_title = (body.get("job_title") or "").strip() or None
    company = (body.get("company") or "").strip() or None
    country = (body.get("country") or "").strip() or None

    # Invite token (optional)
    invite_token = (body.get("invite_token") or "").strip() or None

    if not email or not _is_valid_email(email):
        return jsonify(error="valid email is required"), 400
    if not password or len(password) < 8:
        return jsonify(error="password must be at least 8 characters"), 400

    existing = User.query.filter(func.lower(User.email) == email.lower()).first()
    if existing:
        return jsonify(error="email already registered"), 409

    from app.models import Organization, OrganizationMember, PendingInvitation

    # ── If invite token provided, validate it ──
    invite = None
    if invite_token:
        invite = PendingInvitation.query.filter_by(token=invite_token, status="pending").first()
        if not invite:
            return jsonify(error="Invalid or expired invitation"), 400
        if invite.expires_at and invite.expires_at < _now_utc():
            invite.status = "expired"
            db.session.commit()
            return jsonify(error="Invitation has expired"), 400

    # Create user
    u = User(
        email=email,
        name=name,
        password_hash=generate_password_hash(password),
        job_title=job_title,
        company=company,
        country=country
    )
    db.session.add(u)
    db.session.flush()  # Get user ID

    if invite:
        # ── Join the inviter's organization ──
        org = Organization.query.get(invite.organization_id)
        if not org:
            db.session.rollback()
            return jsonify(error="Organization no longer exists"), 400

        membership = OrganizationMember(
            user_id=u.id,
            organization_id=org.id,
            role=invite.role,
            invited_by_user_id=invite.invited_by_user_id,
            invited_at=invite.created_at,
            joined_at=_now_utc(),
            is_active=True,
        )
        db.session.add(membership)

        # Mark invitation as accepted
        invite.status = "accepted"
        invite.accepted_at = _now_utc()

        role = invite.role
    else:
        # ── Create new organization (existing flow) ──
        org_slug = email.split("@")[0].replace(".", "-").replace("_", "-")
        base_slug = org_slug
        counter = 1
        while Organization.query.filter_by(slug=org_slug).first():
            org_slug = f"{base_slug}-{counter}"
            counter += 1

        org_name = name if name else email.split("@")[0].replace(".", " ").title() + "'s Workspace"

        org = Organization(
            name=org_name,
            slug=org_slug,
            country=country
        )
        db.session.add(org)
        db.session.flush()

        membership = OrganizationMember(
            user_id=u.id,
            organization_id=org.id,
            role="owner",
            joined_at=_now_utc(),
        )
        db.session.add(membership)

        role = "owner"

    db.session.commit()

    log_audit(
        organization_id=org.id,
        user_id=u.id,
        action="auth.register",
        category="auth",
        target_type="user",
        target_id=str(u.id),
        target_label=u.email,
        description=f"User registered: {u.email}" + (" (via invite)" if invite else " (new org)"),
        metadata={"role": role, "via_invite": bool(invite)},
    )

    token = create_access_token(secret_key=current_app.config["SECRET_KEY"], user_id=u.id)

    return jsonify(
        accessToken=token,
        user={
            "id": str(u.id),
            "email": u.email,
            "name": u.name,
            "job_title": u.job_title,
            "company": u.company,
            "country": u.country
        },
        organization=_build_org_payload(org),
        role=role,
        joinedViaInvite=bool(invite),
    ), 201


@auth_bp.post("/login")
def login():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = (body.get("password") or "").strip()

    if not email or not password:
        return jsonify(error="email and password are required"), 400

    u = User.query.filter(func.lower(User.email) == email.lower()).first()
    if not u or not check_password_hash(u.password_hash, password):
        return jsonify(error="invalid credentials"), 401

    from app.models import OrganizationMember

    # Load org info for the login response
    membership = OrganizationMember.query.filter_by(
        user_id=u.id,
        is_active=True
    ).first()

    token = create_access_token(secret_key=current_app.config["SECRET_KEY"], user_id=u.id)

    if membership:
        log_audit(
            organization_id=membership.organization_id,
            user_id=u.id,
            action="auth.login",
            category="auth",
            target_type="user",
            target_id=str(u.id),
            target_label=u.email,
            description=f"User logged in: {u.email}",
        )

    response = {
        "accessToken": token,
        "user": {
            "id": str(u.id),
            "email": u.email,
            "name": u.name,
        },
    }

    # Include org + plan info if user has an org
    if membership:
        org = membership.organization
        response["organization"] = _build_org_payload(org)
        response["role"] = membership.role

    return jsonify(response), 200


@auth_bp.get("/me")
@require_auth
def me():
    from app.models import OrganizationMember, Organization

    u = g.current_user

    membership = OrganizationMember.query.filter_by(
        user_id=u.id,
        is_active=True
    ).first()

    if not membership:
        return jsonify(error="User not associated with any organization"), 400

    org = membership.organization

    return jsonify(
        user={
            "id": str(u.id),
            "email": u.email,
            "name": u.name,
            "job_title": u.job_title,
            "company": u.company,
            "country": u.country
        },
        organization=_build_org_payload(org, include_billing=True),
        role=membership.role,
    ), 200