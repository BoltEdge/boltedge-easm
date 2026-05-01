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
from app.models import User, PlatformAnnouncement, OrganizationMember
from app.auth.decorators import require_auth
from app.auth.tokens import create_access_token, verify_password_reset_token
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

    if u.is_suspended:
        return jsonify(
            error="Your account has been suspended. Please contact your admin or reach out to Nano EASM support.",
            code="ACCOUNT_SUSPENDED",
        ), 403

    from app.models import OrganizationMember

    # Load org info for the login response
    membership = OrganizationMember.query.filter_by(
        user_id=u.id,
        is_active=True
    ).first()

    if membership and membership.organization.is_suspended:
        return jsonify(
            error="Your organization's access has been suspended. Please contact your admin or reach out to Nano EASM support.",
            code="ACCOUNT_SUSPENDED",
        ), 403

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
            "isSuperadmin": bool(u.is_superadmin),
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

    if u.is_suspended:
        return jsonify(
            error="Your account has been suspended. Please contact your admin or reach out to Nano EASM support.",
            code="ACCOUNT_SUSPENDED",
        ), 403

    membership = OrganizationMember.query.filter_by(
        user_id=u.id,
        is_active=True
    ).first()

    if not membership:
        return jsonify(error="User not associated with any organization"), 400

    org = membership.organization

    if org.is_suspended:
        return jsonify(
            error="Your organization's access has been suspended. Please contact your admin or reach out to Nano EASM support.",
            code="ACCOUNT_SUSPENDED",
        ), 403

    return jsonify(
        user={
            "id": str(u.id),
            "email": u.email,
            "name": u.name,
            "job_title": u.job_title,
            "company": u.company,
            "country": u.country,
            "isSuperadmin": bool(u.is_superadmin),
            "oauthProvider": u.oauth_provider,
            "hasPassword": bool(u.password_hash),
        },
        organization=_build_org_payload(org, include_billing=True),
        role=membership.role,
    ), 200


@auth_bp.post("/forgot-password")
def forgot_password():
    """Request a password-reset email. Always returns 200 to prevent email enumeration."""
    import os
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()

    generic = jsonify(message="If that email is registered, you'll receive a reset link shortly."), 200

    if not email or not _is_valid_email(email):
        return generic

    user = User.query.filter(func.lower(User.email) == email.lower()).first()
    if not user:
        return generic

    from app.auth.tokens import create_password_reset_token

    token = create_password_reset_token(
        secret_key=current_app.config["SECRET_KEY"],
        user_id=user.id,
        email=user.email,
    )

    frontend_url = os.environ.get("FRONTEND_URL", "https://nanoasm.com").rstrip("/")
    reset_link = f"{frontend_url}/reset-password/{token}"

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
                <p>We received a request to reset your password.</p>
                <p><a href="{reset_link}">Click here to set a new password</a></p>
                <p>This link expires in 24 hours. If you didn't request this, you can safely ignore this email.</p>
                <p>— Nano EASM</p>
                """,
            })
        except Exception:
            pass

    return generic


@auth_bp.post("/change-password")
@require_auth
def change_password():
    """Change the current user's password. Requires the existing password."""
    user = g.current_user
    body = request.get_json(silent=True) or {}
    current_password = (body.get("currentPassword") or "").strip()
    new_password = (body.get("newPassword") or "").strip()

    if not user.password_hash:
        return jsonify(
            error="This account signs in with " + (user.oauth_provider or "an external provider")
                  + ". Set a password via the password reset flow first.",
            code="OAUTH_ACCOUNT",
        ), 400

    if not current_password or not new_password:
        return jsonify(error="Current and new passwords are required"), 400
    if len(new_password) < 8:
        return jsonify(error="New password must be at least 8 characters"), 400
    if new_password == current_password:
        return jsonify(error="New password must be different from current password"), 400

    if not check_password_hash(user.password_hash, current_password):
        return jsonify(error="Current password is incorrect"), 401

    user.password_hash = generate_password_hash(new_password)

    membership = OrganizationMember.query.filter_by(user_id=user.id, is_active=True).first()
    log_audit(
        organization_id=membership.organization_id if membership else None,
        user_id=user.id,
        action="auth.password_changed",
        category="auth",
        target_type="user",
        target_id=str(user.id),
        target_label=user.email,
        description="User changed their password",
    )

    db.session.commit()
    return jsonify(message="Password changed successfully"), 200


@auth_bp.post("/reset-password")
def reset_password():
    """Consume a password-reset token and set a new password. Public endpoint."""
    body = request.get_json(silent=True) or {}
    token = (body.get("token") or "").strip()
    new_password = (body.get("password") or "").strip()

    if not token:
        return jsonify(error="token is required"), 400
    if not new_password or len(new_password) < 8:
        return jsonify(error="Password must be at least 8 characters"), 400

    data = verify_password_reset_token(
        secret_key=current_app.config["SECRET_KEY"],
        token=token,
    )
    if not data:
        return jsonify(error="This reset link is invalid or has expired."), 400

    user = User.query.get(data["user_id"])
    if not user or user.email != data["email"]:
        return jsonify(error="This reset link is invalid or has expired."), 400

    user.password_hash = generate_password_hash(new_password)
    db.session.commit()

    return jsonify(message="Password updated successfully. You can now log in."), 200


@auth_bp.get("/reset-password/verify")
def verify_reset_token():
    """Check if a password-reset token is still valid. Public endpoint."""
    token = (request.args.get("token") or "").strip()
    if not token:
        return jsonify(valid=False, error="token is required"), 400

    data = verify_password_reset_token(
        secret_key=current_app.config["SECRET_KEY"],
        token=token,
    )
    if not data:
        return jsonify(valid=False, error="This reset link is invalid or has expired."), 200

    user = User.query.get(data["user_id"])
    if not user or user.email != data["email"]:
        return jsonify(valid=False, error="This reset link is invalid or has expired."), 200

    return jsonify(valid=True, email=user.email), 200


def _oauth_state_serializer(secret_key: str):
    from itsdangerous import URLSafeTimedSerializer
    return URLSafeTimedSerializer(secret_key, salt="nanoasm-oauth-state")


@auth_bp.get("/oauth/google")
def oauth_google_start():
    import os, urllib.parse
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
    if not client_id:
        return jsonify(error="Google OAuth is not configured"), 503

    frontend_url = os.environ.get("FRONTEND_URL", "https://nanoasm.com").rstrip("/")
    redirect_uri = f"{frontend_url}/api/auth/oauth/google/callback"

    next_url = request.args.get("next", "/dashboard")
    state = _oauth_state_serializer(current_app.config["SECRET_KEY"]).dumps({"next": next_url})

    params = urllib.parse.urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "select_account",
    })

    from flask import redirect as flask_redirect
    return flask_redirect(f"https://accounts.google.com/o/oauth2/v2/auth?{params}")


@auth_bp.get("/oauth/google/callback")
def oauth_google_callback():
    import os, requests as http
    from flask import redirect as flask_redirect

    frontend_url = os.environ.get("FRONTEND_URL", "https://nanoasm.com").rstrip("/")
    error_base = f"{frontend_url}/login?oauth_error="

    # Verify state
    raw_state = request.args.get("state", "")
    try:
        state_data = _oauth_state_serializer(current_app.config["SECRET_KEY"]).loads(
            raw_state, max_age=600
        )
        next_url = state_data.get("next", "/dashboard")
    except Exception:
        return flask_redirect(error_base + "invalid_state")

    code = request.args.get("code")
    if not code:
        error = request.args.get("error", "access_denied")
        return flask_redirect(error_base + error)

    client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")
    redirect_uri = f"{frontend_url}/api/auth/oauth/google/callback"

    # Exchange code for tokens
    try:
        token_resp = http.post("https://oauth2.googleapis.com/token", data={
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }, timeout=10)
        token_resp.raise_for_status()
        tokens = token_resp.json()
    except Exception:
        return flask_redirect(error_base + "token_exchange_failed")

    # Fetch user info
    try:
        userinfo_resp = http.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            timeout=10,
        )
        userinfo_resp.raise_for_status()
        info = userinfo_resp.json()
    except Exception:
        return flask_redirect(error_base + "userinfo_failed")

    google_id = info.get("sub")
    email = (info.get("email") or "").strip().lower()
    name = info.get("name") or info.get("given_name") or email.split("@")[0]
    avatar_url = info.get("picture")

    if not email or not google_id:
        return flask_redirect(error_base + "missing_profile")

    from app.models import Organization, OrganizationMember

    # Find existing user by OAuth ID or email
    user = User.query.filter_by(oauth_provider="google", oauth_provider_id=google_id).first()
    if not user:
        user = User.query.filter(func.lower(User.email) == email).first()

    if user:
        if user.is_suspended:
            return flask_redirect(f"{frontend_url}/login?suspended=true")
        # Update OAuth fields if signing in via Google for the first time on an existing account
        if not user.oauth_provider:
            user.oauth_provider = "google"
            user.oauth_provider_id = google_id
        if avatar_url:
            user.avatar_url = avatar_url
        db.session.commit()
    else:
        # Create new user + org
        user = User(
            email=email,
            name=name,
            password_hash=None,
            oauth_provider="google",
            oauth_provider_id=google_id,
            avatar_url=avatar_url,
        )
        db.session.add(user)
        db.session.flush()

        org_slug = email.split("@")[0].replace(".", "-").replace("_", "-")
        base_slug = org_slug
        counter = 1
        while Organization.query.filter_by(slug=org_slug).first():
            org_slug = f"{base_slug}-{counter}"
            counter += 1

        org = Organization(
            name=f"{name}'s Workspace",
            slug=org_slug,
        )
        db.session.add(org)
        db.session.flush()

        db.session.add(OrganizationMember(
            user_id=user.id,
            organization_id=org.id,
            role="owner",
            joined_at=_now_utc(),
        ))
        db.session.commit()

        log_audit(
            organization_id=org.id,
            user_id=user.id,
            action="auth.register",
            category="auth",
            target_type="user",
            target_id=str(user.id),
            target_label=user.email,
            description=f"User registered via Google OAuth: {user.email}",
            metadata={"provider": "google"},
        )

    is_new = not user.job_title and not user.company and not user.country
    jwt = create_access_token(secret_key=current_app.config["SECRET_KEY"], user_id=user.id)
    import urllib.parse
    return flask_redirect(
        f"{frontend_url}/oauth/callback?token={urllib.parse.quote(jwt)}&next={urllib.parse.quote(next_url)}&new_user={'1' if is_new else '0'}"
    )


@auth_bp.get("/oauth/microsoft")
def oauth_microsoft_start():
    import os, urllib.parse
    client_id = os.environ.get("MICROSOFT_CLIENT_ID", "")
    if not client_id:
        return jsonify(error="Microsoft OAuth is not configured"), 503

    frontend_url = os.environ.get("FRONTEND_URL", "https://nanoasm.com").rstrip("/")
    redirect_uri = f"{frontend_url}/api/auth/oauth/microsoft/callback"

    next_url = request.args.get("next", "/dashboard")
    state = _oauth_state_serializer(current_app.config["SECRET_KEY"]).dumps({"next": next_url})

    params = urllib.parse.urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile User.Read",
        "state": state,
        "response_mode": "query",
        "prompt": "select_account",
    })

    from flask import redirect as flask_redirect
    return flask_redirect(f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{params}")


@auth_bp.get("/oauth/microsoft/callback")
def oauth_microsoft_callback():
    import os, requests as http
    from flask import redirect as flask_redirect

    frontend_url = os.environ.get("FRONTEND_URL", "https://nanoasm.com").rstrip("/")
    error_base = f"{frontend_url}/login?oauth_error="

    raw_state = request.args.get("state", "")
    try:
        state_data = _oauth_state_serializer(current_app.config["SECRET_KEY"]).loads(
            raw_state, max_age=600
        )
        next_url = state_data.get("next", "/dashboard")
    except Exception:
        return flask_redirect(error_base + "invalid_state")

    code = request.args.get("code")
    if not code:
        error = request.args.get("error", "access_denied")
        return flask_redirect(error_base + error)

    client_id = os.environ.get("MICROSOFT_CLIENT_ID", "")
    client_secret = os.environ.get("MICROSOFT_CLIENT_SECRET", "")
    redirect_uri = f"{frontend_url}/api/auth/oauth/microsoft/callback"

    try:
        token_resp = http.post(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
            timeout=10,
        )
        token_resp.raise_for_status()
        tokens = token_resp.json()
    except Exception:
        return flask_redirect(error_base + "token_exchange_failed")

    try:
        userinfo_resp = http.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            timeout=10,
        )
        userinfo_resp.raise_for_status()
        info = userinfo_resp.json()
    except Exception:
        return flask_redirect(error_base + "userinfo_failed")

    ms_id = info.get("id")
    email = (info.get("mail") or info.get("userPrincipalName") or "").strip().lower()
    name = info.get("displayName") or email.split("@")[0]

    if not email or not ms_id:
        return flask_redirect(error_base + "missing_profile")

    from app.models import Organization, OrganizationMember

    user = User.query.filter_by(oauth_provider="microsoft", oauth_provider_id=ms_id).first()
    if not user:
        user = User.query.filter(func.lower(User.email) == email).first()

    if user:
        if user.is_suspended:
            return flask_redirect(f"{frontend_url}/login?suspended=true")
        if not user.oauth_provider:
            user.oauth_provider = "microsoft"
            user.oauth_provider_id = ms_id
        db.session.commit()
    else:
        user = User(
            email=email,
            name=name,
            password_hash=None,
            oauth_provider="microsoft",
            oauth_provider_id=ms_id,
        )
        db.session.add(user)
        db.session.flush()

        org_slug = email.split("@")[0].replace(".", "-").replace("_", "-")
        base_slug = org_slug
        counter = 1
        while Organization.query.filter_by(slug=org_slug).first():
            org_slug = f"{base_slug}-{counter}"
            counter += 1

        org = Organization(name=f"{name}'s Workspace", slug=org_slug)
        db.session.add(org)
        db.session.flush()

        db.session.add(OrganizationMember(
            user_id=user.id,
            organization_id=org.id,
            role="owner",
            joined_at=_now_utc(),
        ))
        db.session.commit()

        log_audit(
            organization_id=org.id,
            user_id=user.id,
            action="auth.register",
            category="auth",
            target_type="user",
            target_id=str(user.id),
            target_label=user.email,
            description=f"User registered via Microsoft OAuth: {user.email}",
            metadata={"provider": "microsoft"},
        )

    is_new = not user.job_title and not user.company and not user.country
    jwt = create_access_token(secret_key=current_app.config["SECRET_KEY"], user_id=user.id)
    import urllib.parse
    return flask_redirect(
        f"{frontend_url}/oauth/callback?token={urllib.parse.quote(jwt)}&next={urllib.parse.quote(next_url)}&new_user={'1' if is_new else '0'}"
    )


@auth_bp.get("/announcements")
@require_auth
def get_announcements():
    """Return active, non-expired announcements visible to the current user's org."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    membership = OrganizationMember.query.filter_by(
        user_id=g.current_user.id, is_active=True
    ).first()
    org_id = membership.organization_id if membership else None

    user_id = g.current_user.id

    q = PlatformAnnouncement.query.filter(
        PlatformAnnouncement.is_active == True,
        db.or_(
            PlatformAnnouncement.expires_at == None,
            PlatformAnnouncement.expires_at > now,
        ),
        # Visibility: user-targeted matches just this user; otherwise fall back
        # to org-targeted (matching their org) or global broadcasts.
        db.or_(
            PlatformAnnouncement.target_user_id == user_id,
            db.and_(
                PlatformAnnouncement.target_user_id == None,
                db.or_(
                    PlatformAnnouncement.target_org_id == None,
                    PlatformAnnouncement.target_org_id == org_id,
                ),
            ),
        ),
    ).order_by(PlatformAnnouncement.created_at.desc())

    anns = q.all()
    return jsonify(announcements=[{
        "id": a.id,
        "title": a.title,
        "body": a.body,
        "kind": a.kind,
        "linkUrl": a.link_url,
        "createdAt": a.created_at.isoformat() + "Z" if a.created_at else None,
    } for a in anns]), 200
