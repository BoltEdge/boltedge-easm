# FILE: app/auth/decorators.py

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from functools import wraps
from typing import Callable, Optional, Tuple

from flask import request, jsonify, g, current_app

from app.models import User, OrganizationMember, Organization, ApiKey
from app.extensions import db
from .tokens import verify_access_token


API_KEY_PREFIX = "ag_sk_"


def get_bearer_token() -> Optional[str]:
    auth = request.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


def _get_api_key_from_request() -> Optional[str]:
    """Read an API key from X-API-Key header or Bearer token (if it has the API-key prefix)."""
    header_key = request.headers.get("X-API-Key")
    if header_key:
        return header_key.strip()
    bearer = get_bearer_token()
    if bearer and bearer.startswith(API_KEY_PREFIX):
        return bearer
    return None


def _authenticate_api_key(raw_key: str) -> Optional[Tuple[User, Organization, OrganizationMember, ApiKey]]:
    """Validate an API key and return (user, org, membership, key) or None."""
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key = ApiKey.query.filter_by(key_hash=key_hash).first()
    if not key or not key.is_active:
        return None

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if key.expires_at and key.expires_at < now:
        return None

    user = key.user
    org = key.organization
    if not user or not org:
        return None
    if user.is_suspended or org.is_suspended:
        return None

    membership = OrganizationMember.query.filter_by(
        user_id=user.id, organization_id=org.id, is_active=True
    ).first()
    if not membership:
        return None

    # Update last_used_at at most once per minute to avoid a write on every request
    if not key.last_used_at or (now - key.last_used_at).total_seconds() > 60:
        try:
            key.last_used_at = now
            db.session.commit()
        except Exception:
            db.session.rollback()

    return user, org, membership, key


def allow_api_key(fn: Callable):
    """Opt this endpoint into API key authentication.

    By default, @require_auth rejects API keys — only endpoints explicitly
    marked with this decorator accept the X-API-Key header. Apply it BELOW
    @require_auth (closer to the view function) so the marker is set on the
    function before require_auth wraps it.

    Example:
        @bp.get("/assets")
        @require_auth
        @allow_api_key
        def list_assets(): ...
    """
    fn._allow_api_key = True
    return fn


def require_auth(fn: Callable):
    api_key_allowed = getattr(fn, "_allow_api_key", False)

    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Try API key first
        raw_api_key = _get_api_key_from_request()
        if raw_api_key:
            if not api_key_allowed:
                return jsonify(
                    error="This endpoint cannot be accessed with an API key. Sign in with your account.",
                    code="API_KEY_NOT_ALLOWED",
                ), 403
            result = _authenticate_api_key(raw_api_key)
            if not result:
                return jsonify(error="invalid or expired API key"), 401
            user, org, membership, key = result
            g.current_user = user
            g.current_user_id = int(user.id)
            g.current_organization = org
            g.current_organization_id = int(org.id)
            g.current_member = membership
            g.current_role = membership.role
            g.auth_method = "api_key"
            g.current_api_key = key
            return fn(*args, **kwargs)

        # Fall back to JWT bearer token
        token = get_bearer_token()
        if not token:
            return jsonify(error="missing Authorization: Bearer <token> or X-API-Key"), 401

        uid = verify_access_token(
            secret_key=current_app.config["SECRET_KEY"], token=token
        )
        if not uid:
            return jsonify(error="invalid or expired token"), 401

        user = User.query.get(uid)
        if not user:
            return jsonify(error="user not found"), 401

        # Get user's organization membership
        membership = OrganizationMember.query.filter_by(
            user_id=user.id,
            is_active=True,
        ).first()

        if not membership:
            return jsonify(error="user not associated with any organization"), 403

        org = membership.organization

        # Store in Flask g context for use in routes and permission decorators
        g.current_user = user
        g.current_user_id = int(user.id)
        g.current_organization = org
        g.current_organization_id = int(org.id)
        g.current_member = membership
        g.current_role = membership.role
        g.auth_method = "jwt"

        return fn(*args, **kwargs)

    return wrapper


# ────────────────────────────────────────────────────────────
# Context helpers
# ────────────────────────────────────────────────────────────

def current_user_id() -> int:
    """Get current user ID from context."""
    return int(getattr(g, "current_user_id", g.current_user.id))


def current_organization_id() -> int:
    """Get current organization ID from context."""
    return int(g.current_organization_id)


def current_role() -> str:
    """Get current user's role in the organization."""
    return str(g.current_role)


# ────────────────────────────────────────────────────────────
# Permission checks — delegates to app.auth.permissions
# ────────────────────────────────────────────────────────────

def has_permission(permission: str) -> bool:
    """
    Check if the current user has a specific permission based on their role.
    Delegates to the full RBAC permission matrix in app.auth.permissions.
    """
    from app.auth.permissions import has_permission as _has_permission
    return _has_permission(current_role(), permission)


def require_permission(permission: str):
    """
    Decorator to require a specific permission.
    Usage: @require_permission("manage_api_keys")
    """
    def decorator(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not has_permission(permission):
                return jsonify(
                    error="You don't have permission to perform this action.",
                    required_permission=permission,
                    your_role=current_role(),
                ), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_superadmin(fn: Callable):
    """
    Decorator for platform admin routes.
    Validates JWT, loads user from DB, checks is_superadmin=True.
    Returns 404 on failure — intentionally does not reveal the route exists.
    Does NOT require org membership (admin operates at platform level).
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = get_bearer_token()
        if not token:
            return jsonify(error="not found"), 404

        uid = verify_access_token(
            secret_key=current_app.config["SECRET_KEY"], token=token
        )
        if not uid:
            return jsonify(error="not found"), 404

        user = User.query.get(uid)
        if not user or not user.is_superadmin:
            return jsonify(error="not found"), 404

        g.current_user = user
        g.current_user_id = int(user.id)

        return fn(*args, **kwargs)

    return wrapper