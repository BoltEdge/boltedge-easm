# FILE: app/auth/decorators.py

from __future__ import annotations

from functools import wraps
from typing import Callable, Optional

from flask import request, jsonify, g, current_app

from app.models import User, OrganizationMember, Organization
from .tokens import verify_access_token


def get_bearer_token() -> Optional[str]:
    auth = request.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


def require_auth(fn: Callable):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = get_bearer_token()
        if not token:
            return jsonify(error="missing Authorization: Bearer <token>"), 401

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