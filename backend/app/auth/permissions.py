# FILE: app/auth/permissions.py
# ═══════════════════════════════════════════════════════════════════
# Plan Limit Enforcement + RBAC Role-Based Access Control
# ═══════════════════════════════════════════════════════════════════
#
# Two enforcement systems that work together:
#
# 1. PLAN LIMITS  — what the organization's plan allows
#    Decorators: @check_limit("assets"), @require_feature("monitoring")
#
# 2. RBAC ROLES   — what the user's role allows within the org
#    Decorator: @require_role("admin"), @require_role("analyst")
#
# Usage in routes:
#
#   @app.post("/groups/<gid>/assets")
#   @require_auth
#   @require_role("analyst")       # analyst, admin, owner can create
#   @check_limit("assets")         # enforces plan asset limit
#   def add_asset(gid):
#       ...
#
#   @app.post("/monitoring/monitors")
#   @require_auth
#   @require_role("analyst")
#   @require_feature("monitoring")  # only paid plans with monitoring
#   def create_monitor():
#       ...

from __future__ import annotations

from functools import wraps
from flask import g, jsonify, request
from app.extensions import db


# ════════════════════════════════════════════════════════════════════
# RBAC: Role Permission Matrix
# ════════════════════════════════════════════════════════════════════
#
# Hierarchy: owner > admin > analyst > viewer
# Each role inherits all permissions of roles below it.

ROLE_HIERARCHY = ["viewer", "analyst", "admin", "owner"]

ROLE_PERMISSIONS = {
    "viewer": {
        # View-only access across the board
        "view_assets",
        "view_groups",
        "view_findings",
        "view_scans",
        "view_schedules",
        "view_monitoring",
        "view_alerts",
        "view_settings",
        "view_members",
        "view_api_keys",
        "view_billing",
        "view_discovery",
    },
    "analyst": {
        # Inherits all viewer permissions, plus:
        # Assets (single operations only — no groups, no bulk)
        "create_assets",
        "edit_assets",
        "delete_assets",
        # Scanning (single scans only — no bulk scan)
        "start_scans",
        "delete_scans",
        "create_schedules",
        "edit_schedules",
        "delete_schedules",
        # Findings
        "edit_findings",           # ignore/unignore/acknowledge
        # Discovery
        "run_discovery",
        # Monitoring
        "create_monitors",
        "edit_monitors",
        "delete_monitors",
        "acknowledge_alerts",
        "set_alert_verdict",
        "close_alerts",
        "create_tuning_rules",
        "edit_tuning_rules",
        # Settings
        "configure_scan_settings",
    },
    "admin": {
        # Inherits all analyst permissions, plus:
        # Groups (admin+ only)
        "create_groups",
        "edit_groups",
        "delete_groups",
        # Bulk operations (admin+ only)
        "bulk_add_assets",
        "bulk_scan",
        # Exports (admin+ only)
        "export_assets",
        "export_alerts",
        "export_scan_results",
        "export_discovery_results",
        # Audit (admin+ only)
        "view_audit_log",
        "export_audit_log",
        # Users
        "invite_users",
        "remove_users",
        "manage_roles",            # can change roles (except cannot touch owner)
        # API Keys
        "manage_api_keys",         # create/revoke API keys
        # Settings
        "configure_integrations",  # webhooks, external tools
        # Billing (admin + owner)
        "manage_billing",          # upgrade, downgrade, start/end trial
    },
    "owner": {
        # Inherits all admin permissions, plus:
        "edit_organization",       # org name, country — owner only
        "delete_organization",
        "transfer_ownership",
        "manage_all_roles",        # can promote to admin, demote admin
    },
}

def _get_all_permissions(role: str) -> set[str]:
    """Get the full set of permissions for a role, including inherited ones."""
    idx = ROLE_HIERARCHY.index(role) if role in ROLE_HIERARCHY else -1
    if idx < 0:
        return set()
    perms = set()
    for i in range(idx + 1):
        r = ROLE_HIERARCHY[i]
        perms |= ROLE_PERMISSIONS.get(r, set())
    return perms


def has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission."""
    return permission in _get_all_permissions(role)


def has_minimum_role(user_role: str, minimum_role: str) -> bool:
    """Check if user_role meets or exceeds minimum_role in the hierarchy."""
    if user_role not in ROLE_HIERARCHY or minimum_role not in ROLE_HIERARCHY:
        return False
    return ROLE_HIERARCHY.index(user_role) >= ROLE_HIERARCHY.index(minimum_role)


def get_user_role(member) -> str:
    """Get the role string from a member object. Compatibility helper."""
    if not member:
        return "viewer"
    if isinstance(member, str):
        return member
    return getattr(member, "role", "viewer")


# ════════════════════════════════════════════════════════════════════
# RBAC Decorators
# ════════════════════════════════════════════════════════════════════

def require_role(minimum_role: str):
    """
    Decorator: reject request if user's role is below the minimum.

    Usage:
        @require_auth
        @require_role("analyst")
        def my_endpoint():
            ...

    Depends on require_auth having set g.current_member.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            member = getattr(g, "current_member", None)
            if not member:
                return jsonify(error="Not authenticated or no organization membership."), 401

            if not has_minimum_role(member.role, minimum_role):
                return jsonify(
                    error="Insufficient permissions.",
                    required_role=minimum_role,
                    your_role=member.role,
                ), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_permission(permission: str):
    """
    Decorator: reject request if user's role doesn't include a specific permission.

    Usage:
        @require_auth
        @require_permission("manage_api_keys")
        def create_api_key():
            ...
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            member = getattr(g, "current_member", None)
            if not member:
                return jsonify(error="Not authenticated or no organization membership."), 401

            if not has_permission(member.role, permission):
                return jsonify(
                    error="You don't have permission to perform this action.",
                    required_permission=permission,
                    your_role=member.role,
                ), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ════════════════════════════════════════════════════════════════════
# PLAN LIMITS: Configuration (imported from billing)
# ════════════════════════════════════════════════════════════════════

def _get_plan_limits(org) -> dict:
    """Get the effective plan limits for an organization."""
    from app.billing.routes import get_effective_limits
    return get_effective_limits(org)


def _get_current_usage(org, resource: str) -> int:
    """
    Get current usage count for a resource.
    Queries the actual DB so enforcement is always accurate.
    """
    from app.models import (
        Asset, ScanJob, ScanSchedule, ApiKey,
        OrganizationMember,
    )

    if resource == "assets":
        return Asset.query.join(
            Asset.group
        ).filter(
            Asset.group.has(organization_id=org.id)
        ).count()

    elif resource == "scans_per_month":
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        first_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return ScanJob.query.join(
            Asset, ScanJob.asset_id == Asset.id
        ).filter(
            Asset.organization_id == org.id,
            ScanJob.created_at >= first_of_month,
        ).count()

    elif resource == "scheduled_scans":
        return ScanSchedule.query.filter_by(
            organization_id=org.id,
            enabled=True,
        ).count()

    elif resource == "api_keys":
        return ApiKey.query.filter_by(
            organization_id=org.id,
            is_active=True,
        ).count()

    elif resource == "team_members":
        return OrganizationMember.query.filter_by(
            organization_id=org.id,
            is_active=True,
        ).count()

    return 0


# ════════════════════════════════════════════════════════════════════
# Plan Limit Decorators
# ════════════════════════════════════════════════════════════════════

def check_limit(resource: str):
    """
    Decorator: reject request if org has reached plan limit for a resource.

    Supported resources:
        "assets", "scans_per_month", "scheduled_scans", "api_keys", "team_members"

    Usage:
        @require_auth
        @check_limit("assets")
        def add_asset():
            ...

    Returns 403 with limit info so the frontend can show an upgrade prompt.
    A limit value of -1 means unlimited.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            org = getattr(g, "current_organization", None)
            if not org:
                return jsonify(error="No organization context."), 401

            limits = _get_plan_limits(org)
            limit_value = limits.get(resource)

            if limit_value is None:
                # Unknown resource — allow (don't block on misconfiguration)
                return fn(*args, **kwargs)

            # -1 = unlimited
            if limit_value == -1:
                return fn(*args, **kwargs)

            current = _get_current_usage(org, resource)

            if current >= limit_value:
                # Map resource key to human-readable name
                resource_labels = {
                    "assets": "assets",
                    "scans_per_month": "scans this month",
                    "scheduled_scans": "scheduled scans",
                    "api_keys": "API keys",
                    "team_members": "team members",
                }
                label = resource_labels.get(resource, resource)

                return jsonify(
                    error=f"Plan limit reached: {label}.",
                    code="PLAN_LIMIT_REACHED",
                    resource=resource,
                    limit=limit_value,
                    current=current,
                    plan=org.effective_plan,
                    upgrade_url="/settings/billing",
                ), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_feature(feature: str):
    """
    Decorator: reject request if the org's plan doesn't include a feature.

    Supported features:
        "monitoring", "deep_discovery", "webhooks"

    Usage:
        @require_auth
        @require_feature("monitoring")
        def create_monitor():
            ...
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            org = getattr(g, "current_organization", None)
            if not org:
                return jsonify(error="No organization context."), 401

            limits = _get_plan_limits(org)
            enabled = limits.get(feature, False)

            if not enabled:
                return jsonify(
                    error=f"Feature not available on your plan: {feature}.",
                    code="FEATURE_NOT_AVAILABLE",
                    feature=feature,
                    plan=org.effective_plan,
                    upgrade_url="/settings/billing",
                ), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def check_scan_profile(profile_id_param: str = "profileId"):
    """
    Decorator: reject request if the scan profile isn't allowed on the org's plan.

    Usage:
        @require_auth
        @check_scan_profile()
        def create_scan_job():
            ...

    Reads the profile ID from the JSON body or route kwargs.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            org = getattr(g, "current_organization", None)
            if not org:
                return jsonify(error="No organization context."), 401

            # Get profile ID from body or kwargs
            body = request.get_json(silent=True) or {}
            pid = body.get(profile_id_param) or kwargs.get(profile_id_param)

            if not pid:
                # No profile specified — allow (will use default)
                return fn(*args, **kwargs)

            # Look up the profile
            from app.models import ScanProfile
            profile = ScanProfile.query.get(pid)
            if not profile:
                return fn(*args, **kwargs)  # let the endpoint handle 404

            # Check if profile type is allowed
            limits = _get_plan_limits(org)
            allowed_profiles = limits.get("scan_profiles", [])
            profile_type = (profile.name or "").lower()

            # Match profile name against allowed list
            # Allowed values: "quick", "standard", "deep", "custom"
            profile_key = None
            if "deep" in profile_type:
                profile_key = "deep"
            elif "standard" in profile_type:
                profile_key = "standard"
            elif "quick" in profile_type:
                profile_key = "quick"
            else:
                profile_key = "custom"

            if profile_key not in allowed_profiles:
                return jsonify(
                    error=f"Scan profile '{profile.name}' is not available on your plan.",
                    code="PROFILE_NOT_AVAILABLE",
                    profile=profile.name,
                    allowed_profiles=allowed_profiles,
                    plan=org.effective_plan,
                    upgrade_url="/settings/billing",
                ), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ════════════════════════════════════════════════════════════════════
# Combined decorator for common patterns
# ════════════════════════════════════════════════════════════════════

def require_role_and_limit(minimum_role: str, resource: str):
    """
    Combined decorator: check both role AND plan limit.

    Usage:
        @require_auth
        @require_role_and_limit("analyst", "assets")
        def add_asset():
            ...
    """
    def decorator(fn):
        @wraps(fn)
        @require_role(minimum_role)
        @check_limit(resource)
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_role_and_feature(minimum_role: str, feature: str):
    """
    Combined decorator: check both role AND feature availability.

    Usage:
        @require_auth
        @require_role_and_feature("analyst", "monitoring")
        def create_monitor():
            ...
    """
    def decorator(fn):
        @wraps(fn)
        @require_role(minimum_role)
        @require_feature(feature)
        def wrapper(*args, **kwargs):
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ════════════════════════════════════════════════════════════════════
# Helper: Get user's permission set (for /settings/me endpoint)
# ════════════════════════════════════════════════════════════════════

def get_permissions_for_role(role: str) -> dict[str, bool]:
    """
    Returns a dict of permission keys -> bool for the frontend.
    Used by the /settings/me endpoint so the UI knows what to show/hide.
    """
    all_perms = _get_all_permissions(role)
    return {
        # Assets
        "view_assets": "view_assets" in all_perms,
        "create_assets": "create_assets" in all_perms,
        "edit_assets": "edit_assets" in all_perms,
        "delete_assets": "delete_assets" in all_perms,
        # Groups
        "view_groups": "view_groups" in all_perms,
        "create_groups": "create_groups" in all_perms,
        "edit_groups": "edit_groups" in all_perms,
        "delete_groups": "delete_groups" in all_perms,
        # Bulk operations
        "bulk_add_assets": "bulk_add_assets" in all_perms,
        "bulk_scan": "bulk_scan" in all_perms,
        # Scanning
        "start_scans": "start_scans" in all_perms,
        "delete_scans": "delete_scans" in all_perms,
        "create_schedules": "create_schedules" in all_perms,
        "edit_schedules": "edit_schedules" in all_perms,
        "delete_schedules": "delete_schedules" in all_perms,
        "configure_scan_settings": "configure_scan_settings" in all_perms,
        # Findings
        "edit_findings": "edit_findings" in all_perms,
        # Discovery
        "run_discovery": "run_discovery" in all_perms,
        # Monitoring
        "view_monitoring": "view_monitoring" in all_perms,
        "create_monitors": "create_monitors" in all_perms,
        "edit_monitors": "edit_monitors" in all_perms,
        "delete_monitors": "delete_monitors" in all_perms,
        "acknowledge_alerts": "acknowledge_alerts" in all_perms,
        "set_alert_verdict": "set_alert_verdict" in all_perms,
        "close_alerts": "close_alerts" in all_perms,
        "create_tuning_rules": "create_tuning_rules" in all_perms,
        "edit_tuning_rules": "edit_tuning_rules" in all_perms,
        # Users
        "invite_users": "invite_users" in all_perms,
        "remove_users": "remove_users" in all_perms,
        "manage_roles": "manage_roles" in all_perms,
        # API Keys
        "manage_api_keys": "manage_api_keys" in all_perms,
        # Settings
        "edit_organization": "edit_organization" in all_perms,
        "configure_integrations": "configure_integrations" in all_perms,
        "view_audit_log": "view_audit_log" in all_perms,
        "export_audit_log": "export_audit_log" in all_perms,
        # Exports
        "export_assets": "export_assets" in all_perms,
        "export_alerts": "export_alerts" in all_perms,
        "export_scan_results": "export_scan_results" in all_perms,
        "export_discovery_results": "export_discovery_results" in all_perms,
        # Billing
        "manage_billing": "manage_billing" in all_perms,
        "delete_organization": "delete_organization" in all_perms,
        "transfer_ownership": "transfer_ownership" in all_perms,
    }