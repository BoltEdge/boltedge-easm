# =============================================================================
# File: app/billing/routes.py
# Description: Billing & Plan Management routes.
#   5 tiers: free, starter, professional, enterprise_silver, enterprise_gold
#   Trial support: one free trial per paid tier per organization
#   Stripe-ready: stub endpoints designed for future Stripe integration
#
# Permissions Integration (based on permissions integration guide):
#   - GET /billing/plan: all roles can view
#   - GET /billing/plans: all roles can view
#   - POST /billing/start-trial: admin+ (manage_billing permission)
#   - POST /billing/upgrade: admin+ (manage_billing permission)
#   - POST /billing/downgrade: admin+ (manage_billing permission)
#   - POST /billing/cancel: admin+ (manage_billing permission)
#   - DELETE /billing/organization: owner only (delete_organization permission)
#   - check_expired_trials(): background job, no auth needed
# =============================================================================

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify, g
from app.extensions import db
from app.auth.decorators import require_auth, current_user_id, current_organization_id
from app.models import Organization, TrialHistory, OrganizationMember
from app.auth.permissions import require_permission
from app.audit.routes import log_audit

billing_bp = Blueprint("billing", __name__, url_prefix="/billing")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ════════════════════════════════════════════════════════════════
# PLAN CONFIGURATION — single source of truth
# ════════════════════════════════════════════════════════════════

PLAN_CONFIG = {
    "free": {
        "label": "Free",
        "price_monthly": 0,
        "price_annual_monthly": 0,
        "price_annual_total": 0,
        "trial_days": 0,
        "limits": {
            "assets": 2,
            "scans_per_month": 4,
            "team_members": 1,
            "scheduled_scans": 2,
            "api_keys": 1,
            "scan_profiles": ["quick", "standard"],
            "monitoring": False,
            "monitoring_frequency": None,
            "deep_discovery": False,
            "webhooks": False,
        },
    },
    "starter": {
        "label": "Starter",
        "price_monthly": 19,
        "price_annual_monthly": 15,
        "price_annual_total": 180,
        "trial_days": 14,
        "limits": {
            "assets": 15,
            "scans_per_month": 500,
            "team_members": 5,
            "scheduled_scans": 10,
            "api_keys": 3,
            "scan_profiles": ["quick", "standard", "deep"],
            "monitoring": True,
            "monitoring_frequency": "every_5_days",
            "deep_discovery": False,
            "webhooks": False,
        },
    },
    "professional": {
        "label": "Professional",
        "price_monthly": 79,
        "price_annual_monthly": 63,
        "price_annual_total": 756,
        "trial_days": 21,
        "limits": {
            "assets": 100,
            "scans_per_month": 5000,
            "team_members": 20,
            "scheduled_scans": 50,
            "api_keys": 10,
            "scan_profiles": ["quick", "standard", "deep"],
            "monitoring": True,
            "monitoring_frequency": "every_2_days",
            "deep_discovery": True,
            "webhooks": True,
        },
    },
    "enterprise_silver": {
        "label": "Enterprise Silver",
        "price_monthly": 249,
        "price_annual_monthly": 199,
        "price_annual_total": 2388,
        "trial_days": 30,
        "limits": {
            "assets": 15000,
            "scans_per_month": -1,  # -1 = unlimited
            "team_members": 100,
            "scheduled_scans": 100,
            "api_keys": -1,
            "scan_profiles": ["quick", "standard", "deep"],
            "monitoring": True,
            "monitoring_frequency": "daily",
            "deep_discovery": True,
            "webhooks": True,
        },
    },
    "enterprise_gold": {
        "label": "Enterprise Gold",
        "price_monthly": -1,  # -1 = contact sales
        "price_annual_monthly": -1,
        "price_annual_total": -1,
        "trial_days": 45,  # sales approval required
        "trial_requires_approval": True,
        "limits": {
            "assets": 50000,
            "scans_per_month": -1,
            "team_members": -1,
            "scheduled_scans": -1,
            "api_keys": -1,
            "scan_profiles": ["quick", "standard", "deep", "custom"],
            "monitoring": True,
            "monitoring_frequency": "every_12_hours",
            "deep_discovery": True,
            "webhooks": True,
        },
    },
}

# Plan tier ordering for upgrade/downgrade logic
PLAN_ORDER = ["free", "starter", "professional", "enterprise_silver", "enterprise_gold"]


def get_plan_limits(plan_key: str) -> dict:
    """Get limits for a plan tier. Falls back to free if unknown."""
    config = PLAN_CONFIG.get(plan_key, PLAN_CONFIG["free"])
    return config["limits"]


def get_effective_limits(org: Organization) -> dict:
    """Get the limits that should actually be enforced for an org."""
    effective = org.effective_plan
    return get_plan_limits(effective)


# ════════════════════════════════════════════════════════════════
# HELPER: Build plan response payload
# ════════════════════════════════════════════════════════════════

def _build_plan_response(org: Organization) -> dict:
    """Build comprehensive plan info for the frontend."""
    effective = org.effective_plan
    config = PLAN_CONFIG.get(effective, PLAN_CONFIG["free"])
    limits = config["limits"]

    # Current usage counts
    member_count = OrganizationMember.query.filter_by(
        organization_id=org.id, is_active=True
    ).count()

    from app.models import ScanSchedule, ApiKey
    schedule_count = ScanSchedule.query.filter_by(
        organization_id=org.id, enabled=True
    ).count()
    api_key_count = ApiKey.query.filter_by(
        organization_id=org.id, is_active=True
    ).count()

    # Trial info
    trial_info = None
    if org.plan_status == "trialing" and org.trial_ends_at:
        remaining = (org.trial_ends_at - _now_utc()).total_seconds()
        trial_info = {
            "plan": org.plan,
            "endsAt": org.trial_ends_at.isoformat() + "Z",
            "daysRemaining": max(0, int(remaining / 86400)),
            "expired": remaining <= 0,
        }

    # Which tiers have been trialed
    trialed_tiers = [
        th.plan for th in TrialHistory.query.filter_by(organization_id=org.id).all()
    ]

    return {
        "plan": effective,
        "planLabel": config["label"],
        "planStatus": org.plan_status,
        "billingCycle": org.billing_cycle,
        "planStartedAt": org.plan_started_at.isoformat() + "Z" if org.plan_started_at else None,
        "planExpiresAt": org.plan_expires_at.isoformat() + "Z" if org.plan_expires_at else None,
        "trial": trial_info,
        "trialedTiers": trialed_tiers,
        "limits": {
            "assets": limits["assets"],
            "scansPerMonth": limits["scans_per_month"],
            "teamMembers": limits["team_members"],
            "scheduledScans": limits["scheduled_scans"],
            "apiKeys": limits["api_keys"],
            "scanProfiles": limits["scan_profiles"],
            "monitoring": limits["monitoring"],
            "monitoringFrequency": limits["monitoring_frequency"],
            "deepDiscovery": limits["deep_discovery"],
            "webhooks": limits["webhooks"],
        },
        "usage": {
            "assets": org.assets_count,
            "scansThisMonth": org.scans_this_month,
            "teamMembers": member_count,
            "scheduledScans": schedule_count,
            "apiKeys": api_key_count,
        },
        "pricing": {
            "monthly": config["price_monthly"],
            "annualMonthly": config["price_annual_monthly"],
            "annualTotal": config["price_annual_total"],
        },
    }


# ════════════════════════════════════════════════════════════════
# ENDPOINTS
# ════════════════════════════════════════════════════════════════

# GET /billing/plan — all roles can view
@billing_bp.get("/plan")
@require_auth
def get_plan():
    org = g.current_organization
    return jsonify(_build_plan_response(org)), 200


# GET /billing/plans — all roles can view
@billing_bp.get("/plans")
@require_auth
def list_plans():
    org = g.current_organization
    trialed_tiers = [
        th.plan for th in TrialHistory.query.filter_by(organization_id=org.id).all()
    ]

    plans = []
    for key in PLAN_ORDER:
        config = PLAN_CONFIG[key]
        limits = config["limits"]
        plans.append({
            "key": key,
            "label": config["label"],
            "priceMonthly": config["price_monthly"],
            "priceAnnualMonthly": config["price_annual_monthly"],
            "priceAnnualTotal": config["price_annual_total"],
            "trialDays": config["trial_days"],
            "trialRequiresApproval": config.get("trial_requires_approval", False),
            "canTrial": key != "free" and key not in trialed_tiers,
            "isCurrent": org.effective_plan == key,
            "limits": {
                "assets": limits["assets"],
                "scansPerMonth": limits["scans_per_month"],
                "teamMembers": limits["team_members"],
                "scheduledScans": limits["scheduled_scans"],
                "apiKeys": limits["api_keys"],
                "scanProfiles": limits["scan_profiles"],
                "monitoring": limits["monitoring"],
                "monitoringFrequency": limits["monitoring_frequency"],
                "deepDiscovery": limits["deep_discovery"],
                "webhooks": limits["webhooks"],
            },
        })

    return jsonify(plans=plans, currentPlan=org.effective_plan), 200


# POST /billing/start-trial — admin+ (manage_billing permission)
@billing_bp.post("/start-trial")
@require_auth
@require_permission("manage_billing")
def start_trial():
    body = request.get_json(silent=True) or {}
    target_plan = (body.get("plan") or "").strip().lower()

    if target_plan not in PLAN_CONFIG or target_plan == "free":
        return jsonify(error="Invalid plan tier."), 400

    org = g.current_organization
    config = PLAN_CONFIG[target_plan]

    if config.get("trial_requires_approval"):
        return jsonify(
            error="Enterprise Gold trials require sales approval. Please contact sales.",
            contactSales=True,
        ), 403

    existing_trial = TrialHistory.query.filter_by(
        organization_id=org.id, plan=target_plan
    ).first()
    if existing_trial:
        return jsonify(error=f"Your organization has already used the {config['label']} trial."), 409

    if org.plan_status == "active" and org.plan != "free":
        return jsonify(error="You're already on a paid plan. Downgrade to Free first, or upgrade directly."), 400

    if org.plan_status == "trialing":
        return jsonify(error="You're already in a trial. Wait for it to end or cancel it first."), 400

    trial_days = config["trial_days"]
    now = _now_utc()
    old_plan = org.plan

    org.plan = target_plan
    org.plan_status = "trialing"
    org.plan_started_at = now
    org.trial_ends_at = now + timedelta(days=trial_days)
    org.plan_expires_at = org.trial_ends_at
    org.asset_limit = config["limits"]["assets"]

    trial_record = TrialHistory(
        organization_id=org.id,
        plan=target_plan,
        started_at=now,
        trial_days=trial_days,
    )
    db.session.add(trial_record)

    log_audit(
        organization_id=org.id,
        user_id=current_user_id(),
        action="billing.trial_started",
        category="billing",
        target_type="organization",
        target_id=str(org.id),
        target_label=org.name,
        description=f"Started {config['label']} trial ({trial_days} days)",
        metadata={"old_plan": old_plan, "new_plan": target_plan, "trial_days": trial_days},
    )

    db.session.commit()

    return jsonify(
        message=f"{config['label']} trial started! You have {trial_days} days.",
        plan=_build_plan_response(org),
    ), 200


# POST /billing/upgrade — admin+ (manage_billing permission)
@billing_bp.post("/upgrade")
@require_auth
@require_permission("manage_billing")
def upgrade():
    body = request.get_json(silent=True) or {}
    target_plan = (body.get("plan") or "").strip().lower()
    billing_cycle = (body.get("billingCycle") or "monthly").strip().lower()

    if target_plan not in PLAN_CONFIG or target_plan == "free":
        return jsonify(error="Invalid plan tier."), 400

    if billing_cycle not in ("monthly", "annual"):
        return jsonify(error="billingCycle must be 'monthly' or 'annual'."), 400

    config = PLAN_CONFIG[target_plan]

    if target_plan == "enterprise_gold":
        return jsonify(
            error="Enterprise Gold requires a custom agreement. Please contact sales.",
            contactSales=True,
        ), 403

    org = g.current_organization
    now = _now_utc()
    old_plan = org.plan
    old_status = org.plan_status

    if org.plan_status == "trialing" and org.plan == target_plan:
        trial_record = TrialHistory.query.filter_by(
            organization_id=org.id, plan=target_plan
        ).first()
        if trial_record:
            trial_record.outcome = "converted"
            trial_record.ended_at = now

    org.plan = target_plan
    org.plan_status = "active"
    org.plan_started_at = now
    org.trial_ends_at = None
    org.billing_cycle = billing_cycle
    org.asset_limit = config["limits"]["assets"]

    if billing_cycle == "annual":
        org.plan_expires_at = now + timedelta(days=365)
    else:
        org.plan_expires_at = now + timedelta(days=30)

    log_audit(
        organization_id=org.id,
        user_id=current_user_id(),
        action="billing.upgraded",
        category="billing",
        target_type="organization",
        target_id=str(org.id),
        target_label=org.name,
        description=f"Upgraded to {config['label']} ({billing_cycle})",
        metadata={"old_plan": old_plan, "new_plan": target_plan, "billing_cycle": billing_cycle, "from_trial": old_status == "trialing"},
    )

    db.session.commit()

    return jsonify(
        message=f"Upgraded to {config['label']}!",
        plan=_build_plan_response(org),
    ), 200


# POST /billing/downgrade — admin+ (manage_billing permission)
@billing_bp.post("/downgrade")
@require_auth
@require_permission("manage_billing")
def downgrade():
    org = g.current_organization
    now = _now_utc()

    old_plan = org.plan
    old_status = org.plan_status

    if org.plan_status == "trialing":
        trial_record = TrialHistory.query.filter_by(
            organization_id=org.id, plan=org.plan
        ).first()
        if trial_record and not trial_record.outcome:
            trial_record.outcome = "cancelled"
            trial_record.ended_at = now

    org.plan = "free"
    org.plan_status = "active"
    org.plan_started_at = now
    org.plan_expires_at = None
    org.trial_ends_at = None
    org.billing_cycle = None
    org.asset_limit = PLAN_CONFIG["free"]["limits"]["assets"]

    log_audit(
        organization_id=org.id,
        user_id=current_user_id(),
        action="billing.downgraded",
        category="billing",
        target_type="organization",
        target_id=str(org.id),
        target_label=org.name,
        description=f"Downgraded from {PLAN_CONFIG.get(old_plan, {}).get('label', old_plan)} to Free",
        metadata={"old_plan": old_plan, "was_trialing": old_status == "trialing"},
    )

    db.session.commit()

    return jsonify(
        message=f"Downgraded from {PLAN_CONFIG.get(old_plan, {}).get('label', old_plan)} to Free.",
        plan=_build_plan_response(org),
    ), 200


# POST /billing/cancel — admin+ (manage_billing permission)
@billing_bp.post("/cancel")
@require_auth
@require_permission("manage_billing")
def cancel():
    org = g.current_organization

    if org.plan == "free":
        return jsonify(error="You're already on the Free plan."), 400

    now = _now_utc()
    old_plan = org.plan
    old_status = org.plan_status

    if org.plan_status == "trialing":
        trial_record = TrialHistory.query.filter_by(
            organization_id=org.id, plan=org.plan
        ).first()
        if trial_record and not trial_record.outcome:
            trial_record.outcome = "cancelled"
            trial_record.ended_at = now

        org.plan = "free"
        org.plan_status = "active"
        org.trial_ends_at = None
        org.plan_expires_at = None
        org.billing_cycle = None
        org.asset_limit = PLAN_CONFIG["free"]["limits"]["assets"]
    else:
        org.plan_status = "cancelled"

    log_audit(
        organization_id=org.id,
        user_id=current_user_id(),
        action="billing.cancelled",
        category="billing",
        target_type="organization",
        target_id=str(org.id),
        target_label=org.name,
        description=f"Cancelled {PLAN_CONFIG.get(old_plan, {}).get('label', old_plan)} subscription",
        metadata={"plan": old_plan, "was_trialing": old_status == "trialing"},
    )

    db.session.commit()

    return jsonify(
        message="Subscription cancelled.",
        plan=_build_plan_response(org),
    ), 200


# DELETE /billing/organization — owner only (delete_organization permission)
@billing_bp.delete("/organization")
@require_auth
@require_permission("delete_organization")
def delete_organization():
    org = g.current_organization
    org_name = org.name
    org_id = org.id

    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="billing.organization_deleted",
        category="billing",
        target_type="organization",
        target_id=str(org_id),
        target_label=org_name,
        description=f"Deleted organization '{org_name}'",
    )

    db.session.delete(org)
    db.session.commit()

    return jsonify(message="Organization deleted."), 200


# ════════════════════════════════════════════════════════════════
# TRIAL EXPIRY CHECK (called by background scheduler)
# ════════════════════════════════════════════════════════════════

def check_expired_trials():
    now = _now_utc()
    expired_orgs = Organization.query.filter(
        Organization.plan_status == "trialing",
        Organization.trial_ends_at <= now,
    ).all()

    for org in expired_orgs:
        old_plan = org.plan

        trial_record = TrialHistory.query.filter_by(
            organization_id=org.id, plan=org.plan
        ).first()
        if trial_record and not trial_record.outcome:
            trial_record.outcome = "expired"
            trial_record.ended_at = now

        org.plan = "free"
        org.plan_status = "active"
        org.trial_ends_at = None
        org.plan_expires_at = None
        org.billing_cycle = None
        org.asset_limit = PLAN_CONFIG["free"]["limits"]["assets"]

        log_audit(
            organization_id=org.id,
            user_id=None,
            action="billing.trial_expired",
            category="billing",
            target_type="organization",
            target_id=str(org.id),
            target_label=org.name,
            description=f"Trial expired for {PLAN_CONFIG.get(old_plan, {}).get('label', old_plan)}, downgraded to Free",
            metadata={"expired_plan": old_plan},
        )

    if expired_orgs:
        db.session.commit()

    return len(expired_orgs)