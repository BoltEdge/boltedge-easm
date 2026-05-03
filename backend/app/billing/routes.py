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

import logging
import os
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify, g

# When False: upgrades are free (no expiry set), trial logic skipped in UI.
# Set ENABLE_BILLING=true in environment to restore full billing behaviour.
ENABLE_BILLING = os.environ.get("ENABLE_BILLING", "false").lower() == "true"
from app.extensions import db
from app.auth.decorators import require_auth, current_user_id, current_organization_id
from app.models import Organization, TrialHistory, OrganizationMember, Asset
from app.auth.permissions import require_permission
from app.audit.routes import log_audit
from . import stripe_service, stripe_webhook

logger = logging.getLogger(__name__)

billing_bp = Blueprint("billing", __name__, url_prefix="/billing")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ════════════════════════════════════════════════════════════════
# PLAN CONFIGURATION — single source of truth
# ════════════════════════════════════════════════════════════════

# Plan tiers — see CLAUDE.md "Cost rationale" before adjusting any number.
# Real cost levers are `scans_per_month` (covers manual + monitoring), the
# product of `monitored_assets` × `monitoring_frequency`, and
# `discoveries_per_month`. `assets` is just inventory and cheap.
PLAN_CONFIG = {
    "free": {
        "label": "Free",
        "price_monthly": 0,
        "price_annual_monthly": 0,
        "price_annual_total": 0,
        "trial_days": 0,
        "limits": {
            "assets": 2,
            "scans_per_month": 5,
            "discoveries_per_month": 2,
            "monitored_assets": 0,
            "team_members": 1,
            "scheduled_scans": 1,
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
            "scans_per_month": 100,
            "discoveries_per_month": 10,
            "monitored_assets": 5,
            "team_members": 5,
            "scheduled_scans": 5,
            "api_keys": 3,
            "scan_profiles": ["quick", "standard", "deep"],
            "monitoring": True,
            "monitoring_frequency": "every_7_days",
            "deep_discovery": False,
            "webhooks": False,
        },
    },
    "professional": {
        "label": "Professional",
        "price_monthly": 99,
        "price_annual_monthly": 79,
        "price_annual_total": 948,
        "trial_days": 21,
        "limits": {
            "assets": 100,
            "scans_per_month": 1000,
            "discoveries_per_month": 50,
            "monitored_assets": 25,
            "team_members": 20,
            "scheduled_scans": 25,
            "api_keys": 10,
            "scan_profiles": ["quick", "standard", "deep"],
            "monitoring": True,
            "monitoring_frequency": "every_3_days",
            "deep_discovery": True,
            "webhooks": True,
        },
    },
    "enterprise_silver": {
        "label": "Enterprise Silver",
        "price_monthly": 499,
        "price_annual_monthly": 399,
        "price_annual_total": 4788,
        "trial_days": 30,
        "limits": {
            "assets": 5000,
            "scans_per_month": 6000,
            "discoveries_per_month": 200,
            "monitored_assets": 100,
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
        # Sales-priced — no public anchor. The "Contact sales" UI is
        # triggered by price_monthly == -1 throughout the codebase.
        "price_monthly": -1,
        "price_annual_monthly": -1,
        "price_annual_total": -1,
        "trial_days": 45,  # sales approval required
        "trial_requires_approval": True,
        "limits": {
            "assets": 10000,
            # Soft "fair use" cap — anything beyond is a separate sales contract.
            "scans_per_month": 50000,
            "discoveries_per_month": -1,
            "monitored_assets": 500,
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
    """Get the limits that should actually be enforced for an org.
    Plan defaults are merged with any per-org overrides set by a superadmin.
    Overrides take precedence for numeric limits; plan still controls feature flags.
    """
    effective = org.effective_plan
    limits = dict(get_plan_limits(effective))  # copy so we don't mutate the config

    overrides = org.limit_overrides or {}
    for key in ("assets", "scans_per_month", "discoveries_per_month", "monitored_assets",
                "team_members", "scheduled_scans", "api_keys",
                "monitoring", "deep_discovery", "webhooks"):
        if key in overrides:
            limits[key] = overrides[key]

    return limits


# ════════════════════════════════════════════════════════════════
# HELPER: Build plan response payload
# ════════════════════════════════════════════════════════════════

def _discovery_jobs_this_month(org_id: int) -> int:
    """Live count of discovery jobs created in the current calendar month."""
    from app.models import DiscoveryJob
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    first_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return DiscoveryJob.query.filter(
        DiscoveryJob.organization_id == org_id,
        DiscoveryJob.created_at >= first_of_month,
    ).count()


def _monitored_assets_count(org_id: int) -> int:
    """Live count of enabled monitors (each monitor = one monitored asset/group)."""
    from app.models import Monitor
    return Monitor.query.filter_by(organization_id=org_id, enabled=True).count()


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
            "discoveriesPerMonth": limits.get("discoveries_per_month", -1),
            "monitoredAssets": limits.get("monitored_assets", 0),
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
            # Live count — Organization.assets_count cache is unreliable.
            "assets": Asset.query.filter_by(organization_id=org.id).count(),
            "scansThisMonth": org.scans_this_month,
            "discoveriesThisMonth": _discovery_jobs_this_month(org.id),
            "monitoredAssets": _monitored_assets_count(org.id),
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
#
# Despite the name, this endpoint NEVER auto-grants a trial. It creates a
# typed contact_request that admins review and approve manually. The
# response tells the user their request is queued and that they'll be
# emailed when the decision is made.
#
# Why: self-serve trials were a real abuse vector ("sign up, scan, leave").
# Going through admin review for every trial — including enterprise — adds
# a small amount of friction in exchange for much better quality control.
@billing_bp.post("/start-trial")
@require_auth
@require_permission("manage_billing")
def start_trial():
    from app.models import ContactRequest

    body = request.get_json(silent=True) or {}
    target_plan = (body.get("plan") or "").strip().lower()

    if target_plan not in PLAN_CONFIG or target_plan == "free":
        return jsonify(error="Invalid plan tier."), 400

    org = g.current_organization
    user = g.current_user
    config = PLAN_CONFIG[target_plan]

    # Hard guards — surface specific errors so the UI can explain.
    existing_trial = TrialHistory.query.filter_by(
        organization_id=org.id, plan=target_plan
    ).first()
    if existing_trial:
        return jsonify(
            error=f"Your organization has already used the {config['label']} trial.",
            code="TRIAL_ALREADY_USED",
        ), 409

    if org.plan_status == "active" and org.plan != "free":
        return jsonify(
            error="You're already on a paid plan. Downgrade to Free first, or contact us to switch tiers.",
            code="ALREADY_PAID",
        ), 400

    if org.plan_status == "trialing":
        return jsonify(
            error="You're already in a trial. Wait for it to end or cancel it first.",
            code="ALREADY_TRIALING",
        ), 400

    # Soft de-dupe — if there's already an open trial request for this plan
    # from this org, bounce them with a friendly message instead of stacking.
    existing_request = ContactRequest.query.filter(
        ContactRequest.email == user.email,
        ContactRequest.request_type == "trial",
        ContactRequest.status.in_(("open", "in_progress")),
        ContactRequest.message.ilike(f"%{target_plan}%"),
    ).first()
    if existing_request:
        return jsonify(
            message=(
                f"Your {config['label']} trial request is already under review. "
                f"We'll email {user.email} once a decision is made."
            ),
            requestId=existing_request.public_id,
            alreadyRequested=True,
        ), 200

    # Submit the request as a contact_request so it shows up alongside other
    # support traffic in /admin/contact-requests.
    org_label = f"{org.name} ({org.public_id or '#' + str(org.id)})"
    cr = ContactRequest(
        name=user.name or user.email,
        email=user.email,
        subject=f"Trial request: {config['label']} — {org.name}",
        message=(
            f"{user.name or user.email} has requested a free trial of the "
            f"{config['label']} plan.\n\n"
            f"Organisation: {org_label}\n"
            f"Current plan: {org.plan}\n"
            f"Requested plan key: {target_plan}\n\n"
            f"Decide the trial duration when granting. "
            f"Approve from the admin panel by upgrading their org plan, "
            f"then reply here so they know it's active."
        ),
        request_type="trial",
        status="open",
        created_at=_now_utc(),
        updated_at=_now_utc(),
    )
    db.session.add(cr)

    log_audit(
        organization_id=org.id,
        user_id=current_user_id(),
        action="billing.trial_requested",
        category="billing",
        target_type="organization",
        target_id=str(org.id),
        target_label=org.name,
        description=f"Requested free trial of {config['label']}",
        metadata={
            "current_plan": org.plan,
            "requested_plan": target_plan,
        },
    )

    db.session.commit()

    return jsonify(
        message=(
            f"Your {config['label']} trial request has been submitted. "
            f"We'll review it and email {user.email} once it's approved — usually "
            f"within one business day."
        ),
        requestId=cr.public_id,
        requested=True,
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
    org.billing_cycle = billing_cycle if ENABLE_BILLING else None
    org.asset_limit = config["limits"]["assets"]

    if ENABLE_BILLING:
        if billing_cycle == "annual":
            org.plan_expires_at = now + timedelta(days=365)
        else:
            org.plan_expires_at = now + timedelta(days=30)
    else:
        org.plan_expires_at = None  # no expiry when billing is disabled

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


# ════════════════════════════════════════════════════════════════
# STRIPE — Checkout, Portal, Webhook, Subscription status
# ════════════════════════════════════════════════════════════════
#
# All Stripe-backed endpoints early-return 503 when ENABLE_BILLING=false
# so the community-preview free-upgrade flow keeps working unchanged.
# The /upgrade endpoint above is preserved for that flow — Stripe never
# touches it.

def _billing_disabled_response():
    return jsonify(
        error="Stripe billing is currently disabled.",
        billingEnabled=False,
    ), 503


def _success_url() -> str:
    return os.environ.get(
        "STRIPE_SUCCESS_URL",
        "https://nanoasm.com/settings/billing?checkout=success",
    )


def _cancel_url() -> str:
    return os.environ.get(
        "STRIPE_CANCEL_URL",
        "https://nanoasm.com/settings/billing?checkout=cancel",
    )


# POST /billing/checkout — admin+ (manage_billing)
# Creates a Stripe-hosted Checkout Session for the requested plan and
# billing cycle, then returns the URL the client should redirect to.
@billing_bp.post("/checkout")
@require_auth
@require_permission("manage_billing")
def create_checkout():
    if not ENABLE_BILLING:
        return _billing_disabled_response()

    body = request.get_json(silent=True) or {}
    target_plan = (body.get("plan") or "").strip().lower()
    billing_cycle = (body.get("billingCycle") or "monthly").strip().lower()

    if billing_cycle not in ("monthly", "annual"):
        return jsonify(error="billingCycle must be 'monthly' or 'annual'."), 400

    if target_plan == "enterprise_gold":
        return jsonify(
            error="Enterprise Gold requires a custom agreement. Please contact sales.",
            contactSales=True,
        ), 403

    if target_plan not in PLAN_CONFIG or target_plan == "free":
        return jsonify(error="Invalid plan tier."), 400

    price_id = stripe_service.plan_to_price(target_plan, billing_cycle)
    if not price_id:
        logger.error(
            "No Stripe price configured for plan=%s cycle=%s", target_plan, billing_cycle
        )
        return jsonify(
            error="This plan is not yet available for purchase. Please contact us.",
        ), 503

    org = g.current_organization
    user = g.current_user

    try:
        session = stripe_service.create_checkout_session(
            price_id=price_id,
            customer_id=org.stripe_customer_id,
            customer_email=org.billing_email or user.email,
            organization_id=org.id,
            success_url=_success_url(),
            cancel_url=_cancel_url(),
            billing_cycle=billing_cycle,
        )
    except Exception as e:
        logger.exception("Stripe checkout session creation failed.")
        return jsonify(error="Could not start checkout. Please try again."), 502

    log_audit(
        organization_id=org.id,
        user_id=current_user_id(),
        action="billing.checkout_started",
        category="billing",
        target_type="organization",
        target_id=str(org.id),
        target_label=org.name,
        description=f"Started Stripe Checkout for {target_plan} ({billing_cycle})",
        metadata={
            "plan": target_plan,
            "billing_cycle": billing_cycle,
            "session_id": session.get("id"),
        },
    )

    return jsonify(
        url=session["url"],
        sessionId=session["id"],
    ), 200


# POST /billing/portal — admin+ (manage_billing)
# Returns a one-shot Stripe Customer Portal URL for managing payment
# method, viewing invoices, and cancelling.
@billing_bp.post("/portal")
@require_auth
@require_permission("manage_billing")
def create_portal():
    if not ENABLE_BILLING:
        return _billing_disabled_response()

    org = g.current_organization
    if not org.stripe_customer_id:
        return jsonify(
            error="No Stripe customer for this organisation yet. Subscribe first."
        ), 400

    return_url = os.environ.get(
        "STRIPE_PORTAL_RETURN_URL",
        "https://nanoasm.com/settings/billing",
    )

    try:
        session = stripe_service.create_portal_session(
            customer_id=org.stripe_customer_id,
            return_url=return_url,
        )
    except Exception:
        logger.exception("Stripe portal session creation failed.")
        return jsonify(error="Could not open billing portal. Please try again."), 502

    return jsonify(url=session["url"]), 200


# GET /billing/subscription — all roles
# Lightweight subscription status for the post-checkout success poll.
# Frontend hits this every 2s for ~30s after the redirect to detect
# when the webhook lands.
@billing_bp.get("/subscription")
@require_auth
def get_subscription_status():
    org = g.current_organization
    return jsonify({
        "plan": org.plan,
        "planStatus": org.plan_status,
        "billingCycle": org.billing_cycle,
        "stripeCustomerId": org.stripe_customer_id,
        "stripeSubscriptionId": org.stripe_subscription_id,
        "subscriptionStatus": org.stripe_subscription_status,
        "cancelAtPeriodEnd": org.cancel_at_period_end,
        "currentPeriodStart": (
            org.current_period_start.isoformat() + "Z"
            if org.current_period_start else None
        ),
        "currentPeriodEnd": (
            org.current_period_end.isoformat() + "Z"
            if org.current_period_end else None
        ),
        "billingEnabled": ENABLE_BILLING,
    }), 200


# POST /billing/stripe-webhook — NO normal auth.
#
# Authentication for this endpoint is the Stripe-Signature header,
# verified against STRIPE_WEBHOOK_SECRET. Anyone can hit the URL but
# only Stripe can produce a valid signature.
#
# The handler is idempotent: each Stripe event_id is recorded in
# `stripe_event` and skipped on redelivery.
@billing_bp.post("/stripe-webhook")
def stripe_webhook_endpoint():
    if not ENABLE_BILLING:
        # Don't even verify when billing is off — Stripe shouldn't be
        # configured to send to this URL in that mode.
        return jsonify(error="Stripe billing is disabled."), 503

    payload = request.get_data()
    signature = request.headers.get("Stripe-Signature", "")

    event, status, _msg = stripe_webhook.verify_and_log_event(payload, signature)
    if status != 200:
        return jsonify(received=False), status
    if event is None:
        # Duplicate event — already processed.
        return jsonify(received=True, duplicate=True), 200

    event_id = event["id"]
    try:
        stripe_webhook.dispatch(event)
        db.session.commit()
        stripe_webhook.mark_event_processed(event_id)
    except Exception as e:
        db.session.rollback()
        logger.exception(
            "Stripe webhook handler failed (event=%s, type=%s).",
            event_id, event.get("type"),
        )
        stripe_webhook.mark_event_processed(event_id, error=str(e))
        # Return 500 so Stripe retries the delivery.
        return jsonify(received=False, error="handler failed"), 500

    return jsonify(received=True), 200