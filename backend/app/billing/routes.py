# =============================================================================
# File: app/billing/routes.py
# Description: Billing & Plan Management routes.
#   6 tiers: free, starter, professional, enterprise_silver, enterprise_gold, custom
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

# Free-upgrade kill switch. While the operator company isn't registered
# for real billing, users can self-serve a 30-day grant of Starter or
# Professional (auto-upgrade) without admin involvement. Higher tiers
# still require contact. Flip to false once real billing is wired and
# the auto-upgrade buttons should disappear from the Plans page.
FREE_UPGRADES_ENABLED = os.environ.get("FREE_UPGRADES_ENABLED", "true").lower() == "true"

# Plans the auto-upgrade endpoint will grant without admin involvement.
# Higher tiers (enterprise_silver / enterprise_gold) are routed through
# the contact form so the operator can decide whether to grant.
AUTO_FREE_UPGRADE_PLANS = {"free", "starter", "professional"}

# Length of each free upgrade grant. Resets on every successful upgrade
# (a user hopping between tiers gets a fresh 30 days each time).
FREE_UPGRADE_DURATION_DAYS = 30
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
# "bestFor" — short positioning sentence for each tier. Surfaced on the
# user-facing Plans page and the Plans API so customers can pick the
# right tier at a glance instead of comparing limit tables. Distinct
# from `label` (the brand name) and `description` (longer marketing
# copy that lives in landing-page UI). Reviewed and tightened May 2026.
PLAN_CONFIG = {
    "free": {
        "label": "Free",
        "bestFor": "Trying it out and evaluating the platform on a couple of assets.",
        "currency": "AUD",
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
            "lookalike_watch_domains": 0,
            "mimic_storage_mb": 0,
            "scan_profiles": ["quick", "standard"],
            "monitoring": False,
            "monitoring_frequency": None,
            "deep_discovery": False,
            "webhooks": False,
            "audit_log": False,
            "leak_detection": False,
            "priority_support": False,
            "white_label": False,
            "onboarding_included": False,
        },
    },
    "starter": {
        "label": "Starter",
        "bestFor": "Individuals, freelance consultants, and small environments.",
        "currency": "AUD",
        "price_monthly": 29,
        "price_annual_monthly": 24,
        "price_annual_total": 288,
        "trial_days": 14,
        "limits": {
            "assets": 15,
            "scans_per_month": 100,
            "discoveries_per_month": 10,
            "monitored_assets": 5,
            "team_members": 3,
            "scheduled_scans": 5,
            "api_keys": 1,
            "lookalike_watch_domains": 1,
            "mimic_storage_mb": 20,
            "scan_profiles": ["quick", "standard", "deep"],
            "monitoring": True,
            "monitoring_frequency": "every_7_days",
            "deep_discovery": False,
            "webhooks": False,
            "audit_log": False,
            "leak_detection": True,
            "priority_support": False,
            "white_label": False,
            "onboarding_included": False,
        },
    },
    "professional": {
        "label": "Professional",
        "bestFor": "Security teams that need continuous monitoring, scheduled reports, and API access.",
        "currency": "AUD",
        "price_monthly": 149,
        "price_annual_monthly": 129,
        "price_annual_total": 1548,
        "trial_days": 21,
        "limits": {
            "assets": 100,
            "scans_per_month": 1000,
            "discoveries_per_month": 50,
            "monitored_assets": 25,
            "team_members": 10,
            "scheduled_scans": 25,
            "api_keys": 5,
            "lookalike_watch_domains": 3,
            "mimic_storage_mb": 100,
            "scan_profiles": ["quick", "standard", "deep"],
            "monitoring": True,
            "monitoring_frequency": "every_3_days",
            "deep_discovery": True,
            "webhooks": True,
            "audit_log": False,
            "leak_detection": True,
            "priority_support": False,
            "white_label": False,
            "onboarding_included": False,
        },
    },
    "enterprise_silver": {
        "label": "Enterprise Silver",
        "bestFor": "MSSPs and consultancies managing several smaller-to-mid-size client environments.",
        "currency": "AUD",
        "price_monthly": 599,
        "price_annual_monthly": 509,
        "price_annual_total": 6108,
        "trial_days": 30,
        "limits": {
            "assets": 10000,
            "scans_per_month": 6000,
            "discoveries_per_month": 200,
            "monitored_assets": 100,
            "team_members": 50,
            "scheduled_scans": 100,
            "api_keys": 10,
            "lookalike_watch_domains": 10,
            "mimic_storage_mb": 500,
            "scan_profiles": ["quick", "standard", "deep"],
            "monitoring": True,
            "monitoring_frequency": "daily",
            "deep_discovery": True,
            "webhooks": True,
            "audit_log": False,
            "leak_detection": True,
            "priority_support": False,
            "white_label": False,
            "onboarding_included": False,
        },
    },
    "enterprise_gold": {
        "label": "Enterprise Gold",
        "bestFor": "MSSPs handling larger client portfolios — adds audit log and priority support.",
        "currency": "AUD",
        # Self-serve top tier — A$999/mo, A$849/mo billed annually
        # (~15% saving). Beyond this, customers go to Custom (sales).
        "price_monthly": 999,
        "price_annual_monthly": 849,
        "price_annual_total": 10188,
        "trial_days": 30,
        "limits": {
            "assets": 20000,
            "scans_per_month": 12000,
            "discoveries_per_month": 400,
            "monitored_assets": 250,
            "team_members": 100,
            "scheduled_scans": 200,
            "api_keys": 20,
            "lookalike_watch_domains": 25,
            "mimic_storage_mb": 2000,
            "scan_profiles": ["quick", "standard", "deep"],
            "monitoring": True,
            "monitoring_frequency": "daily",
            "deep_discovery": True,
            "webhooks": True,
            "audit_log": True,
            "leak_detection": True,
            "priority_support": True,
            "white_label": False,
            "onboarding_included": False,
        },
    },
    "custom": {
        "label": "Custom",
        "bestFor": "Multi-million-asset estates or contracted MSSP delivery with bespoke SLAs and white-labelling.",
        "currency": "AUD",
        # Sales-quoted contract — no public price. The "Contact sales"
        # UI is triggered by price_monthly == -1 throughout the codebase.
        "price_monthly": -1,
        "price_annual_monthly": -1,
        "price_annual_total": -1,
        "trial_days": 0,
        "trial_requires_approval": True,
        "limits": {
            "assets": -1,             # unlimited
            "scans_per_month": -1,    # unlimited (fair use, contract-defined)
            "discoveries_per_month": -1,
            "monitored_assets": -1,
            "team_members": -1,
            "scheduled_scans": -1,
            "api_keys": -1,
            "lookalike_watch_domains": -1,
            "mimic_storage_mb": -1,
            "scan_profiles": ["quick", "standard", "deep", "custom"],
            "monitoring": True,
            "monitoring_frequency": "hourly",  # sub-hourly negotiable per contract
            "deep_discovery": True,
            "webhooks": True,
            "audit_log": True,
            "leak_detection": True,
            "priority_support": True,
            "white_label": True,           # MSSP-friendly rebranding
            "onboarding_included": True,   # dedicated onboarding + training
        },
    },
}

# Plan tier ordering for upgrade/downgrade logic
PLAN_ORDER = ["free", "starter", "professional", "enterprise_silver", "enterprise_gold", "custom"]


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
            "lookalikeWatchDomains": limits.get("lookalike_watch_domains", 0),
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
            "currency": config.get("currency", "AUD"),
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
            "bestFor": config.get("bestFor"),
            "currency": config.get("currency", "AUD"),
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
                "lookalikeWatchDomains": limits.get("lookalike_watch_domains", 0),
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

    # Acknowledgement email so the requester has a record of the
    # request number alongside the in-app confirmation. Best-effort.
    try:
        from app.contact.emails import send_acknowledgement_email
        send_acknowledgement_email(
            to_email=cr.email,
            to_name=cr.name,
            request_id=cr.public_id,
            request_type=cr.request_type,  # "trial"
            subject=cr.subject,
        )
    except Exception:
        logger.exception("Failed to send trial-request acknowledgement to %s", cr.email)

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

    if target_plan == "custom":
        return jsonify(
            error="The Custom plan requires a tailored contract. Please contact sales.",
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

    # Free-upgrade gating. While billing is disabled and free upgrades
    # are enabled, self-serve grants are limited to the Free / Starter /
    # Professional tier set. Higher tiers (Enterprise Silver / Gold)
    # need admin involvement so the operator can decide whether to
    # extend a 30-day grant. Refused with `contactRequired=true` so
    # the frontend can route the visitor to the contact form.
    is_free_upgrade = (not ENABLE_BILLING) and FREE_UPGRADES_ENABLED
    if is_free_upgrade and target_plan not in AUTO_FREE_UPGRADE_PLANS:
        return jsonify(
            error=(
                f"The {config['label']} plan isn't available as a self-serve "
                f"free upgrade yet. Please contact us and we'll grant it manually."
            ),
            contactRequired=True,
            plan=target_plan,
        ), 403

    if not ENABLE_BILLING and not FREE_UPGRADES_ENABLED:
        return jsonify(
            error="Plan upgrades are currently disabled. Please contact us.",
            contactRequired=True,
        ), 403

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
        # Real billing — clear any prior free-upgrade timestamp.
        org.free_upgrade_started_at = None
    elif is_free_upgrade and target_plan != "free":
        # Self-serve free upgrade: grant a fresh 30 days. Stamping
        # free_upgrade_started_at on every grant means a user hopping
        # between tiers always gets a clean 30-day clock — matches the
        # user's "reset on each upgrade" requirement.
        org.plan_expires_at = now + timedelta(days=FREE_UPGRADE_DURATION_DAYS)
        org.free_upgrade_started_at = now
    else:
        org.plan_expires_at = None
        org.free_upgrade_started_at = None

    log_audit(
        organization_id=org.id,
        user_id=current_user_id(),
        action="billing.upgraded",
        category="billing",
        target_type="organization",
        target_id=str(org.id),
        target_label=org.name,
        description=(
            f"Free upgrade to {config['label']} ({FREE_UPGRADE_DURATION_DAYS} days)"
            if is_free_upgrade and target_plan != "free"
            else f"Upgraded to {config['label']} ({billing_cycle})"
        ),
        metadata={
            "old_plan": old_plan,
            "new_plan": target_plan,
            "billing_cycle": billing_cycle,
            "from_trial": old_status == "trialing",
            "free_upgrade": bool(is_free_upgrade and target_plan != "free"),
            "expires_at": org.plan_expires_at.isoformat() if org.plan_expires_at else None,
        },
    )

    db.session.commit()

    # Send confirmation email — best-effort. A failure here doesn't undo
    # the upgrade itself; the user has the upgrade either way.
    if is_free_upgrade and target_plan != "free":
        try:
            from app.billing.emails import send_free_upgrade_confirmation
            send_free_upgrade_confirmation(org, plan_label=config["label"], expires_at=org.plan_expires_at)
        except Exception:
            logger.exception("Free-upgrade confirmation email failed for org %s", org.id)

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

    # Capture the member user ids BEFORE the cascade deletes the
    # OrganizationMember rows. We need this list so we can find any
    # users who'd be left orphaned (no other org membership) and
    # delete them too — otherwise the user row stays in the DB,
    # blocks re-registration on the same email, and shows up in the
    # admin user list as a ghost. Superadmins are never deleted no
    # matter what.
    from app.models import OrganizationMember, User
    member_user_ids = [
        m.user_id for m in OrganizationMember.query.filter_by(organization_id=org_id).all()
    ]

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
    db.session.flush()  # Trigger the FK cascade so the membership-count
                        # check below sees the post-delete state.

    deleted_user_ids: list[int] = []
    for uid in member_user_ids:
        # Any other active membership? Then keep the user.
        other = (
            OrganizationMember.query
            .filter_by(user_id=uid, is_active=True)
            .filter(OrganizationMember.organization_id != org_id)
            .first()
        )
        if other:
            continue
        user = User.query.get(uid)
        if not user:
            continue
        if user.is_superadmin:
            # Superadmin somehow ended up only on this org — leave the
            # account in place and let an admin clean up manually.
            continue
        deleted_user_ids.append(uid)
        db.session.delete(user)

    db.session.commit()

    return jsonify(
        message="Organization deleted.",
        deletedUserCount=len(deleted_user_ids),
    ), 200


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


def check_expired_free_upgrades():
    """Auto-downgrade orgs whose free upgrade has run out.

    Mirrors check_expired_trials() but keys off plan_expires_at
    (set when the user clicked the auto-upgrade button) instead of
    trial_ends_at (set when admin grants a request-based trial).
    Both can co-exist; a single org will only be on one path at a
    time. Best-effort — never raises."""
    if ENABLE_BILLING:
        # Real billing is on — Stripe drives plan_expires_at via
        # subscription events, not the free-upgrade flow. Skip.
        return 0
    now = _now_utc()
    expired_orgs = Organization.query.filter(
        Organization.plan_status == "active",
        Organization.plan != "free",
        Organization.plan_expires_at != None,  # noqa: E711
        Organization.plan_expires_at <= now,
    ).all()

    for org in expired_orgs:
        old_plan = org.plan
        org.plan = "free"
        org.plan_status = "active"
        org.plan_started_at = now
        org.plan_expires_at = None
        org.free_upgrade_started_at = None
        org.billing_cycle = None
        org.asset_limit = PLAN_CONFIG["free"]["limits"]["assets"]

        log_audit(
            organization_id=org.id,
            user_id=None,
            action="billing.free_upgrade_expired",
            category="billing",
            target_type="organization",
            target_id=str(org.id),
            target_label=org.name,
            description=(
                f"Free upgrade expired for {PLAN_CONFIG.get(old_plan, {}).get('label', old_plan)}, "
                f"downgraded to Free"
            ),
            metadata={"expired_plan": old_plan},
        )

    if expired_orgs:
        db.session.commit()

    return len(expired_orgs)


def send_free_upgrade_expiry_warnings():
    """Send T-5 and T-1 day warning emails for active free upgrades.

    Idempotency: this runs hourly, so each org could receive a given
    warning up to 24 times before expiry. We dedupe by stamping a
    flag on the audit log — checked via the most recent
    `billing.free_upgrade_warning_sent` audit row for the org. Cheap
    and avoids a new column."""
    if ENABLE_BILLING:
        return 0
    from datetime import timedelta as _td
    from app.models import AuditLog
    from app.billing.emails import send_free_upgrade_warning

    now = _now_utc()
    sent = 0

    # Pull all orgs whose plan_expires_at falls in the next 5 days
    # (catches both T-5 and T-1 windows; the per-window dedupe is
    # done below via the audit-log lookup).
    upcoming_orgs = Organization.query.filter(
        Organization.plan_status == "active",
        Organization.plan != "free",
        Organization.plan_expires_at != None,  # noqa: E711
        Organization.plan_expires_at > now,
        Organization.plan_expires_at <= now + _td(days=6),
    ).all()

    for org in upcoming_orgs:
        days_remaining = (org.plan_expires_at - now).days
        # Decide which window we're in. T-5 fires once when there's
        # exactly 4 or 5 days left; T-1 fires once when there's 0 or
        # 1 day left. Hourly schedule means we sweep every hour, so
        # we use the audit log to ensure each window only sends once
        # per upgrade grant.
        window = None
        if 4 <= days_remaining <= 5:
            window = "t5"
        elif 0 <= days_remaining <= 1:
            window = "t1"
        if window is None:
            continue

        # Dedupe: skip if we already sent this window's warning since
        # the most recent free_upgrade_started_at.
        since = org.free_upgrade_started_at or now - _td(days=60)
        already_sent = AuditLog.query.filter(
            AuditLog.organization_id == org.id,
            AuditLog.action == "billing.free_upgrade_warning_sent",
            AuditLog.created_at >= since,
        ).all()
        if any((a.metadata_json or {}).get("window") == window for a in already_sent):
            continue

        config = PLAN_CONFIG.get(org.plan, {})
        ok = send_free_upgrade_warning(
            org,
            plan_label=config.get("label", org.plan),
            expires_at=org.plan_expires_at,
            days_remaining=days_remaining,
        )
        if ok:
            sent += 1
            log_audit(
                organization_id=org.id,
                user_id=None,
                action="billing.free_upgrade_warning_sent",
                category="billing",
                target_type="organization",
                target_id=str(org.id),
                target_label=org.name,
                description=f"Free-upgrade expiry warning ({window.upper()}) sent to org",
                metadata={"window": window, "days_remaining": days_remaining,
                          "plan": org.plan, "expires_at": org.plan_expires_at.isoformat()},
            )

    if sent:
        db.session.commit()
    return sent


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
        "https://nanoeasm.com/settings/billing?checkout=success",
    )


def _cancel_url() -> str:
    return os.environ.get(
        "STRIPE_CANCEL_URL",
        "https://nanoeasm.com/settings/billing?checkout=cancel",
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

    if target_plan == "custom":
        return jsonify(
            error="The Custom plan requires a tailored contract. Please contact sales.",
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
        "https://nanoeasm.com/settings/billing",
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