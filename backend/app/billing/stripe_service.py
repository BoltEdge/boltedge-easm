"""
Thin wrapper around the Stripe SDK.

Centralises every direct call to `stripe.*` so the rest of the app
never imports the SDK directly. That gives us:

  * One place to set the API key from env
  * One place to map our plan keys ↔ Stripe Price IDs
  * One place to translate raw Stripe dicts into the shape our app uses
  * Clean failure modes when ENABLE_BILLING=false (no SDK calls at all)

Phase 1 surface:
  - init_stripe()                  — set api_key from env once at import
  - is_billing_enabled()           — single source of truth for the feature flag
  - get_publishable_price_map()    — plan_key → {monthly, annual} price IDs
  - plan_to_price(plan, cycle)     — resolve to a single price ID
  - price_to_plan(price_id)        — reverse lookup (used in webhooks)
  - create_checkout_session(...)   — returns hosted Checkout URL
  - create_portal_session(...)     — returns hosted Customer Portal URL
  - get_subscription(sub_id)       — fetch + return Stripe Subscription
"""
from __future__ import annotations

import logging
import os
from typing import Optional

import stripe


logger = logging.getLogger(__name__)


# ── Feature flag ─────────────────────────────────────────────────────
def is_billing_enabled() -> bool:
    """Single source of truth for whether Stripe is wired up."""
    return os.environ.get("ENABLE_BILLING", "false").lower() == "true"


# ── SDK initialisation ───────────────────────────────────────────────
_initialised = False


def init_stripe() -> None:
    """
    Set the Stripe API key from STRIPE_SECRET_KEY. Idempotent — safe to
    call multiple times. Called lazily before any SDK access.

    Does nothing when ENABLE_BILLING=false so the SDK never makes a
    network call in community-preview mode.
    """
    global _initialised
    if _initialised:
        return
    if not is_billing_enabled():
        return

    secret_key = os.environ.get("STRIPE_SECRET_KEY", "").strip()
    if not secret_key:
        logger.warning(
            "ENABLE_BILLING=true but STRIPE_SECRET_KEY is not set — "
            "Stripe API calls will fail."
        )
        return

    stripe.api_key = secret_key
    # 2025-09-30 is the latest pinned API version we tested against.
    stripe.api_version = os.environ.get("STRIPE_API_VERSION", "2025-09-30.clover")
    _initialised = True


# ── Plan ↔ Price mapping ─────────────────────────────────────────────
# Each plan key maps to two env-driven price IDs (monthly + annual).
# Update the env, not this dict, when prices change in the Stripe
# dashboard.
_PLAN_ENV_KEYS: dict[str, dict[str, str]] = {
    "starter": {
        "monthly": "STRIPE_PRICE_STARTER_MONTHLY",
        "annual":  "STRIPE_PRICE_STARTER_ANNUAL",
    },
    "professional": {
        "monthly": "STRIPE_PRICE_PRO_MONTHLY",
        "annual":  "STRIPE_PRICE_PRO_ANNUAL",
    },
    "enterprise_silver": {
        "monthly": "STRIPE_PRICE_SILVER_MONTHLY",
        "annual":  "STRIPE_PRICE_SILVER_ANNUAL",
    },
    # enterprise_gold is sales-priced — no public Stripe price; admin
    # creates a one-off Stripe Invoice manually after the contract is signed.
}


def get_price_map() -> dict[str, dict[str, Optional[str]]]:
    """plan_key → {'monthly': price_..., 'annual': price_...}, env-resolved."""
    out: dict[str, dict[str, Optional[str]]] = {}
    for plan, cycles in _PLAN_ENV_KEYS.items():
        out[plan] = {
            cycle: os.environ.get(env_key) or None
            for cycle, env_key in cycles.items()
        }
    return out


def plan_to_price(plan_key: str, billing_cycle: str) -> Optional[str]:
    """Resolve `(plan, monthly|annual)` to a Stripe Price ID via env."""
    cycles = _PLAN_ENV_KEYS.get(plan_key)
    if not cycles:
        return None
    env_key = cycles.get(billing_cycle)
    if not env_key:
        return None
    price = os.environ.get(env_key)
    return price.strip() if price else None


def price_to_plan(price_id: str) -> Optional[tuple[str, str]]:
    """Reverse lookup: Stripe Price ID → (plan_key, billing_cycle)."""
    if not price_id:
        return None
    for plan, cycles in _PLAN_ENV_KEYS.items():
        for cycle, env_key in cycles.items():
            if os.environ.get(env_key) == price_id:
                return plan, cycle
    return None


# ── Checkout & Portal sessions ───────────────────────────────────────
def create_checkout_session(
    *,
    price_id: str,
    customer_id: Optional[str],
    customer_email: Optional[str],
    organization_id: int,
    success_url: str,
    cancel_url: str,
    billing_cycle: str,
) -> stripe.checkout.Session:
    """
    Create a Stripe-hosted Checkout Session for a subscription.

    Returns the Session object — caller redirects the browser to
    `session.url`. All card collection and 3DS/SCA happen on Stripe's
    domain; nothing sensitive ever touches our servers.

    `organization_id` and `billing_cycle` are stamped into
    `client_reference_id` and `metadata` so webhook handlers can map
    the resulting subscription back to our DB row.
    """
    init_stripe()

    kwargs: dict = {
        "mode": "subscription",
        "line_items": [{"price": price_id, "quantity": 1}],
        "success_url": success_url,
        "cancel_url": cancel_url,
        "client_reference_id": str(organization_id),
        "metadata": {
            "organization_id": str(organization_id),
            "billing_cycle": billing_cycle,
        },
        "subscription_data": {
            "metadata": {
                "organization_id": str(organization_id),
                "billing_cycle": billing_cycle,
            },
        },
        # Let Stripe collect tax IDs from EU/UK businesses.
        "tax_id_collection": {"enabled": True},
        "billing_address_collection": "auto",
        "allow_promotion_codes": True,
    }

    # Reuse the same Stripe Customer for repeat checkouts so the org's
    # payment-method history stays on one object.
    if customer_id:
        kwargs["customer"] = customer_id
        kwargs["customer_update"] = {"address": "auto", "name": "auto"}
    elif customer_email:
        kwargs["customer_email"] = customer_email

    return stripe.checkout.Session.create(**kwargs)


def create_portal_session(*, customer_id: str, return_url: str) -> stripe.billing_portal.Session:
    """
    Create a Stripe Customer Portal session — self-serve UI for payment
    method updates, invoice history, and cancellation.

    Configure what the portal exposes in:
        Stripe dashboard → Settings → Billing → Customer portal
    """
    init_stripe()
    return stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=return_url,
    )


# ── Subscription helpers ─────────────────────────────────────────────
def get_subscription(subscription_id: str) -> Optional[stripe.Subscription]:
    """Fetch a Stripe Subscription. Returns None if not found."""
    init_stripe()
    try:
        return stripe.Subscription.retrieve(subscription_id)
    except stripe.error.InvalidRequestError:
        return None


def construct_event(payload: bytes, signature: str, secret: str) -> stripe.Event:
    """
    Verify a webhook signature and return the parsed Event object.

    Raises:
        stripe.error.SignatureVerificationError — bad/missing signature
        ValueError                              — malformed payload
    """
    init_stripe()
    return stripe.Webhook.construct_event(payload, signature, secret)
