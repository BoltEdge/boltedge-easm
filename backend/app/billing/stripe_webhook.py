"""
Stripe webhook dispatcher.

Stripe POSTs every billing event to one URL on our backend. This
module:

  1. Verifies the request came from Stripe (signature check).
  2. Records every received event in `stripe_event` so a redelivery
     can be detected and skipped (idempotency).
  3. Routes the event to a handler that updates our `Organization`
     row and writes a `BillingEvent` audit row.

Webhooks are the *source of truth* for subscription state — never
trust the success_url alone, and never write subscription state
from frontend-initiated requests.

Phase 1 events:
  - checkout.session.completed
  - customer.subscription.created
  - customer.subscription.updated
  - customer.subscription.deleted
  - invoice.payment_succeeded
  - invoice.payment_failed
  - customer.updated
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

from flask import current_app

from app.extensions import db
from app.models import BillingEvent, Organization, StripeEvent

from . import stripe_service


logger = logging.getLogger(__name__)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _from_unix(ts: Optional[int]) -> Optional[datetime]:
    """Stripe timestamps are unix seconds; we store naive UTC."""
    if not ts:
        return None
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).replace(tzinfo=None)


# ─────────────────────────────────────────────────────────────────────
# Verification + idempotency
# ─────────────────────────────────────────────────────────────────────

def verify_and_log_event(payload: bytes, signature: str) -> tuple[Optional[dict], int, str]:
    """
    Verify signature, dedupe on stripe_id, persist to stripe_event.

    Returns (event_dict, status_code, message). If status_code is non-2xx
    the caller should return that response without further processing.
    A 200 with event_dict=None means "duplicate, already handled".
    """
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "").strip()
    if not secret:
        logger.error("STRIPE_WEBHOOK_SECRET is not configured.")
        return None, 503, "webhook not configured"

    try:
        event = stripe_service.construct_event(payload, signature, secret)
    except ValueError:
        return None, 400, "invalid payload"
    except Exception:  # SignatureVerificationError or anything else
        # Don't log the signature header — that's the secret-equivalent.
        logger.warning("Stripe webhook signature verification failed.")
        return None, 400, "invalid signature"

    event_id = event["id"]
    event_type = event["type"]

    # Idempotency — was this event already received?
    existing = StripeEvent.query.filter_by(stripe_id=event_id).first()
    if existing and existing.processed_at is not None:
        logger.info("Skipping duplicate Stripe event %s (%s).", event_id, event_type)
        return None, 200, "duplicate"

    if existing is None:
        log = StripeEvent(
            stripe_id=event_id,
            type=event_type,
            received_at=_now_utc(),
            payload=event,
        )
        db.session.add(log)
        db.session.commit()

    # Convert stripe.Event to a plain dict so the handlers don't depend
    # on the SDK object shape.
    return dict(event), 200, "accepted"


def mark_event_processed(event_id: str, error: Optional[str] = None) -> None:
    """Stamp `processed_at` (or `error`) on the stripe_event row."""
    log = StripeEvent.query.filter_by(stripe_id=event_id).first()
    if not log:
        return
    if error:
        log.error = error[:5000]
    else:
        log.processed_at = _now_utc()
    db.session.commit()


# ─────────────────────────────────────────────────────────────────────
# Handlers
# ─────────────────────────────────────────────────────────────────────

def _find_org_by_customer(customer_id: Optional[str]) -> Optional[Organization]:
    if not customer_id:
        return None
    return Organization.query.filter_by(stripe_customer_id=customer_id).first()


def _find_org_by_subscription(subscription_id: Optional[str]) -> Optional[Organization]:
    if not subscription_id:
        return None
    return Organization.query.filter_by(stripe_subscription_id=subscription_id).first()


def _find_org_for_event(obj: dict) -> Optional[Organization]:
    """
    Find the Organization for any Stripe object. Tries (in order):

      1. metadata.organization_id   — set on Checkout/Subscription create
      2. client_reference_id        — set on Checkout
      3. customer + stripe_customer_id lookup
      4. subscription + stripe_subscription_id lookup
    """
    # 1. metadata
    metadata = obj.get("metadata") or {}
    org_id = metadata.get("organization_id")
    if org_id:
        try:
            org = Organization.query.get(int(org_id))
            if org:
                return org
        except (ValueError, TypeError):
            pass

    # 2. client_reference_id (Checkout Session)
    client_ref = obj.get("client_reference_id")
    if client_ref:
        try:
            org = Organization.query.get(int(client_ref))
            if org:
                return org
        except (ValueError, TypeError):
            pass

    # 3. customer
    customer_id = obj.get("customer")
    if isinstance(customer_id, dict):
        customer_id = customer_id.get("id")
    org = _find_org_by_customer(customer_id)
    if org:
        return org

    # 4. subscription
    subscription_id = obj.get("subscription")
    if isinstance(subscription_id, dict):
        subscription_id = subscription_id.get("id")
    return _find_org_by_subscription(subscription_id)


def _apply_subscription_state(org: Organization, sub: dict, *, default_cycle: Optional[str] = None) -> None:
    """
    Mirror a Stripe Subscription object onto Organization columns.

    Used by both `customer.subscription.created` and `.updated`. Only
    touches columns we own; never overwrites org.plan with an unknown
    price.
    """
    org.stripe_subscription_id = sub.get("id") or org.stripe_subscription_id
    org.stripe_subscription_status = sub.get("status") or org.stripe_subscription_status
    org.cancel_at_period_end = bool(sub.get("cancel_at_period_end"))
    org.current_period_start = _from_unix(sub.get("current_period_start")) or org.current_period_start
    org.current_period_end = _from_unix(sub.get("current_period_end")) or org.current_period_end

    if sub.get("default_payment_method"):
        pm = sub["default_payment_method"]
        org.default_payment_method = pm if isinstance(pm, str) else pm.get("id")

    # Map Stripe Price ID → plan key
    items = (sub.get("items") or {}).get("data") or []
    price_id = None
    if items:
        price_id = (items[0].get("price") or {}).get("id")

    if price_id:
        mapping = stripe_service.price_to_plan(price_id)
        if mapping:
            plan_key, cycle = mapping
            org.plan = plan_key
            org.billing_cycle = cycle
        elif default_cycle:
            org.billing_cycle = default_cycle

    # Mirror Stripe status onto our plan_status field for UI convenience.
    status_map = {
        "active": "active",
        "trialing": "trialing",
        "past_due": "past_due",
        "canceled": "cancelled",
        "incomplete": "incomplete",
        "incomplete_expired": "expired",
        "unpaid": "past_due",
    }
    if sub.get("status") in status_map:
        org.plan_status = status_map[sub["status"]]


def _record_billing_event(
    *,
    org: Organization,
    kind: str,
    description: str,
    amount_cents: Optional[int] = None,
    currency: Optional[str] = None,
    stripe_object_id: Optional[str] = None,
) -> None:
    db.session.add(BillingEvent(
        organization_id=org.id,
        kind=kind,
        amount_cents=amount_cents,
        currency=(currency or "usd").lower()[:3] if currency else None,
        description=description[:500],
        stripe_object_id=stripe_object_id,
        created_at=_now_utc(),
    ))


# ── checkout.session.completed ──
def handle_checkout_completed(obj: dict) -> None:
    """
    Fired when a user finishes Stripe-hosted Checkout. The Subscription
    already exists by this point — we attach customer_id + subscription_id
    to our Organization and let `customer.subscription.created` fill in
    the rest of the state.
    """
    org = _find_org_for_event(obj)
    if not org:
        logger.warning(
            "checkout.session.completed for unknown org (session=%s)",
            obj.get("id"),
        )
        return

    customer_id = obj.get("customer")
    subscription_id = obj.get("subscription")

    if isinstance(customer_id, dict):
        customer_id = customer_id.get("id")
    if isinstance(subscription_id, dict):
        subscription_id = subscription_id.get("id")

    if customer_id:
        org.stripe_customer_id = customer_id
    if subscription_id:
        org.stripe_subscription_id = subscription_id

    cycle = (obj.get("metadata") or {}).get("billing_cycle")
    if cycle in ("monthly", "annual"):
        org.billing_cycle = cycle

    customer_details = obj.get("customer_details") or {}
    if customer_details.get("email"):
        org.billing_email = customer_details["email"]

    _record_billing_event(
        org=org,
        kind="subscription_created",
        description="Subscription started via Checkout.",
        stripe_object_id=subscription_id,
    )


# ── customer.subscription.created / .updated ──
def handle_subscription_upserted(obj: dict) -> None:
    org = _find_org_for_event(obj)
    if not org:
        logger.warning(
            "subscription event for unknown org (sub=%s)", obj.get("id")
        )
        return

    cycle = (obj.get("metadata") or {}).get("billing_cycle")
    _apply_subscription_state(org, obj, default_cycle=cycle)

    if obj.get("status") in ("active", "trialing"):
        # Successful state — clear any prior expiry.
        org.plan_expires_at = org.current_period_end


# ── customer.subscription.deleted ──
def handle_subscription_deleted(obj: dict) -> None:
    org = _find_org_for_event(obj)
    if not org:
        return

    org.stripe_subscription_status = "canceled"
    org.cancel_at_period_end = False
    # Drop to Free plan — limits enforced by effective_plan.
    org.plan = "free"
    org.plan_status = "active"
    org.billing_cycle = None
    org.plan_expires_at = None

    _record_billing_event(
        org=org,
        kind="subscription_canceled",
        description="Subscription ended.",
        stripe_object_id=obj.get("id"),
    )


# ── invoice.payment_succeeded ──
def handle_invoice_paid(obj: dict) -> None:
    org = _find_org_for_event(obj)
    if not org:
        return

    amount = obj.get("amount_paid")
    currency = obj.get("currency")

    _record_billing_event(
        org=org,
        kind="payment_succeeded",
        description=(
            f"Payment of {(amount or 0) / 100:.2f} {(currency or 'usd').upper()} succeeded."
        ),
        amount_cents=amount,
        currency=currency,
        stripe_object_id=obj.get("id"),
    )

    # If we were past_due, recover.
    if org.stripe_subscription_status == "past_due":
        org.stripe_subscription_status = "active"
        org.plan_status = "active"


# ── invoice.payment_failed ──
def handle_invoice_failed(obj: dict) -> None:
    org = _find_org_for_event(obj)
    if not org:
        return

    org.stripe_subscription_status = "past_due"
    org.plan_status = "past_due"

    amount = obj.get("amount_due")
    currency = obj.get("currency")

    _record_billing_event(
        org=org,
        kind="payment_failed",
        description=(
            f"Payment of {(amount or 0) / 100:.2f} {(currency or 'usd').upper()} failed."
        ),
        amount_cents=amount,
        currency=currency,
        stripe_object_id=obj.get("id"),
    )


# ── customer.updated ──
def handle_customer_updated(obj: dict) -> None:
    org = _find_org_for_event(obj)
    if not org:
        return
    if obj.get("email"):
        org.billing_email = obj["email"]


# ─────────────────────────────────────────────────────────────────────
# Dispatch table
# ─────────────────────────────────────────────────────────────────────

HANDLERS = {
    "checkout.session.completed":    handle_checkout_completed,
    "customer.subscription.created": handle_subscription_upserted,
    "customer.subscription.updated": handle_subscription_upserted,
    "customer.subscription.deleted": handle_subscription_deleted,
    "invoice.payment_succeeded":     handle_invoice_paid,
    "invoice.payment_failed":        handle_invoice_failed,
    "customer.updated":              handle_customer_updated,
}


def dispatch(event: dict) -> None:
    """
    Run the matching handler for this event type. Caller is responsible
    for the surrounding transaction + idempotency log.
    """
    event_type = event.get("type")
    handler = HANDLERS.get(event_type)
    if not handler:
        logger.info("No handler for Stripe event type %s — ignoring.", event_type)
        return

    obj = (event.get("data") or {}).get("object") or {}
    handler(obj)
