# =============================================================================
# File: app/audit/webhook.py
# Description: Forward audit-log events to a customer-configured webhook
# (typically a SIEM ingestion endpoint).
#
# Plan-gated to tiers where PLAN_CONFIG sets `audit_log: True`
# (Enterprise Gold + Custom).
#
# Delivery model:
#   - Fire-and-forget on a daemon thread per event so the request that
#     triggered the audit log never blocks on an external receiver.
#   - HMAC-SHA256 signature over the raw JSON body, sent in
#     `X-Nano-Signature: sha256=<hex>`. The receiver verifies with the
#     org's stored secret.
#   - Each delivery carries a unique UUID in `X-Nano-Event-Id` so the
#     receiver can dedupe (we don't retry today, but if we add retries
#     later the same event id is reused).
#   - Every attempt — success or failure — is recorded in
#     `audit_webhook_delivery` for the settings-page debug panel.
# =============================================================================

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import requests

from app.extensions import db
from app.models import (
    AuditLog,
    AuditWebhookDelivery,
    Organization,
)

logger = logging.getLogger(__name__)


# Receiver should respond quickly. We don't want to tie up a thread
# (or, worse, the request thread on the synchronous "send test" path)
# waiting on a slow endpoint.
DELIVERY_TIMEOUT_SECONDS = 10
USER_AGENT = "Nano-EASM-Audit-Webhook/1.0"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_secret() -> str:
    """Generate a webhook signing secret. Used when an operator first
    configures the webhook so they can't pick a weak value."""
    return f"whsec_{secrets.token_urlsafe(32)}"


def forward_audit_event(entry: AuditLog, organization_id: int) -> None:
    """
    Forward an audit-log entry to the org's configured webhook.

    Safe to call from the request path: returns immediately after
    spawning a daemon thread. Caller need not (and should not) await.

    This is a no-op if:
        - the org's plan doesn't include audit-log forwarding
        - the webhook is not configured / disabled
        - the entry's category isn't in the allow-list (when set)

    We snapshot the entry attributes synchronously into a plain dict
    before spawning the thread because the caller's outer transaction
    hasn't committed yet — a background session wouldn't see the row.
    Capturing the values here also means the SQLAlchemy object never
    crosses thread boundaries (which would be an error: instances are
    bound to their originating session).
    """
    try:
        from flask import current_app
        app = current_app._get_current_object()  # type: ignore[attr-defined]
    except RuntimeError:
        # No request context — never expected, but be defensive.
        logger.warning("forward_audit_event called outside app context")
        return

    snapshot = {
        "id": entry.id,
        "organization_id": entry.organization_id,
        "user_id": entry.user_id,
        "user_email": entry.user_email,
        "action": entry.action,
        "category": entry.category,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "target_label": entry.target_label,
        "description": entry.description,
        "metadata_json": entry.metadata_json,
        "ip_address": entry.ip_address,
        "created_at": entry.created_at,
    }

    t = threading.Thread(
        target=_deliver_in_background,
        args=(app, snapshot, organization_id),
        daemon=True,
    )
    t.start()


def send_test_event(organization_id: int) -> AuditWebhookDelivery:
    """
    Synchronous test delivery — used by the "Send test event" button.

    Records the attempt (with `audit_log_id = NULL`) so it shows up in
    the deliveries panel alongside real events. Returns the delivery
    row so the route can include status/code/error in the response.
    """
    org = Organization.query.get(organization_id)
    if not org or not org.audit_webhook_url:
        raise ValueError("Webhook not configured")

    payload = _build_test_payload(org)
    return _deliver(
        organization_id=organization_id,
        audit_log_id=None,
        url=org.audit_webhook_url,
        secret=org.audit_webhook_secret or "",
        payload=payload,
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _deliver_in_background(app, snapshot: dict[str, Any], organization_id: int) -> None:
    """POST the snapshotted audit event inside its own app context."""
    with app.app_context():
        try:
            org = Organization.query.get(organization_id)
            if not org:
                return
            if not org.audit_webhook_enabled or not org.audit_webhook_url:
                return
            if not _plan_allows_audit_log(org):
                return

            # Category allow-list — NULL means forward everything.
            allowed = org.audit_webhook_categories
            category = snapshot.get("category")
            if allowed and category and category not in allowed:
                return

            payload = _build_event_payload(snapshot, org)
            _deliver(
                organization_id=organization_id,
                audit_log_id=snapshot.get("id"),
                url=org.audit_webhook_url,
                secret=org.audit_webhook_secret or "",
                payload=payload,
            )
        except Exception as e:
            # Background thread — never let an exception bubble up and
            # crash the worker process.
            logger.warning(f"Audit webhook background delivery failed: {e}")


def _deliver(
    *,
    organization_id: int,
    audit_log_id: int | None,
    url: str,
    secret: str,
    payload: dict[str, Any],
) -> AuditWebhookDelivery:
    """POST the payload, record the attempt, return the delivery row."""
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    event_id = payload["event_id"]
    signature = _sign(body, secret)

    headers = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "X-Nano-Event-Id": event_id,
        "X-Nano-Signature": f"sha256={signature}",
        "X-Nano-Event-Type": payload.get("category", "audit"),
    }

    delivery = AuditWebhookDelivery(
        organization_id=organization_id,
        audit_log_id=audit_log_id,
        event_id=event_id,
        delivery_url=url,
        status="pending",
        attempted_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.session.add(delivery)
    db.session.flush()

    started = time.monotonic()
    status_code: int | None = None
    error: str | None = None
    try:
        resp = requests.post(
            url, data=body, headers=headers,
            timeout=DELIVERY_TIMEOUT_SECONDS,
        )
        status_code = resp.status_code
        if not (200 <= resp.status_code < 300):
            # Capture a snippet of the body for debugging — receivers
            # often return JSON error messages.
            text = (resp.text or "")[:500]
            error = f"HTTP {resp.status_code}: {text}".strip()
    except requests.exceptions.Timeout:
        error = f"Timeout after {DELIVERY_TIMEOUT_SECONDS}s"
    except requests.exceptions.ConnectionError as e:
        error = f"Connection error: {str(e)[:200]}"
    except Exception as e:
        error = f"{type(e).__name__}: {str(e)[:200]}"

    duration_ms = int((time.monotonic() - started) * 1000)

    delivery.status_code = status_code
    delivery.duration_ms = duration_ms
    delivery.error_message = error
    delivery.status = "success" if (status_code and 200 <= status_code < 300) else "failed"

    try:
        db.session.commit()
    except Exception as e:
        logger.warning(f"Failed to record audit webhook delivery: {e}")
        db.session.rollback()

    return delivery


def _sign(body: bytes, secret: str) -> str:
    """HMAC-SHA256 hex digest. Empty secret still produces a deterministic
    digest — it's the receiver's job to reject deliveries when no shared
    secret has been configured on their end."""
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _plan_allows_audit_log(org: Organization) -> bool:
    """True iff the org's effective plan includes `audit_log: True`."""
    try:
        from app.billing.routes import PLAN_CONFIG
    except Exception:
        return False
    plan_key = getattr(org, "effective_plan", None) or org.plan or "free"
    cfg = PLAN_CONFIG.get(plan_key) or PLAN_CONFIG.get("free", {})
    return bool((cfg.get("limits") or {}).get("audit_log"))


def _build_event_payload(snapshot: dict[str, Any], org: Organization) -> dict[str, Any]:
    """
    Stable, documented JSON shape that customers can write SIEM parsers
    against. Keep field names snake_case for SIEM-friendliness — this is
    the one place we deliberately diverge from the camelCase UI contract.
    """
    created_at = snapshot.get("created_at")
    timestamp = (
        created_at.replace(tzinfo=timezone.utc).isoformat()
        if created_at else None
    )
    return {
        "event_id": str(uuid.uuid4()),
        "schema_version": "1",
        "event_type": "audit.event",
        "timestamp": timestamp,
        "organization": {
            "id": org.id,
            "name": org.name,
        },
        "actor": {
            "user_id": snapshot.get("user_id"),
            "user_email": snapshot.get("user_email"),
            "ip_address": snapshot.get("ip_address"),
        },
        "action": snapshot.get("action"),
        "category": snapshot.get("category"),
        "target": {
            "type": snapshot.get("target_type"),
            "id": snapshot.get("target_id"),
            "label": snapshot.get("target_label"),
        },
        "description": snapshot.get("description"),
        "metadata": snapshot.get("metadata_json") or {},
        "audit_log_id": snapshot.get("id"),
    }


def _build_test_payload(org: Organization) -> dict[str, Any]:
    """Synthetic event used by the 'Send test event' button."""
    now_iso = datetime.now(timezone.utc).isoformat()
    return {
        "event_id": str(uuid.uuid4()),
        "schema_version": "1",
        "event_type": "audit.test",
        "timestamp": now_iso,
        "organization": {
            "id": org.id,
            "name": org.name,
        },
        "actor": {"user_id": None, "user_email": "test@nanoasm.com", "ip_address": None},
        "action": "settings.webhook_test",
        "category": "settings",
        "target": {"type": "settings", "id": "audit_webhook", "label": "Audit webhook"},
        "description": "Test event from Nano EASM. If you see this in your SIEM, the webhook is wired up correctly.",
        "metadata": {"test": True},
        "audit_log_id": None,
    }
