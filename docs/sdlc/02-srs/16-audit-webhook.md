# SRS Module 16 — Audit Log Webhook Stream

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 16 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies the outbound stream of audit log events to a customer-configured webhook receiver — typically a SIEM ingestion endpoint. This is a separate, more privileged feature than the general-purpose integration webhooks in Module 09.

---

## FR-AWH-001 — Plan-tier feature gate

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Audit log webhook streaming shall be available only on plans where `PLAN_CONFIG.audit_log = True` — currently Enterprise Gold and Custom. Lower plans see an upgrade-prompt empty state on the configuration UI; backend rejects with HTTP 403 / `FEATURE_NOT_AVAILABLE`.

---

## FR-AWH-002 — Configuration

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Owner shall be able to configure the audit log webhook stream via `/settings/integrations` → "Audit Log Stream" tab.

**Acceptance criteria:**
- AC-1 Endpoint URL (validated to start with `http://` or `https://`).
- AC-2 Optional category allow-list (e.g., only forward `auth`, `scan`, `admin`); empty = forward everything.
- AC-3 Master enable / disable toggle.
- AC-4 Server-side-generated signing secret (`whsec_…`); customer-supplied secrets are not allowed.
- AC-5 The plaintext secret is shown to the user **once** at creation or rotation; subsequently only a `whsec_…last4` mask is exposed.
- AC-6 Configuration changes are audit-logged.
- AC-7 Owner-only writes; Admin can read and test but not modify the URL or secret.

---

## FR-AWH-003 — Forwarding mechanism

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

When the feature is enabled and the org's plan permits, the system shall forward every audit log event:

**Acceptance criteria:**
- AC-1 Dispatch happens on a daemon thread (fire-and-forget) so the request that triggered the audit log never blocks on the external receiver.
- AC-2 Snapshot of the audit log row is taken before the thread spawns; the SQLAlchemy instance does not cross thread boundaries.
- AC-3 The category allow-list (FR-AWH-002 AC-2) is enforced before dispatch.
- AC-4 If the feature is disabled or the plan no longer permits it, the dispatch is a silent no-op (no failed-delivery row).

---

## FR-AWH-004 — Delivery contract

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Each delivery shall:

**Acceptance criteria:**
- AC-1 HTTP `POST` with `Content-Type: application/json`, `User-Agent: Nano-EASM-Audit-Webhook/1.0`, 10-second timeout.
- AC-2 Header `X-Nano-Signature: sha256=<hex>` — HMAC-SHA256 of the raw body using the org's secret.
- AC-3 Header `X-Nano-Event-Id: <uuid>` — receiver-side idempotency key.
- AC-4 Header `X-Nano-Event-Type: <category>` — convenience for routing rules.
- AC-5 Body shape (snake_case, intentionally diverging from the camelCase UI contract for SIEM-friendliness):
```json
{
  "event_id": "<uuid>",
  "schema_version": "1",
  "event_type": "audit.event",
  "timestamp": "2026-05-05T12:00:00Z",
  "organization": { "id": 42, "name": "Acme" },
  "actor": { "user_id": 7, "user_email": "alice@acme.com", "ip_address": "1.2.3.4" },
  "action": "scan.started",
  "category": "scan",
  "target": { "type": "asset", "id": "AS0042", "label": "shop.acme.com" },
  "description": "Scan started for shop.acme.com",
  "metadata": { ... },
  "audit_log_id": 12345
}
```

---

## FR-AWH-005 — Per-attempt log

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Each delivery — success or failure — shall be recorded in `AuditWebhookDelivery` with: status, status code, duration, error message, attempted_at, and the snapshot URL at delivery time. Used for the "Recent deliveries" debug panel.

---

## FR-AWH-006 — No retry today

**Priority:** P0 — Must (intentional non-feature)
**Status:** [IMPLEMENTED]

Failed deliveries are **not** retried at this stage. Retrying audit events with stale state has correctness implications (e.g., the audit row may have been deleted by retention) that need their own design. The failure is recorded; the audit log record is still durable in the database.

---

## FR-AWH-007 — Send test event

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The configuration UI shall include a "Send test event" button that synchronously dispatches a synthetic audit event (with `event_type: "audit.test"`) and reports the receiver's response inline. This validates secrets, signature checks, and SIEM routing rules before the customer flips the toggle on.

---

## FR-AWH-008 — Recent deliveries panel

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

A "Recent deliveries" debug panel shall list the last 50 attempts (success or failure) with status code, duration, error message, and attempted_at — for operator debugging without scraping app logs.

---

## FR-AWH-009 — Secret rotation

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The Owner shall be able to rotate the signing secret. Rotation:

**Acceptance criteria:**
- AC-1 Generates a fresh `whsec_…` value via `secrets.token_urlsafe(32)`.
- AC-2 Returns the plaintext value once in the rotation response.
- AC-3 Immediately invalidates the previous secret (no overlap window — the customer must update their receiver to accept the new secret quickly).
- AC-4 Audit-logged.

---

## FR-AWH-010 — Delete configuration

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The Owner shall be able to delete the audit webhook configuration entirely (URL, secret, category filter all cleared, enabled flag set to false). Audit-logged.

---

*End of module 16.*
