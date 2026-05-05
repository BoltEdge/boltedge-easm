# SRS Module 09 — Integrations & Notifications

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 09 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies how an organisation connects external systems (Slack, Jira, PagerDuty, generic webhook, email) and configures rules that route platform events to those connections.

The audit-log webhook stream is a separate, more privileged feature — see Module 16.

---

## FR-INT-001 — Integration types

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system shall support the following integration types:

| Type | Auth | Direction | Purpose |
|---|---|---|---|
| **Slack** | Incoming Webhook URL | Outbound POST | Channel notifications |
| **Jira** | Email + API token | Outbound POST | Ticket creation |
| **PagerDuty** | Events API v2 routing key | Outbound POST | Incident triggering |
| **Generic webhook** | Optional HMAC secret | Outbound POST | Customer-defined receiver |
| **Email** | Recipient list, optional from-address | Outbound | Email notifications |

---

## FR-INT-002 — Create an integration

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Admin shall be able to add a new integration:

**Acceptance criteria:**
- AC-1 The form requires the integration's type-specific config fields (per FR-INT-001).
- AC-2 The system validates required fields server-side; missing fields → HTTP 400.
- AC-3 Sensitive fields (API tokens, routing keys, HMAC secrets) are stored encrypted at rest.
- AC-4 The integration row carries a friendly name.
- AC-5 Audit-log `integration.created`.

---

## FR-INT-003 — Test an integration

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The integration UI shall include a "Test" button that sends a synthetic event to the integration and surfaces the receiver's response (success / failure code, latency).

**Acceptance criteria:**
- AC-1 The synthetic event clearly identifies itself as a test in its body.
- AC-2 The result indicator updates within 10 seconds.
- AC-3 The test does NOT count toward the customer's notification rate limits or rules.

---

## FR-INT-004 — Enable / disable an integration

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Each integration has an `enabled` flag. A disabled integration is skipped by all matching rules without erroring.

---

## FR-INT-005 — Delete an integration

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Admin may delete an integration. Notification rules that reference it are cascade-deleted with the user warned. Audit-log `integration.deleted`.

---

## FR-INT-006 — Notification rules

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A notification rule binds a platform event type to one or more integrations. Supported event types:

| Event | Description |
|---|---|
| `finding.critical` | New finding with severity = critical |
| `finding.high` | New finding with severity = high |
| `finding.medium` | New finding with severity = medium |
| `finding.any` | Any new finding (wildcard) |
| `scan.completed` | A scan job finished successfully |
| `scan.failed` | A scan job failed |
| `exposure.threshold` | Exposure score crosses a configured threshold |
| `monitor.alert` | A monitor raised an alert (Module 07) |

**Acceptance criteria:**
- AC-1 An Admin creates a rule with: event-type filter, target integration(s), optional asset-group filter, optional severity-floor filter, optional quiet-hours window.
- AC-2 The rule is enableable / disableable.
- AC-3 At runtime, when a matching event fires, the system dispatches to every enabled integration on every matching rule.
- AC-4 Each dispatch is logged (the source event, the target integration, success / failure, status code, latency).
- AC-5 Audit-log on rule create / update / delete.

---

## FR-INT-007 — Webhook signing

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Generic webhook deliveries shall:

**Acceptance criteria:**
- AC-1 Include `X-Nano-Signature: sha256=<hex>` header containing HMAC-SHA256 of the raw body using the integration's secret (if configured).
- AC-2 Include `X-Nano-Event-Id: <uuid>` for receiver-side idempotency.
- AC-3 Use a 10-second connect/read timeout.
- AC-4 Send a fixed `User-Agent: Nano-EASM-Webhook/1.0` (or audit-log variant).
- AC-5 Body is JSON with a stable schema versioned via `schema_version` field.

---

## FR-INT-008 — Webhook delivery retry

**Priority:** P1 — Should
**Status:** [GAP — currently single-attempt with no retry]

Failed webhook deliveries should be retried with exponential backoff (1m, 5m, 30m, 2h, then drop) and the per-attempt log surfaces each retry. [GAP — implementation pending.]

---

## FR-INT-009 — In-app notification banner

**Priority:** P1 — Should
**Status:** [PARTIAL]

[GAP for the dedicated bell / inbox UI.] The system should provide an in-app inbox showing recent notifications routed to the user. Today, only platform announcement banners are shown; a per-user notification feed has not been built.

---

## FR-INT-010 — Email notification format

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Email notifications shall:

**Acceptance criteria:**
- AC-1 Originate from `no-reply@nanoasm.com` (or the configured `EMAIL_FROM`).
- AC-2 Use the standard branded shell.
- AC-3 Carry a clear subject line including event type and asset / org name where relevant.
- AC-4 Include unsubscribe-from-this-rule link [TBD — currently rule management is by admin only; per-recipient unsubscribe is not exposed].
- AC-5 Plain-text fallback for clients that do not render HTML.

---

## FR-INT-011 — Plan-tier feature gating

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The Slack / Jira / PagerDuty / generic webhook integration types are plan-gated: available on Professional tier and above. Email integration is available on every plan including Free.

---

## FR-INT-012 — Quiet hours

**Priority:** P1 — Should
**Status:** [PARTIAL]

A notification rule may specify quiet hours (start/end times in the org's configured timezone) during which low/medium severity events are queued and delivered at the end of the quiet window. Critical / high events bypass quiet hours.

---

*End of module 09.*
