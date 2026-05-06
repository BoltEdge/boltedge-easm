# SRS Module 10 — Billing & Subscriptions

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 10 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies the plan tier model, the Free-tier 90-day evaluation lifecycle, Stripe-driven paid subscriptions (checkout, portal, webhook handling), trial requests, and refund handling.

---

## FR-BILL-001 — Plan tiers

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system shall offer the following plan tiers with monthly / annual pricing in AUD:

| Plan | Monthly | Annual /mo | Free / Paid |
|---|---|---|---|
| Free | A$0 | — | Free (90-day evaluation) |
| Starter | A$29 | A$24 | Paid |
| Professional | A$149 | A$129 | Paid |
| Enterprise Silver | A$599 | A$509 | Paid |
| Enterprise Gold | A$999 | A$849 | Paid |
| Custom | Sales-quoted | Sales-quoted | Paid (contract) |

Limits per tier (`assets`, `monitored_assets`, `scans_per_month`, `discoveries_per_month`, `team_members`, `scheduled_scans`, `api_keys`, plus feature flags) are defined in `app/billing/routes.py:PLAN_CONFIG`.

---

## FR-BILL-002 — Free-tier 90-day evaluation lifecycle (option c)

**Priority:** P0 — Must
**Status:** [GAP: not yet implemented — see positioning pivot tasks doc 00, §2]

The Free tier is a **90-day evaluation**, not a permanent free service. The lifecycle:

```
day 0       Sign-up. Free tier active. Full Free-tier limits.
day 80      Reminder email: "10 days left on your Free tier".
day 87      Reminder email: "3 days left on your Free tier".
day 90      Free tier expires. plan_status = "expired".
            User can no longer log in (FREE_TIER_EXPIRED block at login,
            FR-AUTH-006 AC-6). Data is RETAINED for 30 days.
day 90+     Login is blocked with an upgrade prompt that links straight
            to Stripe Checkout. Successful payment flips plan_status
            back to "active" and unblocks login.
day 113     Reminder email: "Data deletion in 7 days".
day 120     Hard-delete the organisation, members (orphaned), scan jobs,
            findings, monitors, reports, audit log entries — same path
            as the org-deletion flow.
```

**Acceptance criteria:**
- AC-1 At org creation on Free tier, an `expires_at` timestamp is set to `created_at + 90 days`.
- AC-2 The hourly scheduler flips `plan_status` from `active` to `expired` for Free orgs whose `expires_at` is past.
- AC-3 The login endpoint enforces the expiry block (FR-AUTH-006 AC-6).
- AC-4 An upgrade to a paid plan within 30 days of expiry restores `plan_status` to `active`.
- AC-5 After 30 days expired, the org is hard-deleted via the same code path as `delete_organization`, with notification email at day 113 + day 120.
- AC-6 Audit-log entries for every state transition (`billing.free_tier_expired`, `billing.free_tier_extended`, `billing.free_tier_data_deleted`).

---

## FR-BILL-003 — Free-tier email notifications

**Priority:** P0 — Must
**Status:** [GAP: not yet implemented]

The system shall dispatch the following emails during the Free-tier lifecycle:

- **Day 80** — "10 days left on your Free tier — upgrade to keep your assets monitored"
- **Day 87** — "3 days left on your Free tier"
- **Day 90** — "Your Free tier has expired — upgrade within 30 days or your data will be deleted"
- **Day 113** — "Data deletion in 7 days — last chance to upgrade"
- **Day 120** — "Your data has been deleted"

Each is sent at most once per org per lifecycle (idempotent, tracked per-template flags on the org row).

---

## FR-BILL-004 — Trial request for paid tiers

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Paid tiers offer **request-only trials** rather than self-serve trial activation. An Owner / Admin requesting a trial of a paid plan creates a typed `ContactRequest(request_type="trial")` for admin review.

**Acceptance criteria:**
- AC-1 The request endpoint validates the target plan is a paid plan (not `free`, not `custom`).
- AC-2 Already-trialled tiers (per `TrialHistory`) are blocked.
- AC-3 An already-paid org cannot request a trial.
- AC-4 An already-trialing org cannot request another trial.
- AC-5 Soft de-dupe: an existing open trial request from the same email + same target plan returns the existing request id, not a new one.
- AC-6 The user receives an acknowledgement email referencing the request id (Module 09 dispatch).
- AC-7 Audit-log `billing.trial_requested`.

---

## FR-BILL-005 — Trial approval (admin-driven)

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The trial is approved by a superadmin upgrading the org's plan via the admin console. When the upgrade matches an open trial request from a member of that org, the system shall:

**Acceptance criteria:**
- AC-1 Mark the trial request as `replied`.
- AC-2 Send a "your trial is now active" email to the requester.
- AC-3 Audit-log `admin.trial_approved_emailed`.
- AC-4 Surface a confirmation toast in the admin UI ("Plan updated to Enterprise Silver. Trial-approval email sent to user@example.com.").

---

## FR-BILL-006 — Stripe checkout

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`POST /billing/checkout` shall:

**Acceptance criteria:**
- AC-1 Accept a target plan and billing cycle (monthly / annual).
- AC-2 Validate the target plan exists and is a Stripe-purchasable tier (not Free, not Custom).
- AC-3 Create or reuse the Stripe Customer for the org.
- AC-4 Create a Stripe Checkout Session for the corresponding AUD price id.
- AC-5 Return the hosted Checkout URL.
- AC-6 Audit-log `billing.checkout_initiated`.

---

## FR-BILL-007 — Stripe Customer Portal

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`POST /billing/portal` shall return a hosted Stripe Customer Portal URL for the org's customer record. The portal allows the customer to update payment method, change plan within configured options, cancel, and view invoices.

---

## FR-BILL-008 — Stripe webhook handling

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`POST /billing/stripe-webhook` shall:

**Acceptance criteria:**
- AC-1 Verify the `Stripe-Signature` header (NFR-SEC-019). Reject invalid signatures with HTTP 400.
- AC-2 Be idempotent — every event id is recorded in the `StripeEvent` table; duplicate deliveries are no-ops.
- AC-3 Handle the following events:
  - `checkout.session.completed` → create / update the subscription, flip `plan` and `plan_status`, send receipt email
  - `invoice.paid` → send receipt email, log billing event
  - `invoice.payment_failed` → send payment-failed email, mark `plan_status = "past_due"`
  - `customer.subscription.updated` → reflect new plan or quantity
  - `customer.subscription.deleted` → revert to Free plan or apply 30-day grace, per business rules
  - `charge.refunded` → send refund email
- AC-4 Audit-log every event processed (`billing.<event_type>`).

---

## FR-BILL-009 — Receipt emails sent from our domain

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Receipt, payment-failed, and refund emails shall originate from `no-reply@nanoeasm.com` via Resend, **not** from Stripe's default sender. Stripe's automatic customer emails shall be disabled in the Stripe dashboard.

---

## FR-BILL-010 — Plan downgrade

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`POST /billing/downgrade` reverts the org to Free plan. The system shall:

**Acceptance criteria:**
- AC-1 Cancel the active Stripe subscription (at period end by default).
- AC-2 On period end (signalled by `customer.subscription.deleted`), set `plan = "free"`, `plan_status = "active"`, and a fresh 90-day Free-tier `expires_at`.
- AC-3 If the org was on a paid trial (per `TrialHistory`), do not extend a fresh 90-day Free window — the org goes straight to a 30-day grace before deletion.
- AC-4 Audit-log `billing.downgraded`.

---

## FR-BILL-011 — Plan upgrade (within paid tiers)

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A paid org upgrading to a higher tier shall use Stripe's subscription-update mechanism. The new plan applies pro-rata; charge / credit is automatic.

---

## FR-BILL-012 — Refunds

**Priority:** P1 — Should
**Status:** [IMPLEMENTED — via Stripe Customer Portal + admin escalation]

Customer-initiated refund requests are handled by the customer through the Stripe Customer Portal where their plan permits, or by an admin manually issuing a refund in Stripe Dashboard. The platform's refund policy is documented in the SLA / DPA. Audit-log `billing.refund_processed`.

---

## FR-BILL-013 — Billing event log

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system shall maintain a user-visible billing audit trail (`BillingEvent`) covering subscription state changes, plan changes, payments, refunds, trial events. Visible in `/settings/billing` for Owner / Admin.

---

## FR-BILL-014 — Custom plan handling

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

The Custom tier is **not** Stripe-purchasable. Attempts to checkout / upgrade to Custom are routed to a contact form. Custom-tier orgs are activated by a superadmin manually setting plan + limit_overrides.

---

## FR-BILL-015 — Free-tier extension (admin)

**Priority:** P2 — Could
**Status:** [GAP: not yet implemented — pivot task 2.7]

A superadmin shall be able to extend a Free org's `expires_at` by up to 90 days at a time, audit-logged. Useful for partner / friendly extensions.

---

## FR-BILL-016 — In-app countdown banner

**Priority:** P0 — Must
**Status:** [GAP: not yet implemented — pivot task 5.7]

For Free orgs within 30 days of `expires_at`, the authenticated layout shall display a persistent banner: "X days left on your Free tier — upgrade to keep your data" with a one-click route to checkout.

---

## FR-BILL-017 — Expired-Free login screen

**Priority:** P0 — Must
**Status:** [GAP: not yet implemented — pivot task 5.8]

A user blocked at login by `FREE_TIER_EXPIRED` shall be routed to a dedicated screen explaining the expiry, the 30-day grace period, and providing a one-click upgrade path that hops straight into Stripe Checkout. Successful payment unblocks login.

---

*End of module 10.*
