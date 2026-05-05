# ADR 0010 — Stripe as the Payment Processor

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-05-05 |
| Deciders | Founder / sole engineer |
| Supersedes | – |
| Superseded by | – |

## Context

Nano EASM sells subscriptions. We need a payment processor that:
- Handles card details so we never touch them (PCI scope minimisation).
- Supports recurring subscriptions, prorations, plan changes, cancellations.
- Supports AUD-denominated pricing (we sell in AUD; CLAUDE.md "Plan tiers and limits").
- Has a hosted checkout we can route to from our app.
- Has a customer-portal / self-service for plan management and invoice download.
- Has reliable webhooks for subscription lifecycle events.
- Has a strong API client for Python.

We also need the billing layer to be **temporarily disable-able** via a feature flag — Nano EASM launched as Free-only and toggled billing on later (CLAUDE.md "Billing Feature Flag").

## Decision

We use **Stripe** as the sole payment processor.

- Hosted **Checkout** for upgrade flows (`/billing/checkout` opens a Stripe-hosted page).
- **Customer Portal** for self-service plan / payment management (`/billing/portal`).
- **Webhooks** for subscription state (`/billing/stripe-webhook`), signature-verified, idempotent on event id.
- AUD-denominated **Prices** in the Stripe dashboard; their `price_…` IDs live in env vars (`STRIPE_PRICE_STARTER_MONTHLY`, etc.).
- Stripe-events are stored in a `stripe_event` table for idempotency.
- Custom-tier customers are **not** routed through Stripe — they go to the contact form for a sales-quoted contract.

## Considered alternatives

| Alternative | Why rejected |
|---|---|
| **Paddle** | Acts as merchant of record (handles VAT / GST / sales tax globally). Attractive for international sales without the tax complexity. Trade-off: Paddle's UX, customer-facing branding, and the limited ability to control checkout details. We chose Stripe and accept the tax-handling responsibility (we register where we must). |
| **Lemon Squeezy** | Similar to Paddle; merchant of record. Attractive for one-engineer ops. Less mature subscription primitives at the time of decision. Reconsider if we add international expansion and don't want to manage tax compliance ourselves. |
| **Braintree (PayPal)** | Comparable to Stripe technically. Documentation and developer ergonomics weaker. Stripe wins on day-1 productivity. |
| **Adyen / Worldpay / mature enterprise gateways** | Targeted at higher volume; integration is heavier. Overkill at our stage. |
| **Direct merchant account + custom integration** | Massive PCI surface. Not happening. |

## Consequences

**Positive:**
- **Best-in-class developer ergonomics.** Hosted Checkout is a one-redirect integration; webhook handling is well-documented.
- **PCI surface is minimised.** We never see card numbers; Stripe handles all of it.
- **Self-service plan management.** Customer Portal handles upgrade, downgrade, payment-method update, invoice download — features we'd build over months otherwise.
- **Webhook reliability is good.** Retries happen for up to 3 days.
- **AUD-native** — we don't pay FX margin on top of card fees for our domestic customers.
- **Subscription primitives** (proration, trials, dunning) are built-in. Our app glues them together without reimplementing.

**Negative:**
- **Vendor lock-in is real.** Migrating away from Stripe is a project: customer migration via Stripe's tooling, webhook re-wiring, possible price re-creation. The lock-in is the price of the convenience.
- **Fee structure.** Stripe takes ~2.9% + 30¢ per transaction, plus international and dispute fees. Built into our margin model (CLAUDE.md hard rule #6 — re-run when fees or FX move >10%).
- **Tax (GST in AU, VAT in EU) is our problem.** Stripe Tax helps but doesn't absolve us. We handle this with our accountant.
- **Branding constraint.** Hosted Checkout is Stripe-branded; some enterprise prospects expect to see only us. Mitigated by Stripe's customisation knobs (logo, colours, primary domain set to `billing.nanoasm.com`).

## Implementation notes

- **Idempotency:** every Stripe event id is inserted into `stripe_event` on first receipt. Duplicates are no-ops. This is the only guard against Stripe retries causing double-execution.
- **Signature verification:** the webhook secret is in `STRIPE_WEBHOOK_SECRET`. A signature mismatch returns 400; the body is **not** logged (treated as adversarial).
- **Receipts and refunds** go through Resend (ADR 0009), not Stripe-default email, so the from-address is `nanoasm.com`.
- **Test mode vs live mode** is determined by the `STRIPE_API_KEY` value (`sk_test_` vs `sk_live_`). No mode toggle in code.
- **Custom tier** is not Stripe-purchasable — `/billing/upgrade` to "Custom" returns 403 with copy directing to contact-sales.

## Feature flag

`ENABLE_BILLING=false` (backend) and `NEXT_PUBLIC_ENABLE_BILLING=false` (frontend) hide all billing UI and skip Stripe calls in upgrade flows. The Stripe code paths remain present and reachable when the flag flips on. Migrations and database fields (`stripe_customer_id`, `stripe_event`, `plan_expires_at`) are unconditionally present.

## References

- ADR 0009 (Resend) — receipts go through Resend, not Stripe defaults
- §07 Integrations §2 — Stripe integration detail
- §09 Key Scenarios §4 — Stripe webhook → plan upgrade flow
- CLAUDE.md "Billing Feature Flag" — flag mechanics
- CLAUDE.md "Cost rationale" — margin model that depends on Stripe fee structure

---
