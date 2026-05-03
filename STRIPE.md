# Stripe Integration — Reference

Status: **paused mid-build.** Test mode is wired end-to-end, including
emails. Live mode hasn't been switched on yet. This document is the
authoritative record of what exists, what's still pending, and how to
resume.

> **Currently active:** `ENABLE_BILLING=true` and `NEXT_PUBLIC_ENABLE_BILLING=true`
> in dev. To pause Stripe entirely, set both to `false` — checkout endpoints
> return 503, the legacy free-upgrade flow takes over, and no UI breaks.

---

## What's implemented

### Backend

```
backend/app/billing/
├── routes.py            ← /billing/* endpoints (checkout, portal, subscription, webhook, ...)
├── stripe_service.py    ← thin SDK wrapper (sessions, price↔plan map)
├── stripe_webhook.py    ← signature-verified dispatcher with idempotency
└── emails.py            ← receipt, payment-failed, refund emails (Resend)
```

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `POST /billing/checkout`        | manage_billing | Creates a hosted Checkout session, returns redirect URL |
| `POST /billing/portal`          | manage_billing | Creates a Customer Portal session, returns redirect URL |
| `GET  /billing/subscription`    | any auth | Subscription status (used for post-checkout polling + UI banners) |
| `GET  /billing/plan`            | any auth | Existing plan + limits + usage payload (unchanged) |
| `GET  /billing/plans`           | any auth | Existing plan list (unchanged) |
| `POST /billing/stripe-webhook`  | Stripe signature only | Receives + verifies + dispatches events |

Existing `/upgrade`, `/downgrade`, `/cancel`, `/start-trial` all kept — they handle the community-preview free flow when `ENABLE_BILLING=false`.

### Webhook events handled

| Event | What happens |
|-------|--------------|
| `checkout.session.completed`     | Attach `stripe_customer_id` + `stripe_subscription_id` to the org, capture billing email |
| `customer.subscription.created`  | Mirror Stripe state onto `Organization` (status, period, plan, cycle) |
| `customer.subscription.updated`  | Same — used for plan changes, cancel toggling, status transitions |
| `customer.subscription.deleted`  | Drop org back to Free, clear cycle/expiry, write `subscription_canceled` event |
| `invoice.payment_succeeded`      | Recover from past_due, write `payment_succeeded` event, **send branded receipt email** |
| `invoice.payment_failed`         | Mark `past_due`, write `payment_failed` event, **send "update your card" email** |
| `charge.refunded`                | Write `refund_issued` event, **send refund email** |
| `customer.updated`               | Sync `org.billing_email` when user changes it in the Portal |

All event IDs deduped via `stripe_event` table — Stripe redeliveries are silently skipped.

### Frontend

```
frontend/app/lib/
├── stripe-config.ts                          ← publishable key + canCheckout()
└── api.ts (additions)                        ← createCheckoutSession, createPortalSession,
                                                getSubscriptionStatus, getAdminBilling*

frontend/app/(authenticated)/
├── settings/billing/page.tsx                 ← order-review dialog with delta + cycle toggle + trust strip
└── layout.tsx                                ← BillingStatusBanner (past-due / cancelling)

frontend/app/(admin)/admin/
├── billing/page.tsx                          ← admin billing dashboard
└── layout.tsx                                ← Billing entry in admin sidebar

frontend/public/
├── icon.svg                                  ← square brand mark
├── logo.svg                                  ← horizontal lockup (light bg)
└── logo-on-dark.svg                          ← horizontal lockup (dark bg)
```

**Customer-facing copy** never says "Stripe" — uses "secure checkout", "billing portal", "Manage billing", etc.

### Database

Migration `b3c4d5e6f7a8_add_stripe_billing.py` (chains from `a2b3c4d5e6f7`):

- New columns on `organization`: `stripe_subscription_status`, `current_period_start/end`, `cancel_at_period_end`, `default_payment_method`, `billing_email`
- Indexes on `stripe_customer_id` + `stripe_subscription_id` for webhook lookups
- New table `stripe_event` — webhook idempotency log
- New table `billing_event` — user-visible audit trail (`kind` ∈ {subscription_created, subscription_updated, subscription_canceled, payment_succeeded, payment_failed, refund_issued, plan_changed})
- `BE` prefix added to display_id registry for `billing_event`

### Admin console

Page at `/admin/billing` (superadmin only). Backed by 4 endpoints:

| Endpoint | What it returns |
|----------|----------------|
| `GET /admin/billing/overview`       | Counts (active/trialing/past_due/cancelling) + MRR + monthly revenue + webhook health |
| `GET /admin/billing/subscriptions`  | Paginated org list with `?status=` filter + `?search=` |
| `GET /admin/billing/events`         | Paginated `BillingEvent` feed across all orgs |
| `GET /admin/billing/webhook-log`    | Paginated `StripeEvent` log with `?errorOnly=1` for debugging |

---

## Stripe Dashboard setup

These need configuring once per environment (test, then live).

### 1. Branding (Settings → Branding)
- [ ] Logo uploaded (`frontend/public/logo.svg` or 512×512 PNG export)
- [ ] Icon uploaded (`frontend/public/icon.svg`)
- [ ] Brand colour: `#14b8a6`
- [ ] Accent colour: `#0a0f1e` (or default)
- [ ] Public business name: `Nano EASM`
- [ ] Statement descriptor: `NANO EASM`

### 2. Customer emails (Settings → Customer emails)
- [ ] **Successful payments — OFF** (we send our own from `no-reply@nanoasm.com`)
- [ ] **Refunds — OFF** (we send our own)
- [ ] Subscription email reminders — leave ON (we don't send these)

### 3. Customer Portal (Settings → Billing → Customer portal)
- [ ] **Subscription updates — ON** (so "Upgrade to Pro" buttons can switch plans inside the Portal)
- [ ] **Payment method updates — ON**
- [ ] **Invoice history — ON**
- [ ] **Cancel subscription — ON** (cancel at period end)
- [ ] Return URL: `https://nanoasm.com/settings/billing`

### 4. Tax (Settings → Tax) — optional but recommended
- [ ] Stripe Tax enabled if selling to EU/UK B2B (legally required for VAT)
- [ ] Receipts will automatically show the `Tax` line once enabled — no code change needed

### 5. Products + Prices
Create one Product per plan, two Prices per Product (monthly + annual):

| Product | Price (monthly) | Price (annual) |
|---------|----------------|----------------|
| Nano EASM Starter | $19/mo | $180/yr |
| Nano EASM Professional | $99/mo | $948/yr |
| Nano EASM Enterprise Silver | $499/mo | $4,788/yr |

Enterprise Gold is sales-priced — don't create a public Price for it.

Copy the 6 `price_...` IDs into env vars (see below).

### 6. Webhook endpoint (Developers → Webhooks)
- [ ] URL: `https://nanoasm.com/api/billing/stripe-webhook` (prod) or via `stripe listen` for local
- [ ] Events subscribed:
  - [ ] `checkout.session.completed`
  - [ ] `customer.subscription.created`
  - [ ] `customer.subscription.updated`
  - [ ] `customer.subscription.deleted`
  - [ ] `invoice.payment_succeeded`
  - [ ] `invoice.payment_failed`
  - [ ] `charge.refunded`
  - [ ] `customer.updated`
- [ ] Copy signing secret (`whsec_...`) → `STRIPE_WEBHOOK_SECRET`

---

## Environment variables

```env
# Feature flags
ENABLE_BILLING=true                    # backend
NEXT_PUBLIC_ENABLE_BILLING=true        # frontend (build-time)

# Keys — TEST (replace with sk_live_/pk_live_ for production)
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...        # different per webhook endpoint
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_API_VERSION=2025-09-30.clover   # pinned

# Price IDs (price_..., not prod_...)
STRIPE_PRICE_STARTER_MONTHLY=price_...
STRIPE_PRICE_STARTER_ANNUAL=price_...
STRIPE_PRICE_PRO_MONTHLY=price_...
STRIPE_PRICE_PRO_ANNUAL=price_...
STRIPE_PRICE_SILVER_MONTHLY=price_...
STRIPE_PRICE_SILVER_ANNUAL=price_...

# Redirect URLs
STRIPE_SUCCESS_URL=https://nanoasm.com/settings/billing?checkout=success
STRIPE_CANCEL_URL=https://nanoasm.com/settings/billing?checkout=cancel
STRIPE_PORTAL_RETURN_URL=https://nanoasm.com/settings/billing

# Email — already set up for verification + monitoring
RESEND_API_KEY=re_...
EMAIL_FROM=Nano EASM <no-reply@nanoasm.com>
```

All passed through `docker-compose.yml`. `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` is build-time — frontend rebuild required when changed.

---

## What's NOT built (intentionally deferred)

These are the limitations to remember when resuming. None are bugs — all are scope decisions.

1. **In-app cancel / reactivate / plan switch buttons.** Customer Portal handles all three. The billing page shows a "Manage billing" button on the current plan card and "Upgrade to {Plan}" / "Downgrade to {Plan}" buttons that all open the Portal when there's an active subscription. This avoids state divergence between our DB and Stripe.

2. **In-app invoice list page.** Customer Portal shows full invoice history with PDF downloads. The receipt email also links directly to the Stripe-hosted invoice PDF.

3. **BillingEvent audit feed in user-facing UI.** Rows are written, surfaced in `/admin/billing`, but not yet shown to the org owner. Easy to add when needed (`GET /billing/events`).

4. **Currency support beyond USD.** Single-currency by design. Multi-currency = one Price per (tier × cycle × currency) plus FX considerations.

5. **Stripe Tax row on receipts** — code is ready (the `Tax` row appears automatically when `invoice.tax > 0`). Just needs Stripe Tax activated in dashboard.

6. **Refund handler in admin UI.** Refunds are issued via Stripe Dashboard. Webhook fires → `BillingEvent(kind="refund_issued")` row written → refund email sent. There's no in-app "refund this charge" button (and there shouldn't be — refunds are rare and risky).

7. **Stripe-trial periods.** The Checkout session doesn't pass `trial_period_days`. All trials are admin-approved via the existing `/billing/start-trial` → ContactRequest flow.

8. **Webhook health alerting.** `/admin/billing` shows error/unprocessed counts in last 24h. There's no auto-email when the count spikes — needs manual checking.

---

## Testing

### Stripe CLI (local webhook forwarding)
```bash
stripe listen --forward-to localhost:5000/api/billing/stripe-webhook
# Use the whsec_... it prints as STRIPE_WEBHOOK_SECRET locally
```

### Test cards (test mode only)
| Number | Behaviour |
|--------|-----------|
| `4242 4242 4242 4242` | Success |
| `4000 0027 6000 3184` | 3DS challenge → success |
| `4000 0000 0000 9995` | Declined (insufficient funds) |
| `4000 0000 0000 0341` | Attaches OK, next charge fails — for testing past_due |

Any future expiry, any CVC, any postcode.

### CLI event triggers
```bash
stripe trigger checkout.session.completed
stripe trigger invoice.payment_succeeded
stripe trigger invoice.payment_failed
stripe trigger customer.subscription.deleted
stripe trigger charge.refunded
```

### Idempotency
```bash
stripe events resend evt_...
# Backend log: "Skipping duplicate Stripe event evt_xxx"
# stripe_event row count for that ID stays at 1
```

### Customer-facing checklist
1. Free → Starter via Checkout — banner appears, then plan flips
2. Cancel during Checkout — friendly red banner
3. Receipt email arrives from `no-reply@nanoasm.com` with line-items table
4. Switch plan in Portal — receipt explains proration with italic note
5. Trigger payment_failed — red banner appears, "update card" email arrives
6. Trigger charge.refunded — refund email arrives + admin events feed shows row
7. As an admin: `/admin/billing` — counts update live, webhook log shows recent events

---

## Test → Live switch

| Variable | Test | Live |
|----------|------|------|
| `STRIPE_SECRET_KEY` | `sk_test_...` | `sk_live_...` |
| `STRIPE_WEBHOOK_SECRET` | from test webhook endpoint | from **separate** live webhook endpoint |
| `STRIPE_PRICE_*` (×6) | test Price IDs | live Price IDs (recreate Products+Prices in live mode) |
| `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` | `pk_test_...` | `pk_live_...` ← requires `--no-cache` frontend rebuild |

Smoke test after the switch:
1. Subscribe to Starter monthly with a real card you own
2. Confirm the receipt email arrives correctly addressed
3. Open Customer Portal, cancel
4. Refund the charge from Stripe Dashboard
5. Verify all events landed in `/admin/billing` events feed

If all five pass, you're live.

---

## Operational notes

- **Webhooks are the source of truth.** Never write subscription state from frontend-initiated requests. The only writers to `Organization.stripe_*` are the webhook handlers in `stripe_webhook.py`.
- **Past-due grace** — handled by Stripe Smart Retries (configurable in dashboard, default ~3 weeks). During past_due, `effective_plan` returns the paid plan so users keep access. Once Stripe gives up, `customer.subscription.deleted` drops them to Free.
- **Webhook errors are silent.** Check `/admin/billing` → Webhook log tab → "Errors only" filter weekly during the first month live.
- **Resend failures don't block webhooks.** If an email send fails, the webhook still acks Stripe and the DB still updates. Customer just won't get the email — better than Stripe retrying the whole event and risking double billing-event rows.
- **Refunds are dashboard-driven.** Issue from Stripe Dashboard → Payments → Refund payment. Webhook fires → BillingEvent row + email automatically.
- **Currency**: hardcoded USD in PLAN_CONFIG and Price IDs. Receipts render whatever currency Stripe returns — if you ever sell in another currency, the email will format it correctly, but the plan card UI assumes USD.
