# Stripe Integration — Requirements & Implementation Plan

This document captures everything needed before, during, and after wiring Stripe into Nano EASM. Read end-to-end before starting work — a few decisions in §2 cascade into the data model and webhook handling.

> **Current state:** Stripe is **not** implemented. The `Organization` model already has nullable `stripe_customer_id` and `stripe_subscription_id` columns as stubs. There is no Stripe SDK, no API calls, no webhook endpoint. Billing is currently gated by the `ENABLE_BILLING` / `NEXT_PUBLIC_ENABLE_BILLING` flag and runs in "free upgrade" mode.

---

## 1. Pre-flight checklist

Everything below must exist (in **test mode** first) before we write any backend code.

### 1.1 Stripe account
- [ ] Stripe account created at https://dashboard.stripe.com
- [ ] Business profile filled in (legal name, address, support email — `contact@nanoasm.com`)
- [ ] Tax ID added if applicable (UK VAT / EU VAT / US EIN — depends on entity)
- [ ] Payout bank account added (only required when going live, not for test mode)
- [ ] Two-factor auth enabled on the Stripe account (mandatory for live mode anyway)

### 1.2 API keys
You need **four** keys in total — two for test, two for live. Treat secret keys like database passwords.

| Key | Environment | Where it goes | What it does |
|-----|-------------|---------------|--------------|
| `pk_test_...` | Test | `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` (frontend, baked at build) | Browser-side — creating Checkout Sessions, mounting Stripe Elements |
| `sk_test_...` | Test | `STRIPE_SECRET_KEY` (backend env) | Server-side — creating customers, subscriptions, calling all Stripe APIs |
| `pk_live_...` | Live | `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` (prod build) | Same, real money |
| `sk_live_...` | Live | `STRIPE_SECRET_KEY` (prod env) | Same, real money |

Plus webhook signing secrets (one per environment, see §1.4).

> ⚠️ `sk_*` keys must **never** appear in frontend code, git history, or logs. Add `STRIPE_SECRET_KEY` to `.env` only — already in `.gitignore`.

### 1.3 Products & Prices
Stripe distinguishes **Products** (the thing) from **Prices** (how much, how often, in what currency). For Nano EASM we want one Product per plan tier and one Price per (tier × cycle × currency) combination.

Recommended product/price layout (test mode):

| Product (name) | Price ID (test) | Amount | Cycle | Currency |
|---|---|---|---|---|
| Nano EASM Starter | `price_starter_monthly_usd` | $19 | monthly | USD |
| Nano EASM Starter | `price_starter_annual_usd` | $190 (≈17%) | yearly | USD |
| Nano EASM Professional | `price_pro_monthly_usd` | $99 | monthly | USD |
| Nano EASM Professional | `price_pro_annual_usd` | $990 | yearly | USD |
| Nano EASM Enterprise Silver | `price_silver_monthly_usd` | $499 | monthly | USD |
| Nano EASM Enterprise Silver | `price_silver_annual_usd` | $4,990 | yearly | USD |

**Free** has no Stripe product (it's the "no subscription" state). **Enterprise Gold** has no Stripe price either — it's sales-quoted, billed via Stripe Invoices manually after sales agreement, or via a custom Price object created per-deal in the dashboard.

Decisions to make about products/prices:
- Use **dashboard UI** to create them (recommended — simpler, audit trail) **or** automate via a one-off seeding script (`backend/scripts/seed_stripe.py`).
- Price IDs go into env vars (`STRIPE_PRICE_STARTER_MONTHLY=price_...`) so the same code works in test + prod.
- Annual discount: typically 2 months free (i.e. 10× monthly). Adjust to taste.

### 1.4 Webhook endpoint
Stripe sends events to a backend URL whenever something happens (subscription created, payment failed, etc.). We need:

- [ ] A public URL: `https://nanoasm.com/api/billing/stripe-webhook` (prod), `http://localhost:5000/api/billing/stripe-webhook` (local — exposed via `stripe listen` CLI)
- [ ] Configured in Stripe dashboard → Developers → Webhooks → Add endpoint
- [ ] Subscribed to **at minimum** these events:
  - `checkout.session.completed` — user finished Checkout, subscription is created
  - `customer.subscription.created` — redundancy; sometimes fires before checkout.session.completed
  - `customer.subscription.updated` — plan change, status change (active → past_due → canceled)
  - `customer.subscription.deleted` — subscription ended
  - `invoice.payment_succeeded` — recurring charge succeeded; reset usage windows here
  - `invoice.payment_failed` — dunning trigger; mark org `past_due`
  - `customer.updated` — email/name change in Customer Portal
  - `payment_method.attached` / `payment_method.detached` — optional, for UI display
- [ ] Signing secret (`whsec_...`) → `STRIPE_WEBHOOK_SECRET` env var
- [ ] Endpoint must verify signature on **every** request (`stripe.Webhook.construct_event`)

Local development:
```bash
# In a separate terminal, forward Stripe events to localhost
stripe listen --forward-to localhost:5000/api/billing/stripe-webhook
# Outputs a temporary whsec_... — use that as STRIPE_WEBHOOK_SECRET locally
```

### 1.5 Customer Portal
Stripe-hosted self-service for cancellation, payment method updates, invoice history. Free, no extra integration code.

- [ ] Configure in dashboard → Settings → Billing → Customer portal
- [ ] Enable: update payment method, view invoices, download invoices, update billing address, cancel subscription
- [ ] Decide: allow plan switching via portal? (Recommendation: **no** — handle plan changes in our own UI so we control the flow)
- [ ] Set the return URL → `https://nanoasm.com/settings/billing`

### 1.6 Tax handling
Either:
- **Stripe Tax** (recommended) — Stripe automatically calculates VAT/sales tax based on customer location. Costs 0.5% of the transaction. Requires Tax registration in each jurisdiction you collect.
- **Manual tax** — prices are tax-inclusive or tax-exclusive flat. Simpler but legal risk.

Decisions:
- [ ] Stripe Tax on or off?
- [ ] If on: register for VAT/sales tax in jurisdictions where you have nexus
- [ ] Do prices include or exclude tax? (Most B2B SaaS: exclude)

### 1.7 Email & receipts
- [ ] Stripe sends receipts automatically — toggle in dashboard → Settings → Customer emails
- [ ] Customise receipt branding (logo, colour) → Settings → Branding
- [ ] Decide: send our own receipt via Resend in addition? (Recommendation: **no** — Stripe's receipts are excellent and avoid duplicates)

---

## 2. Decisions to make before coding

These need answers from the product owner. Each one shapes the implementation.

| # | Decision | Options | Recommendation | Why |
|---|----------|---------|----------------|-----|
| 1 | **Checkout style** | (a) Stripe Checkout (hosted page), (b) Stripe Elements (embedded form), (c) Payment Element (newer embedded) | **(a) Hosted Checkout** | Fastest to ship, PCI-DSS SAQ A (lowest scope), handles 3DS/SCA automatically, mobile-optimised. Trade-off: redirect away from app for ~30 seconds. |
| 2 | **Billing cycle** | (a) Monthly only, (b) Annual only, (c) Both with toggle | **(c) Both, default monthly** | Annual = better cash flow + lower churn. Most B2B SaaS offers both with ~17% annual discount. |
| 3 | **Tax** | (a) Stripe Tax, (b) Manual flat rate, (c) Tax-inclusive prices | **(a) Stripe Tax** | Compliance offloaded to Stripe. 0.5% fee is worth not getting fined. |
| 4 | **Trial model** | (a) Stripe trial (auto-charges after N days), (b) No trial in Stripe; admin grants trial via DB flag, (c) Both | **(b) DB-only trials** | Aligns with current "request free trial → admin approves" flow. Stripe trials need a card upfront, which contradicts the current request-only model. |
| 5 | **Dunning** | (a) Stripe Smart Retries (built-in, free), (b) Custom retry logic, (c) Cancel immediately on failure | **(a) Smart Retries** | Stripe's algorithm recovers ~30% more failed payments than naive retries. Configure in dashboard, no code. |
| 6 | **Cancel timing** | (a) Cancel immediately (refund pro-rata), (b) Cancel at period end (keep access until paid period ends) | **(b) At period end** | Industry standard. Avoids refund disputes. Refunds become an admin-only action via Stripe dashboard. |
| 7 | **Plan switching** | (a) Pro-rate immediately (Stripe default), (b) Switch at next renewal, (c) User chooses | **(a) Pro-rate immediately** | What users expect when upgrading. For downgrades, change takes effect at period end (no refunds). |

> **Action required:** ☐ Owner picks a/b/c for each row above before Phase 1 begins.

---

## 3. Backend implementation plan

### 3.1 Dependencies
```
# requirements.txt
stripe==11.5.0  # latest 2026-Q1 stable
```

### 3.2 New / modified models

`Organization`:
```python
# Already exists (stubs):
stripe_customer_id        = db.Column(db.String(100), nullable=True, index=True)
stripe_subscription_id    = db.Column(db.String(100), nullable=True, index=True)

# New columns to add:
stripe_subscription_status = db.Column(db.String(30), nullable=True)
    # active | trialing | past_due | canceled | incomplete | incomplete_expired | unpaid
billing_cycle              = db.Column(db.String(10), nullable=True)
    # monthly | annual
current_period_start       = db.Column(db.DateTime, nullable=True)
current_period_end         = db.Column(db.DateTime, nullable=True)
cancel_at_period_end       = db.Column(db.Boolean, default=False, nullable=False)
default_payment_method     = db.Column(db.String(100), nullable=True)
    # pm_... — for "Mastercard ending 4242" UI
billing_email              = db.Column(db.String(255), nullable=True)
    # may differ from owner email
```

New table — `stripe_event` (idempotency log):
```python
class StripeEvent(db.Model):
    __tablename__ = 'stripe_event'
    id            = db.Column(db.Integer, primary_key=True)
    stripe_id     = db.Column(db.String(100), unique=True, index=True, nullable=False)
    type          = db.Column(db.String(100), nullable=False)
    received_at   = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    processed_at  = db.Column(db.DateTime, nullable=True)
    payload       = db.Column(db.JSON, nullable=False)
    error         = db.Column(db.Text, nullable=True)
```

> Why: Stripe occasionally redelivers webhooks. We process each event ID exactly once.

New table — `billing_event` (audit trail visible to user):
```python
class BillingEvent(db.Model):
    __tablename__ = 'billing_event'
    id              = db.Column(db.Integer, primary_key=True)
    public_id       = db.Column(db.String(20), unique=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False, index=True)
    kind            = db.Column(db.String(40), nullable=False)
        # subscription_created | subscription_updated | subscription_canceled |
        # payment_succeeded | payment_failed | refund_issued | plan_changed
    amount_cents    = db.Column(db.Integer, nullable=True)
    currency        = db.Column(db.String(3), nullable=True)
    description     = db.Column(db.String(500), nullable=True)
    stripe_object_id = db.Column(db.String(100), nullable=True)  # invoice/charge ID
    created_at      = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
```

Add `BL` prefix to `display_id.PREFIX_BY_TABLE` for `billing_event`.

### 3.3 Migration
```bash
flask db migrate -m "stripe billing columns and tables"
flask db upgrade
```

### 3.4 New endpoints

```
POST   /billing/checkout                  — create Stripe Checkout session, return URL
POST   /billing/portal                    — create Customer Portal session, return URL
POST   /billing/change-plan               — switch to different price (pro-rated)
POST   /billing/cancel-subscription       — set cancel_at_period_end=true
POST   /billing/reactivate-subscription   — undo cancel_at_period_end
POST   /billing/stripe-webhook            — receive + verify + dispatch events (no auth, signature only)
GET    /billing/invoices                  — list past invoices for org
GET    /billing/invoices/<id>/pdf         — proxy to Stripe-hosted PDF (auth required)
GET    /billing/payment-method            — current default PM (last4, brand)
GET    /billing/events                    — billing audit trail (last 50)
```

### 3.5 Webhook handler skeleton

```python
# backend/app/billing/stripe_webhook.py
import stripe
from flask import request, jsonify

@billing_bp.post("/stripe-webhook")
def stripe_webhook():
    payload = request.data
    sig = request.headers.get("Stripe-Signature", "")
    secret = current_app.config["STRIPE_WEBHOOK_SECRET"]

    try:
        event = stripe.Webhook.construct_event(payload, sig, secret)
    except (ValueError, stripe.error.SignatureVerificationError):
        return jsonify(error="invalid signature"), 400

    # Idempotency — skip already-processed events
    if StripeEvent.query.filter_by(stripe_id=event["id"]).first():
        return jsonify(received=True), 200

    log = StripeEvent(stripe_id=event["id"], type=event["type"], payload=event)
    db.session.add(log)
    db.session.commit()

    handler = HANDLERS.get(event["type"])
    if handler:
        try:
            handler(event["data"]["object"])
            log.processed_at = datetime.utcnow()
        except Exception as e:
            log.error = str(e)
            current_app.logger.exception("stripe webhook handler failed: %s", event["type"])
            db.session.commit()
            return jsonify(error="handler failed"), 500
        db.session.commit()

    return jsonify(received=True), 200


HANDLERS = {
    "checkout.session.completed":      handle_checkout_completed,
    "customer.subscription.created":   handle_subscription_created,
    "customer.subscription.updated":   handle_subscription_updated,
    "customer.subscription.deleted":   handle_subscription_deleted,
    "invoice.payment_succeeded":       handle_invoice_paid,
    "invoice.payment_failed":          handle_invoice_failed,
    "customer.updated":                handle_customer_updated,
}
```

Each handler updates the `Organization` row from the Stripe object's fields. Critical mapping: `subscription.items.data[0].price.id` → look up in `STRIPE_PRICE_TO_PLAN` dict → set `org.plan`.

### 3.6 Subscription state machine

```
                 ┌────────────────┐
                 │   Free (none)  │
                 └────────┬───────┘
                          │ checkout.session.completed
                          ▼
                 ┌────────────────┐
                 │   Active       │◄────────┐
                 └───┬──────┬─────┘         │
                     │      │               │
       payment fails │      │ plan switch   │ payment succeeds
                     ▼      │  (pro-rated)  │ (after past_due)
                 ┌────────────────┐         │
                 │   Past Due     │─────────┘
                 └────────┬───────┘
                          │ smart retries exhausted (~3 weeks)
                          ▼
                 ┌────────────────┐
                 │   Canceled     │ → downgrade to Free, keep org data
                 └────────────────┘
```

**Access control rule:** treat `active` and `trialing` as paid. Treat `past_due` as paid for 7 days, then read-only. `canceled` / no subscription → Free plan limits.

### 3.7 Feature flag interplay
Keep `ENABLE_BILLING` / `NEXT_PUBLIC_ENABLE_BILLING`. When enabled, billing UI shows. When disabled (community preview), checkout endpoints return 503 and frontend hides Stripe-related buttons. **Do not delete the flag.** It lets us ship Stripe code to prod without forcing payment, then flip the switch when ready.

### 3.8 Environment variables to add
```
# .env (backend)
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_STARTER_MONTHLY=price_...
STRIPE_PRICE_STARTER_ANNUAL=price_...
STRIPE_PRICE_PRO_MONTHLY=price_...
STRIPE_PRICE_PRO_ANNUAL=price_...
STRIPE_PRICE_SILVER_MONTHLY=price_...
STRIPE_PRICE_SILVER_ANNUAL=price_...
STRIPE_SUCCESS_URL=https://nanoasm.com/settings/billing?checkout=success
STRIPE_CANCEL_URL=https://nanoasm.com/settings/billing?checkout=cancel

# .env.local (frontend)
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_test_...
```

Plus pass them through `docker-compose.yml`. Remember `NEXT_PUBLIC_*` is build-time — needs `--no-cache` rebuild.

---

## 4. Frontend implementation plan

### 4.1 New library
```
npm install @stripe/stripe-js
```

### 4.2 New API methods (`frontend/app/lib/api.ts`)
```ts
export async function createCheckoutSession(priceId: string, cycle: "monthly" | "annual"): Promise<{ url: string }>
export async function createPortalSession(): Promise<{ url: string }>
export async function changePlan(priceId: string): Promise<Plan>
export async function cancelSubscription(): Promise<Plan>
export async function reactivateSubscription(): Promise<Plan>
export async function listInvoices(): Promise<Invoice[]>
export async function getPaymentMethod(): Promise<PaymentMethod | null>
export async function listBillingEvents(): Promise<BillingEvent[]>
```

### 4.3 Pages to update

**`/settings/billing` (Plans page) — extensive changes when `BILLING_ENABLED=true`:**
- Show current plan + status badge (Active / Past Due / Canceling on Mar 14)
- Show "Manage payment method" button → opens Customer Portal
- Show "Cancel subscription" / "Reactivate" buttons
- Plan cards: each "Switch to this plan" CTA → calls `createCheckoutSession` for new orgs (no `stripe_customer_id`) or `changePlan` for existing customers
- Annual/monthly toggle

**New `/settings/invoices` page:**
- Table of invoices with date, amount, status, download PDF link
- Empty state: "No invoices yet"

**Landing page (`/`):**
- Pricing cards already exist. When `BILLING_ENABLED=true`, "Get Started" CTA → register flow → upon completion, redirect to `/settings/billing` with the chosen plan pre-selected.
- Add `?plan=starter&cycle=monthly` query support so deep links work.

**TopBar / Sidebar:**
- If `subscription_status === "past_due"`: show amber banner "Payment failed — update your card" linking to portal.
- If `cancel_at_period_end`: show grey banner "Subscription ends on {date} — Reactivate".

### 4.4 Checkout flow (UX)

```
[Click "Switch to Pro" on /settings/billing]
        │
        ▼
[Frontend calls POST /billing/checkout {priceId, cycle}]
        │
        ▼
[Backend creates Checkout Session, returns hosted URL]
        │
        ▼
[Browser redirects to checkout.stripe.com/...]
        │
   ┌────┴────┐
   │         │
[Pays]   [Cancels]
   │         │
   ▼         ▼
[success_url?session_id=cs_...]   [cancel_url]
   │
   ▼
[Frontend shows "Activating..." spinner]
   │
   ▼ (webhook fires in background — checkout.session.completed)
   │
[Backend creates subscription, updates org.plan, org.stripe_subscription_id]
   │
   ▼
[Frontend polls GET /billing/plan every 2s for ≤30s until plan matches]
   │
   ▼
[Confetti / success state]
```

Polling is needed because the redirect can land before the webhook does (rare, but happens). Don't trust the success_url alone.

---

## 5. Implementation phases

### Phase 1 — MVP (≈1 week)
- Stripe account + products/prices in test mode
- DB migration (new columns + tables)
- `POST /billing/checkout` + `POST /billing/portal` endpoints
- Webhook handler with the 7 critical event types
- Settings page: "Switch to plan" buttons launch Checkout, "Manage billing" launches Portal
- Test card flow: `4242 4242 4242 4242` → 3DS card `4000 0027 6000 3184` → declined `4000 0000 0000 0002`
- Manual QA against test mode end-to-end

### Phase 2 — Polish (≈3 days)
- Annual/monthly toggle on plan cards
- Invoice list page
- Past-due / canceling banner UI in TopBar
- Email notifications via Resend on payment failures (in addition to Stripe receipts)
- Billing event audit log surfaced to user

### Phase 3 — Production hardening (≈3 days)
- Switch to live keys + live products
- Stripe Tax enabled (if §2 row 3 = yes)
- Smart Retries configured in dashboard
- Webhook monitoring: alert if >5 failed/unprocessed events in 1h (admin notification)
- `/admin/billing` page: org-level subscription overview, force sync from Stripe button
- Refund admin tool (link to Stripe dashboard, since refunds are rare)
- Backfill: existing orgs on paid plans (community preview era) — offer "lock in your current plan" migration to Stripe before flipping `BILLING_ENABLED`

### Phase 4 — Optional, not blocking launch
- Usage-based pricing for Enterprise Gold (Stripe metered billing)
- Coupons / promo codes (Stripe Coupon objects)
- Multiple payment methods per customer
- Receipt language localisation
- Failed payment dunning emails sent through Resend with our branding

---

## 6. Things to flag (real risk)

### 6.1 This is real money
A bug here can charge customers wrong amounts, double-charge, or fail to charge them at all. Mitigate by:
- All Stripe code paths tested in **test mode** end-to-end before flipping live keys
- Webhook handlers must be **idempotent** (use `StripeEvent.stripe_id` unique constraint)
- Never compute prices client-side — Stripe Price ID is the source of truth
- Feature-flag the live switch — keep `BILLING_ENABLED=false` until you've manually tested at least:
  - Subscribe → cancel → resubscribe
  - Plan upgrade (pro-rated)
  - Plan downgrade (at period end)
  - Payment fails → user updates card → retry succeeds
  - Subscription expires after 3 retries
  - Refund issued in Stripe dashboard reflects in BillingEvent

### 6.2 Webhook failures are silent
If our webhook endpoint is down or returns 5xx, Stripe retries with exponential backoff for ~3 days then gives up. By then the user state can be very wrong. Mitigations:
- Health check on webhook endpoint (200 OK on GET)
- Daily reconciliation cron: list all subscriptions from Stripe, compare to DB, alert on divergence
- Stripe dashboard → Webhooks → shows recent failures; check weekly during MVP

### 6.3 Grandfathering existing users
Anyone who upgraded during the free community preview has their plan set without a Stripe subscription. Decide:
- **Option A:** Force them to checkout at next login, downgrade to Free until they pay
- **Option B:** Keep them on their current plan free for N months, then prompt
- **Option C:** Lock them in at a discounted "early supporter" price forever

Recommendation: **B with email warning 60 days before flip**. Avoid surprise charges.

### 6.4 Refunds & disputes
- Refunds: handled in Stripe dashboard manually for now. Webhook `charge.refunded` should create a `BillingEvent(kind="refund_issued")` so the user sees it in their audit log.
- Disputes (chargebacks): Stripe charges $15 per dispute. Webhook `charge.dispute.created` should alert admin via email + suspend the org until resolved.

### 6.5 SCA / 3D Secure
European cards require Strong Customer Authentication. Stripe Checkout handles this automatically — **do not** use older Charges API or Payment Intents without `automatic_payment_methods=true`. Test with the 3DS test card `4000 0027 6000 3184`.

### 6.6 Currency
Start with **USD only**. Multi-currency adds significant complexity (one Price object per currency, Stripe Tax per region, FX risk). Add later if needed.

### 6.7 Invoicing for Enterprise Gold
Gold is sales-quoted. Two options:
- **Stripe Invoicing:** create one-off Invoice in dashboard, send via email, customer pays via hosted invoice page. No subscription, no recurring.
- **Manual:** wire transfer, invoice via accounting system (Xero/QuickBooks). Stripe not involved.

Recommendation: Stripe Invoicing — keeps audit in one place, supports ACH for big tickets.

---

## 7. Useful Stripe test data

### Test cards (test mode only)
| Number | Behaviour |
|--------|-----------|
| `4242 4242 4242 4242` | Always succeeds |
| `4000 0025 0000 3155` | Requires authentication (3DS), then succeeds |
| `4000 0000 0000 9995` | Insufficient funds — declined |
| `4000 0000 0000 0341` | Attaches OK but next charge fails (good for testing past_due) |
| `4000 0027 6000 3184` | 3DS challenge (forces SCA) |

Any future expiry, any 3-digit CVC, any postcode.

### Stripe CLI cheatsheet
```bash
# Forward webhooks to local dev
stripe listen --forward-to localhost:5000/api/billing/stripe-webhook

# Trigger specific events for testing
stripe trigger checkout.session.completed
stripe trigger invoice.payment_failed
stripe trigger customer.subscription.deleted

# Tail webhook events live
stripe events resend evt_...
```

---

## 8. Open questions for the owner

Decide these before Phase 1 begins:

1. ☐ Decisions §2 rows 1–7 (especially #4 trial model — currently leaning DB-only)
2. ☐ Stripe Tax on or off?
3. ☐ Annual discount — 2 months free (10× monthly) or different?
4. ☐ Currency — USD only at launch, or also GBP/EUR?
5. ☐ Grandfathering policy for community-preview users (recommended: Option B above)
6. ☐ Customer Portal — allow plan switching, or our UI only? (Recommendation: our UI only)
7. ☐ Refund policy text (needed for landing page footer / Terms of Use update)

Once these are answered, the implementation is ~1.5–2 weeks for a polished, production-ready Stripe integration.

---

## 9. Files that will change

```
backend/
  requirements.txt                             # +stripe==11.5.0
  app/models.py                                # +columns on Organization, +StripeEvent, +BillingEvent
  app/billing/routes.py                        # +6 new endpoints
  app/billing/stripe_webhook.py                # NEW — webhook handler
  app/billing/stripe_service.py                # NEW — wrapper around stripe SDK
  app/utils/display_id.py                      # +BL prefix for billing_event
  app/__init__.py                              # register stripe webhook route (no auth)
  migrations/versions/<new>_stripe_billing.py  # NEW migration
  scripts/seed_stripe.py                       # OPTIONAL — automate product/price creation

frontend/
  package.json                                 # +@stripe/stripe-js
  app/lib/api.ts                               # +8 new methods
  app/lib/stripe-config.ts                     # NEW — price ID lookups, plan→price map
  app/(authenticated)/settings/billing/page.tsx # rewrite for Stripe-aware UI
  app/(authenticated)/settings/invoices/page.tsx # NEW
  app/TopBar.tsx                               # +past_due / canceling banners
  app/(unauthenticated)/page.tsx               # pricing CTAs deep-link to checkout

CLAUDE.md                                      # update billing section: Stripe is now wired
docker-compose.yml                             # +5–8 STRIPE_* env passthroughs
.env.example                                   # +all STRIPE_* keys (placeholder values)
```

---

## 10. Suggested next step

1. Owner picks a/b/c for §2 decisions 1–7
2. Owner creates Stripe account in test mode
3. Owner creates products + prices via dashboard, drops the price IDs into a shared doc
4. Owner provides `pk_test_...` and `sk_test_...` keys to the dev env
5. Phase 1 work begins on a feature branch `feat/stripe-mvp`

Estimated effort across all phases: **~2 weeks** of focused work. Phase 1 alone (MVP, test mode only) is **~1 week**.
