# Positioning Pivot — Task List

## Document Control

| Field | Value |
|---|---|
| Document ID | SDLC-00 |
| Title | Positioning Pivot — Task List |
| Status | Open — tracking active work |
| Owner | [TBD — founder name] |
| Created | 2026-05-05 |
| Triggered by | Charter rewrite removing open-source / community-preview positioning; Free tier becomes 90-day evaluation with login-block + 30-day retention (option **c**) |
| Related documents | 01 Vision & Charter |

This is a **transient operational document**, not a long-lived SDLC artefact. It tracks the codebase, copy, configuration, and process changes required to land the positioning shift described in the charter. Once every task is closed, this file should be archived (move to `docs/sdlc/archive/`) so it doesn't pretend to be authoritative for new work.

Status legend:

- **TODO** — not started
- **IN PROGRESS** — actively being worked on
- **DONE** — merged / deployed / verified
- **DEFERRED** — explicitly chosen to defer, with rationale

Priority legend:

- **P0** — blocks the pivot; product is internally inconsistent until done
- **P1** — required before the new positioning is exposed externally
- **P2** — nice-to-have polish; can ship after the pivot is live
- **DECISION** — not a code task; founder decision required before related code tasks can proceed

---

## 1. Configuration & Feature Flags

| ID | Task | Priority | Status | Notes |
|---|---|---|---|---|
| 1.1 | Flip backend env: `ENABLE_BILLING=false` → `true` in `.env`, EC2 systemd / docker-compose, and the production secrets store | P0 | TODO | Backend reads via `os.environ.get("ENABLE_BILLING", "false")` in `app/billing/routes.py` |
| 1.2 | Flip frontend env: `NEXT_PUBLIC_ENABLE_BILLING=false` → `true` in `.env.local` and the production build env | P0 | TODO | Read via `lib/billing-config.ts` → `BILLING_ENABLED`. **Reminder: `NEXT_PUBLIC_*` vars are baked at build time — needs `--no-cache` rebuild on EC2.** |
| 1.3 | Audit every code path that branches on `BILLING_ENABLED` / `ENABLE_BILLING` and confirm the `=true` branch is the intended behaviour | P0 | TODO | Greppable: `BILLING_ENABLED`, `ENABLE_BILLING`. Includes pricing page, register page, monitoring upgrade prompt, sidebar label, topbar trial badge, monitoring scheduler. |

---

## 2. Backend — Free-tier 90-day Expiry (option c)

The chosen Free-tier expiry behaviour:

> At day 90, the tenant is **login-blocked** with a clear "upgrade to keep your data" screen. Data is retained for **30 days** of grace. If the tenant upgrades within those 30 days, full access resumes. After 30 days of grace (day 120 total), the tenant + all data is hard-deleted.

This needs to follow the existing `Organization.plan_status` lifecycle and reuse the existing trial-expiry scheduler patterns where possible.

| ID | Task | Priority | Status | Notes |
|---|---|---|---|---|
| 2.1 | Add `expires_after_days: 90` (or equivalent) to `PLAN_CONFIG["free"]` in `app/billing/routes.py` | P0 | TODO | Single source of truth for the duration |
| 2.2 | Migration: ensure every existing Free org gets an `expires_at` timestamp (use `created_at + 90 days` for legacy orgs, `now() + 90 days` for any in flight) | P0 | TODO | One-shot migration; add to `backend/migrations/versions/`. Use the existing `org.plan_expires_at` column if appropriate, or add a dedicated `free_tier_expires_at` if `plan_expires_at` semantics conflict |
| 2.3 | Scheduled job: every hour, find Free orgs whose `expires_at` is in the past and `plan_status != "expired"`, set `plan_status = "expired"`, log audit event `billing.free_tier_expired` | P0 | TODO | Reuse APScheduler. Mirror the existing `check_expired_trials()` pattern in `app/billing/routes.py` |
| 2.4 | Login gate: in `app/auth/routes.py` `login()`, if `org.plan == "free"` AND `org.plan_status == "expired"`, return a specific 403 with code `FREE_TIER_EXPIRED` and the org's grace-period end date | P0 | TODO | Distinct from `ACCOUNT_SUSPENDED` so the frontend can route to the upgrade screen |
| 2.5 | Upgrade flow: when an expired-Free org completes a paid checkout, `plan_status` flips from `expired` → `active` and `plan` flips to the new tier; subsequent logins succeed | P0 | TODO | Already handled by `/billing/upgrade` for non-expired orgs — verify it also covers `expired` state |
| 2.6 | Scheduled job: every hour, find orgs that have been `plan_status == "expired"` for >30 days; hard-delete via the same path used by `delete_organization()` (org + orphaned single-org users) | P0 | TODO | Audit-log each deletion; honour the `is_superadmin` skip rule from `delete_organization` |
| 2.7 | Admin endpoint: `POST /admin/organizations/<id>/extend-free-tier` for the superadmin to add days to a Free org's `expires_at` (used for partner / friendly extensions) | P2 | TODO | Audit-logged; bounded (e.g., max +90 days per call) |
| 2.8 | Audit-log entries for every state transition: `billing.free_tier_expired`, `billing.free_tier_extended`, `billing.free_tier_data_deleted` | P1 | TODO | Use the existing `log_audit()` helper |

---

## 3. Backend — Email Notifications for Free Expiry

| ID | Task | Priority | Status | Notes |
|---|---|---|---|---|
| 3.1 | Email template: "10 days left on your Free tier" sent at day 80 | P1 | TODO | Reuse `app/utils/email_shell.py` shell. Add to a new `app/billing/free_expiry_emails.py` |
| 3.2 | Email template: "3 days left on your Free tier" sent at day 87 | P1 | TODO | Same module |
| 3.3 | Email template: "Your Free tier has expired" sent at day 90 (with upgrade CTA + clear "data is retained for 30 days" line) | P0 | TODO | Same module. Without this, expiry is silent and feels broken |
| 3.4 | Email template: "Data deletion in 7 days" sent at day 113 | P1 | TODO | Last-chance recovery prompt |
| 3.5 | Email template: "Your data has been deleted" sent at day 120 | P2 | TODO | Closing-the-loop courtesy email; required to avoid GDPR / Privacy Act surprise |
| 3.6 | Schedule trigger: extend the per-hour scheduler to dispatch each of the above based on org age + last-sent timestamp; idempotent (track last-sent in a `org.free_tier_email_state` JSON column or per-template flags) | P0 | TODO | Without idempotency tracking the user gets the same email every hour after the threshold passes |

---

## 4. Backend — Stripe Verification (Go-live)

These are not new code, they're a verification pass on existing Stripe wiring before flipping `ENABLE_BILLING=true`.

| ID | Task | Priority | Status | Notes |
|---|---|---|---|---|
| 4.1 | Confirm AUD prices for Starter / Pro / Silver / Gold (monthly + annual) exist in the Stripe dashboard at the values currently in `PLAN_CONFIG` | P0 | TODO | Founder action in Stripe console. Note IDs in env vars (`STRIPE_PRICE_STARTER_MONTHLY`, etc.) |
| 4.2 | Verify `/billing/checkout` opens hosted Checkout in Stripe **test mode** with valid AUD prices | P0 | TODO | Use Stripe's test cards (`4242 4242 4242 4242`) |
| 4.3 | Verify `/billing/portal` opens the Customer Portal and lets a test subscription be cancelled / updated | P0 | TODO | |
| 4.4 | Verify the `/billing/stripe-webhook` endpoint is reachable from Stripe (test webhook from dashboard); confirm signature verification rejects spoofed calls | P0 | TODO | Webhook secret env var must be set |
| 4.5 | Verify webhook idempotency by replaying the same event twice — should be a no-op the second time | P0 | TODO | Stripe events are stored with their `id` in the `stripe_event` table |
| 4.6 | Verify receipt / payment-failed / refund emails come from `no-reply@nanoeasm.com` via Resend (not Stripe's defaults). Disable Stripe's "automatic customer emails" in the dashboard | P0 | TODO | Otherwise customers get duplicate receipts |
| 4.7 | Switch Stripe from test mode → live mode; rotate API keys; rotate webhook secret | P0 | TODO | **One-way switch** — do this last, after every other Stripe task verifies in test mode |
| 4.8 | Sanity check: register a fresh test account, hit Free tier, upgrade to Starter via Checkout, verify plan flips and limits expand | P0 | TODO | End-to-end smoke test before announcing |

---

## 5. Frontend — Copy & UI Updates

Every place that currently says "free during community preview", "free upgrade tiers", "switch to this plan" (when it should say "subscribe") or hides pricing needs a pass.

| ID | Task | Priority | Status | Notes |
|---|---|---|---|---|
| 5.1 | Landing page (`frontend/app/(unauthenticated)/page.tsx`): pricing section becomes visible by default; hero CTA changes from "Get started free" to "Try free for 90 days"; "Pricing" nav link visible | P0 | TODO | Most of this is automatic once `BILLING_ENABLED=true`, but verify the copy matches the new positioning (no "preview" / "community" language) |
| 5.2 | Register page (`frontend/app/(unauthenticated)/register/page.tsx`): "Free to use" → "Free for 90 days. No credit card required." | P0 | TODO | Reflects the actual offer |
| 5.3 | Plans page (`frontend/app/(authenticated)/settings/billing/page.tsx`): prices visible, trial buttons visible (where eligible), "Switch to this plan" → "Subscribe to {plan}" / "Upgrade to {plan}" / "Downgrade to {plan}" depending on direction | P0 | TODO | Most of this is gated on `BILLING_ENABLED` — verify after flip |
| 5.4 | Sidebar (`frontend/app/Sidebar.tsx`): "Plans" → "Payment & Plans" | P0 | TODO | Already gated on `BILLING_ENABLED` |
| 5.5 | Monitoring upgrade prompt (`frontend/app/(authenticated)/monitoring/page.tsx`): prices visible, "Switch to {plan}" → "Start trial" / "Subscribe to {plan}" | P0 | TODO | |
| 5.6 | TopBar (`frontend/app/TopBar.tsx`): trial countdown badge visible when applicable | P1 | TODO | Already gated on `BILLING_ENABLED` |
| 5.7 | New countdown UI: in-app banner showing "X days left on your Free tier" once the org is within 30 days of expiry, with an inline "Upgrade now" CTA | P0 | TODO | Probably mounted in `(authenticated)/layout.tsx` next to `<AnnouncementBanners />` |
| 5.8 | Expired-Free login screen: when login returns `FREE_TIER_EXPIRED`, route to a dedicated screen explaining the expiry, the 30-day grace period, and providing a one-click upgrade path that hops straight into Checkout | P0 | TODO | New page: `frontend/app/(unauthenticated)/free-tier-expired/page.tsx` |
| 5.9 | Search project for `community preview`, `Community Preview`, `free upgrade`, `during preview`, `community-preview` strings; either remove or rephrase each one | P0 | TODO | Run: `grep -rn "community preview\|community-preview\|free upgrade\|during preview" frontend/ --exclude-dir=node_modules` |
| 5.10 | FAQ content (`frontend/app/(unauthenticated)/faq/`): scrub OSS / community preview references; add Q&A covering "What happens when my Free tier expires?" / "Can I extend my Free tier?" / "Will my data be deleted?" | P1 | TODO | |
| 5.11 | Onboarding tour copy (`frontend/app/ui/OnboardingTour.tsx`): make sure no step assumes "free forever" or hides paid features | P2 | TODO | Probably already neutral — quick read-through |

---

## 6. Documentation — `CLAUDE.md`

`CLAUDE.md` is the source of truth for anyone (human or LLM) coming into the codebase. Several sections describe the current state as open-source / community preview / billing-off.

| ID | Task | Priority | Status | Notes |
|---|---|---|---|---|
| 6.1 | Section "Current Product Status (v2 — April 2026)": rewrite. Drop "open-source", drop "free to use during community preview", drop "free upgrade tiers", drop "all pricing/payment/subscription/checkout/trial wording is hidden from the UI" | P0 | TODO | Replace with: "Nano EASM is a freemium SaaS — Free (90-day) plus paid tiers (Starter, Professional, Enterprise Silver, Enterprise Gold, Custom). Billing is live. Stripe is the payment processor." |
| 6.2 | Section "Billing Feature Flag": rewrite. The flag still exists for emergency switch-off but the default state is now `true`. Document the kill-switch use case but don't lead with it | P0 | TODO | |
| 6.3 | Section "Plan tiers and limits": add the 90-day Free expiry behaviour to the Free row | P0 | TODO | Update the tier table to mention "90-day evaluation" against Free |
| 6.4 | Add a new subsection "Free-tier lifecycle" describing the 90-day evaluation, the 30-day grace, the email cadence, and the data-deletion behaviour | P0 | TODO | Becomes the single reference for the lifecycle so future work doesn't drift |
| 6.5 | Search `CLAUDE.md` for any other "open-source", "community preview", "free during preview" references; remove or rephrase | P0 | TODO | |

---

## 7. Repo & Branding Decisions

The repo has been private since creation, and no `LICENSE` or `README` file exists at the repo root. Most of the original §7 decisions are therefore already resolved by the existing state. Only one founder decision remains.

| ID | Item | Priority | Status | Notes |
|---|---|---|---|---|
| 7.1 | GitHub repo state | n/a | DONE | Repo has always been private. No code or commit-history audit required. |
| 7.2 | License file | n/a | DONE | No `LICENSE` file at repo root. Nothing to remove. (If a customer ever requests a written redistribution / use license, that's a sales-driven addition, not a pivot task.) |
| 7.3 | README at repo root | P2 | TODO | Currently absent. A short internal README for engineer onboarding (env setup, run commands, deploy) is worth adding *eventually* but doesn't block the pivot. **`CLAUDE.md` already serves this role for the LLM/dev-tooling case** — only humans cloning the repo fresh would benefit from a README. |
| 7.4 | Public quick-scan tool: stays public (top-of-funnel) or moved behind login? | DECISION | TODO | Recommend stays public — abuse protection already in place via rate limit + IP block list. Conversion-to-signup funnel benefit outweighs minor abuse risk. |

---

## 8. Documentation — Other SDLC Documents That Will Inherit This

These don't need rewriting yet but they will need to assume the new positioning when written. Listing here so I don't have to flag it again in each one.

| ID | Document | Notes |
|---|---|---|
| 8.1 | 02-srs.md | Free-tier lifecycle is a functional requirement; spec it precisely (state machine, transitions, allowed actions per state). Pricing tiers + limits get a section. No "preview" language. |
| 8.2 | 03-sad.md | The free-expiry scheduler is a deployment component; document it. Stripe is now part of the runtime architecture, not a future addition. |
| 8.3 | 04-threat-model.md | Free-tier abuse (re-registration, throwaway emails) is an attacker scenario. Stripe webhook spoofing is a threat surface. |
| 8.4 | 09-sla.md | SLA is now real (paying customers will read it). Frame uptime, support response, and refund policy honestly. |
| 8.5 | 10-dpa.md | Real customers will request a signed DPA. Stub now, polish before EU customer asks. |

---

## 9. Out of scope (deliberately not doing as part of this pivot)

Documenting what's **NOT** changing so future you doesn't try to bundle it in.

- **Existing trial-request flow** (admin-reviewed `ContactRequest` of type `trial`) — stays as-is. The Free tier is a separate path; trial of *paid* tiers still goes through admin approval.
- **API keys / RBAC / audit log** — unaffected by the positioning pivot.
- **Multi-currency support** — still AUD-only. Adding USD or EUR is its own project.
- **Self-hosted offering** — explicitly out of scope per the charter.

---

## 10. SRS-driven gap inventory

The following gaps surfaced while drafting the SRS (`02-srs.md` + `02-srs/*`). Each is a real product feature mentioned in the spec but not yet implemented in production. Listed here so they have a tracking home outside the SRS itself, since the SRS is prescriptive (states intent) and the pivot doc is operational (tracks work).

### 10.1 Multi-Factor Authentication (MFA) — net new

| ID | Task | Priority | Status | Spec ref |
|---|---|---|---|---|
| 10.1.1 | TOTP enrolment flow at `/settings/account/mfa` (QR code + secret + confirmation) | P0 | TODO | FR-AUTH-012 |
| 10.1.2 | TOTP verification at login (mfaRequired path, ±1 step skew, ≤5 attempts/challenge) | P0 | TODO | FR-AUTH-013 |
| 10.1.3 | Recovery codes (10 per user, single-use, hashed at rest, regenerable) | P0 | TODO | FR-AUTH-014 |
| 10.1.4 | MFA disable flow (require password + current TOTP) | P0 | TODO | FR-AUTH-015 |
| 10.1.5 | Org-required MFA for elevated roles (Owner-toggle) | P1 | TODO | FR-AUTH-016 |
| 10.1.6 | Required MFA for superadmin accounts (block `/admin/*` until enrolled) | P0 | TODO | FR-AUTH-017 |
| 10.1.7 | DB migration: `User.mfa_enabled`, `User.mfa_secret_encrypted`, `MfaRecoveryCode` table | P0 | TODO | (schema) |
| 10.1.8 | Audit-log entries: `auth.mfa_enabled` / `auth.mfa_disabled` / `auth.mfa_recovery_code_used` / `auth.mfa_verify_*` | P0 | TODO | (audit) |
| 10.1.9 | UI for MFA enrolment, verification step at login, recovery code display, settings page | P0 | TODO | (frontend) |
| 10.1.10 | TOTP secret encrypted at the application layer using a key from outside the database (NFR-SEC-009 AC-3) | P0 | TODO | (security) |

### 10.2 Other gaps surfaced

| ID | Task | Priority | Status | Spec ref |
|---|---|---|---|---|
| 10.2.1 | Session token revocation list (so a password reset / explicit logout invalidates other live sessions) | P1 | TODO | FR-AUTH-009 AC-4 |
| 10.2.2 | Account lockout after 10 failed login attempts in 10 minutes | P1 | TODO | NFR-SEC-024 |
| 10.2.3 | Breach-list password rejection at registration / reset (HIBP k-anonymity API) | P1 | TODO | NFR-SEC-002 AC-2 |
| 10.2.4 | Application-layer encryption for sensitive single-value fields (API key plaintext at issue, OAuth tokens, integration secrets) | P0 | TODO | NFR-SEC-009 AC-3 |
| 10.2.5 | Self-serve account deletion UI for non-Owner members | P1 | TODO | FR-AUTH-019 |
| 10.2.6 | Email change flow with new-address verification | P2 | TODO | FR-AUTH-022 |
| 10.2.7 | Owner transfer flow | P2 | TODO | FR-RBAC-013 |
| 10.2.8 | In-org member suspension by Owner / Admin (today only superadmin can suspend) | P1 | TODO | FR-RBAC-008 |
| 10.2.9 | Cross-org switcher (a single user belonging to multiple orgs picks active org per session) | P2 | TODO | FR-RBAC-003 AC-2 |
| 10.2.10 | Manual finding creation (analyst records a finding outside a scan) | P1 | TODO | FR-FIND-010 |
| 10.2.11 | Webhook delivery retry with exponential backoff | P1 | TODO | FR-INT-008 |
| 10.2.12 | In-app per-user notification feed / inbox UI | P1 | TODO | FR-INT-009 |
| 10.2.13 | Per-recipient unsubscribe-from-this-rule link in email notifications | P2 | TODO | FR-INT-010 AC-4 |
| 10.2.14 | Quiet-hours queue+release for non-critical events | P1 | TODO | FR-INT-012 |
| 10.2.15 | Audit log automated retention roll-off (1-2y target) | P1 | TODO | FR-AUDIT-005 |
| 10.2.16 | DB-level UPDATE/DELETE revoke on `audit_log` table for the application user | P1 | TODO | FR-AUDIT-006 |
| 10.2.17 | Verify Quick-Scan form has a honeypot field | P2 | TODO | FR-QSC-009 |
| 10.2.18 | Admin verification-cleanup tool (bulk reset users in broken email_verified state) | P2 | TODO | FR-ADM-015 |
| 10.2.19 | Per-API-key rate limiting (600/h read, 60/h write) | P1 | TODO | FR-API-005 |
| 10.2.20 | OpenAPI 3.x spec at `/api-docs/openapi.json` | P2 | TODO | FR-API-008 |
| 10.2.21 | API key `Idempotency-Key` header support | P1 | TODO | FR-API-012 |
| 10.2.22 | Automated dependency vulnerability scanning (weekly) | P1 | TODO | NFR-SEC-022 |
| 10.2.23 | Centralised secrets manager (move off env-files when team > 1) | P0 (when team grows) | TODO | NFR-SEC-010 AC-4 |
| 10.2.24 | Backend physical / WAL-archive PITR backups (currently logical-only) | P0 | TODO | NFR-REL-002 AC-2 |
| 10.2.25 | Self-serve DSAR (data export) flow | P1 | TODO | NFR-COMP-003 |
| 10.2.26 | Formal WCAG 2.1 AA audit of the web app | P1 | TODO | NFR-USAB-003 |
| 10.2.27 | NFR baseline measurements (latency, scan time, concurrent tenants) → replace placeholder targets with measured values | P1 | TODO | NFR-PERF-001..010 |
| 10.2.28 | Test-coverage measurement + CI gate (≥70% line, ≥90% on auth/billing/RBAC) | P1 | TODO | NFR-MAINT-003 |
| 10.2.29 | Structured (JSON) application logs with PII masking | P1 | TODO | NFR-MAINT-004 |
| 10.2.30 | Background job retry with exponential backoff | P1 | TODO | NFR-REL-005 |

---

*End of Document. Archive this file once every P0 and P1 task is DONE or DEFERRED with rationale.*
