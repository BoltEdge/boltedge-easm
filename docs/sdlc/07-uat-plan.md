# 07 — User Acceptance Test (UAT) Plan

| Field | Value |
|---|---|
| Document | 07 — UAT Plan |
| Owner | Founder / sole engineer |
| Status | Draft |
| Last reviewed | 2026-05-05 |
| Related docs | `02-srs.md`, `06-test-strategy.md`, `09-sla.md` (forthcoming) |

---

## 1. Purpose

Automated tests (`06-test-strategy.md`) verify that the system behaves as the spec says. UAT verifies that the **system as a whole satisfies the user**: that the intended user journey is achievable, comprehensible, and free of surface-level defects an automated test wouldn't catch (confusing copy, broken visual hierarchy, unintuitive sequencing).

UAT is the last gate before a release reaches users. It is also the structured procedure we run **with a customer** during Enterprise onboarding so the customer signs off that the platform meets their expectation.

---

## 2. Scope

UAT exercises end-to-end user journeys aligned to the SRS modules. It is **not** a redo of integration / E2E tests; the test pyramid handles those. UAT focuses on:

- Whether the **flow** makes sense to a real human, not just whether each step returns 200.
- Whether on-screen guidance and error copy is clear.
- Whether the journey from signup to first value is achievable without external help.
- Whether documented features behave as documented.

UAT is **not in scope** for: load testing, security pen-testing, infrastructure DR drills, code-level review.

---

## 3. When UAT runs

| Trigger | Scope |
|---|---|
| Major release (UI overhaul, new top-level feature, billing flag flip, MFA launch, tier repricing) | Full UAT pass against all journey scripts |
| Each Enterprise customer onboarding | Subset focused on customer's stated use cases + integration setup |
| Quarterly | Smoke pass against the journey scripts to catch regressions in long-tail flows |
| Pre-launch of a new tier or plan structure | Focused on billing journey + plan limits |
| After significant supplier change (Stripe / Resend swap, hypothetical) | Journey scripts that touch the supplier |

UAT is **not** part of every PR. A PR-level gate would force us to either run UAT in 30 seconds (impossible) or block on UAT for routine changes (wasteful). The CI pyramid in `06-test-strategy.md` is the per-PR gate.

---

## 4. Roles

| Role | Responsibility |
|---|---|
| **UAT Lead** | Runs the session; records results; decides pass/fail; raises blockers |
| **Tester** | Executes the journey scripts as a "real user" — does not skip steps because they know how the system works |
| **Customer (Enterprise UAT only)** | Validates against their stated use cases; signs off |
| **Engineer (on-call)** | Available for clarification; not part of the testing — engineering presence biases the test |

For one-engineer scale, the founder plays UAT Lead + Tester, with discipline: no shortcuts, no "it works on my machine" rationalisation. When a second person is available (an early customer, a contractor, an early hire), they run the test and the founder takes notes.

---

## 5. Environments

| Env | Purpose | Reset cadence |
|---|---|---|
| **Local** | Smoke pass during development | per-test |
| **Staging** (when established — see SAD §04 §6.2) | Pre-release UAT | per-release |
| **Production** | Customer onboarding UAT (against the customer's own tenant in a controlled fashion) | n/a — real |

Until staging exists, pre-release UAT runs locally with a production-shaped seed (no real customer data). This is acknowledged as suboptimal — staging is on the SAD scaling roadmap.

For Enterprise UAT in production, we use a **trial / sandbox tenant** for the customer; their primary tenant is not the test subject.

---

## 6. Pre-conditions for a UAT session

Before a session starts:

1. **Build under test is identified** — git SHA, deployment slug, environment URL written down at the top of the session log.
2. **Reset / seed state** — the tenant under test has known starting data (or is empty).
3. **Test accounts are prepared** — distinct emails per role being tested; passwords stored in the session log so the tester can log in.
4. **Known issues are listed** — any open bug that will trip a tester is called out so it is recognised and not re-reported.
5. **Stripe is in test mode** for billing journeys; Stripe test card number documented.
6. **External integrations are reachable** — sandbox Slack workspace, sandbox Jira project, etc.

If any pre-condition is not met, the session is paused, not run on bad ground.

---

## 7. UAT acceptance criteria

A UAT session is **PASS** when:

- All in-scope journey scripts complete without a blocker.
- Any defects found are categorised; no defect is severity-Blocker; severity-Critical defects have an agreed-upon fix or workaround before release.
- Customer (when present) signs off in writing.

A UAT session is **FAIL** when:

- A Blocker defect prevents completion of a critical journey.
- Multiple Critical defects accumulate that the team is not confident can be fixed before release.
- Customer (when present) declines to sign off.

A FAIL ends the release — the build does not ship until issues are addressed and UAT is rerun.

### 7.1 Defect severity

| Severity | Definition | Example |
|---|---|---|
| **Blocker** | The user cannot proceed; no workaround | Login is broken; cannot reach dashboard |
| **Critical** | A documented feature is unusable, or data integrity is at risk | Scan results don't render; billing doesn't update |
| **Major** | A feature works but with a significant flaw; visible to most users | Audit log misses a category; pagination broken on large lists |
| **Minor** | A flaw that is cosmetic or low-impact | Misaligned button; typo in copy |
| **Trivial** | Negligible | Inconsistent capitalisation in one tooltip |

Blocker and Critical defects gate the release. Major / Minor / Trivial are tracked and prioritised.

---

## 8. Journey scripts

Each script is a numbered, narrated walkthrough that a tester executes step-by-step. Below are the core scripts; new scripts are added as new top-level features ship.

### Script 8.1 — New user onboarding (Free tier)

**Goal:** A new user can sign up, verify, log in, add an asset, run a scan, see findings.

```
1.  Open the marketing landing page. Click "Get started free".
2.  Submit the registration form (email, password, org name). Solve the reCAPTCHA.
3.  Confirm the page indicates "check your email".
4.  Open the verification email. Confirm the link does NOT auto-fire any state change.
5.  Click "Verify my email" on the landing page. Confirm a JWT is issued and you reach the dashboard.
6.  From the dashboard, navigate to "Assets". Add a domain you own (use example.com for the test).
7.  From the asset detail page, click "Run quick scan".
8.  Confirm the scan job appears with status=queued, then transitions to running, then completed.
9.  View the findings. Confirm at least one finding renders with severity, title, evidence, and remediation copy.
10. Navigate to "Audit log". Confirm entries for: register, verify_email, login, asset_create, scan_create.
11. Sign out. Confirm redirect to login page.

PASS if every step completes; the dashboard reflects 1 asset, 1 scan, ≥0 findings.
```

### Script 8.2 — Org member invitation + RBAC

**Goal:** Owner invites users in each role; each role has the documented privileges.

```
1.  As the Owner, navigate to Settings → Members. Invite three users with roles:
    Viewer (viewer@…), Analyst (analyst@…), Admin (admin@…).
2.  As each invited user, accept the invitation and log in.
3.  Viewer: confirm read access to assets / scans / findings; confirm "Run scan" button is absent
    or returns an error if accessed; confirm cannot reach Settings.
4.  Analyst: confirm read access + can run scans + can update finding status; confirm cannot
    reach Settings → Members or Settings → Billing.
5.  Admin: confirm full settings access (members, integrations) but Plans/Billing is restricted
    to Owner. Confirm cannot delete the org.
6.  Owner: confirm Plans/Billing surface is reachable.

PASS if each role has exactly the documented privileges, no more and no less.
```

### Script 8.3 — Plan limits

**Goal:** Free-tier limits enforce.

```
1.  As a Free-tier Owner, attempt to add a 3rd asset. Expected: 402/403 with limit message.
2.  Attempt to run a 6th quick scan. Expected: limit message.
3.  Attempt to invite a 2nd member. Expected: limit message.
4.  Attempt to create a 2nd API key. Expected: limit message.
5.  Verify upgrade prompts point to the Plans page (not a payment page if billing flag is off).

PASS if every limit is enforced and the messaging is clear about why and what to do.
```

### Script 8.4 — Billing upgrade (when ENABLE_BILLING=true)

**Goal:** A user can upgrade from Free to Professional via Stripe Checkout (test mode).

```
1.  As Owner on Free, navigate to Plans. Confirm tiers are visible with AUD pricing.
2.  Click "Upgrade to Professional".
3.  Confirm redirect to Stripe-hosted Checkout.
4.  Enter Stripe test card 4242 4242 4242 4242 + any future date + any CVC.
5.  Submit. Confirm redirect back to the app.
6.  Verify the org is on Professional with plan_expires_at ~30 days out.
7.  Verify a receipt email arrives from Resend, sent from a nanoeasm.com address.
8.  Navigate to Plans → "Manage subscription". Confirm Stripe Customer Portal opens.
9.  Cancel the subscription via the portal. Return to the app.
10. Confirm the org's plan reflects scheduled cancellation.

PASS only if every step completes and email arrives within ~5 minutes.
```

### Script 8.5 — Billing flag OFF (current)

**Goal:** With ENABLE_BILLING=false, no pricing is visible and "Switch to" works for free.

```
1.  Open landing page. Confirm pricing section is absent; nav has no "Pricing" link.
2.  Register. Confirm registration copy says "Free to use" (not "no credit card required").
3.  Navigate to Plans. Confirm prices are hidden, buttons say "Switch to this plan".
4.  Click "Switch to Professional". Confirm the org is on Professional with plan_expires_at=NULL
    (no payment, no expiry).
5.  Try the Custom tier — confirm it shows "Contact Us" with a mailto link, not Checkout.

PASS if no payment UI / pricing leaks through anywhere.
```

### Script 8.6 — Discovery → asset onboarding

**Goal:** The discovery feature populates the asset inventory.

```
1.  As an Admin, navigate to Discovery. Submit a root domain (use one the test account owns).
2.  Wait for the discovery job to complete (status transitions visible).
3.  Verify discovered subdomains, IPs, and services appear under Assets.
4.  Verify they are tagged with their kind (subdomain / ip / service / certificate).
5.  Verify discovery did NOT create assets for unrelated domains.

PASS if discovery completes, assets land tenant-scoped to this org, no cross-tenant bleed.
```

### Script 8.7 — Monitoring tick

**Goal:** A monitor runs on schedule and produces a new scan job.

```
1.  As an Admin, mark an asset as monitored with the shortest cadence the plan allows.
2.  Wait for the scheduler to fire (or accelerate by setting next_run_at in the DB if running locally).
3.  Verify a new scan job is created with source=monitor.
4.  Verify scan_job count increments against scans_per_month.
5.  Verify findings produced by the monitor are linked to the scan job.

PASS if the scheduled run executes without manual trigger and counts correctly.
```

### Script 8.8 — API key surface

**Goal:** A customer can use API key to run an opted-in operation.

```
1.  As an Admin, create an API key in Settings → API Keys. Copy the plaintext (shown once).
2.  Run a curl command against an opted-in route, e.g.:
       curl -H "Authorization: Bearer $KEY" https://nanoeasm.com/api/assets
    Verify a 200 with tenant-scoped assets.
3.  Run against a non-opted-in route (e.g. /api/billing/upgrade). Verify 403 API_KEY_NOT_ALLOWED.
4.  Revoke the key. Re-run step 2. Verify 401 immediately.

PASS if every assertion holds.
```

### Script 8.9 — Audit-log webhook stream (Enterprise Gold / Custom)

**Goal:** Customer-configured webhook receives signed events.

```
1.  As an Enterprise Gold Owner, configure the audit webhook with a URL pointing to a sandbox
    receiver (e.g., webhook.site).
2.  Confirm the secret is shown once and masked thereafter.
3.  Click "Send test event". Verify the receiver received a POST with X-Nano-Signature.
4.  Compute HMAC-SHA256 of the body with the secret; verify it matches the header.
5.  Perform any privileged action (e.g., role change). Verify the receiver received an event.
6.  Inspect Settings → Recent deliveries. Verify the success entry is recorded.

PASS if signature verifies and recent-deliveries panel reflects activity.
```

### Script 8.10 — Public quick-scan abuse protection

**Goal:** Anonymous quick-scan rate-limits and IP-blocks correctly.

```
1.  As an unauthenticated browser, run a quick scan. Confirm result.
2.  Repeat 5 times. Confirm scans complete each time.
3.  On the 6th attempt within an hour, confirm a 429 with a clear message.
4.  As superadmin, navigate to /admin/quick-scans. Confirm the requesting IP appears
    with status=rate_limited.
5.  Block the IP via the admin UI. Confirm subsequent attempts return 403.

PASS if rate-limit and block both behave as documented.
```

### Script 8.11 — Superadmin impersonation

**Goal:** Impersonation works, is audit-logged, and can be exited cleanly.

```
1.  As superadmin, navigate to /admin/users. Pick a non-superadmin target.
2.  Click "Impersonate". Verify the amber banner "Impersonating <name>" appears.
3.  Browse the target tenant. Verify it looks as the target would see it.
4.  Click "Exit impersonation". Verify the banner clears and you return to /admin/users.
5.  Open /admin/audit-log. Filter for category=admin. Verify impersonate_start AND
    impersonate_end events are recorded with both actor and target.

PASS if banner / audit / exit all behave correctly.
```

### Script 8.12 — Free-tier expiry (90-day lifecycle)

**Goal:** The expiry lifecycle behaves per FR-BILL-002.

This script requires time-travel to verify; in practice we run it locally with a fixture that
sets `free_expires_at` to past dates and triggers the scheduler tick directly.

```
1.  Set free_expires_at to NOW. Trigger the expiry job.
2.  Verify is_login_blocked=true, grace_starts_at=NOW.
3.  Attempt login. Verify 403 FREE_TIER_EXPIRED with upgrade_url.
4.  Set grace_starts_at to NOW - 30d. Trigger the expiry job.
5.  Verify the org is hard-deleted (cascade through assets, scans, findings, members).
6.  Verify any user who belonged to this org alone is also deleted (per delete_organization
    orphan-user fix).

PASS if both expiry and grace-cleanup behave as documented.
```

### Script 8.13 — Reporting and exports

**Goal:** PDF and Excel reports generate and reflect current data.

```
1.  As an Analyst, generate a PDF report for a completed scan. Confirm download succeeds.
2.  Open the PDF. Confirm: header has org + scan id, findings table has correct severity counts,
    compliance section reflects mappings.
3.  Generate an Excel export of findings. Open it. Confirm rows match the in-app filter.
4.  Generate a Compliance report (PDF). Confirm the language hedges SOC 2 / ISO 27001 with
    "may inform compliance evidence — verify with auditor", not "audit-ready".

PASS if reports render correctly and compliance copy is accurate.
```

---

## 9. Customer-onboarding UAT subset (Enterprise)

When onboarding an Enterprise customer, we run a focused subset:

- **Always:** 8.1 (onboarding), 8.2 (RBAC), 8.6 (discovery), 8.7 (monitoring), 8.8 (API key), 8.13 (reporting).
- **If billing applies:** 8.4.
- **If audit-webhook stream applies:** 8.9.
- **Customer-specific:** any integration the customer asked for (Slack, Jira, custom audit-webhook receiver against their SIEM).

The customer's UAT script lives in their onboarding doc and is signed off in writing.

---

## 10. Session log template

Every UAT session is recorded. The minimum log:

```
UAT Session — <date>
Build under test: <git SHA / deployment slug>
Environment: <local | staging | prod-sandbox>
Scope: <which scripts>
Tester: <name>
UAT Lead: <name>

Pre-conditions:
- [x] Tenant seeded
- [x] Stripe in test mode
- [x] Known issues listed

Script 8.1 — New user onboarding
  Step 1: PASS
  Step 2: PASS
  Step 3: PASS
  Step 4: PASS
  Step 5: PASS
  Step 6: PASS
  Step 7: PASS
  Step 8: PASS — scan completed in 47 seconds
  Step 9: PASS — 4 findings rendered
  Step 10: FAIL — audit log entry for verify_email is missing → DEFECT-2026-05-05-01 (Major)
  Step 11: PASS

[... etc per script ...]

Defects raised:
- DEFECT-2026-05-05-01 — Major — verify_email audit row missing
- DEFECT-2026-05-05-02 — Minor — pagination on findings page jumps on filter change

Outcome: PASS-WITH-DEFECTS — Major defect blocks release until fixed.
Sign-off: <name>, <date>
```

The log is committed to `docs/uat-sessions/` (when established) so historical sessions are auditable.

---

## 11. Defect handling

- **Blocker / Critical:** halt the release. Engineering fixes; UAT reruns affected scripts.
- **Major:** decided per release. The Lead may choose to ship with a documented workaround if the fix is non-trivial and the workaround is acceptable.
- **Minor / Trivial:** filed for follow-up; do not gate the release.

Every defect has: id, severity, reproduction steps, affected script, owning engineer, target fix release.

---

## 12. UAT in the agile cadence

UAT is **not** done at the end of every two-week sprint. It is event-driven (§3) so that the team treats it as a gate for material changes, not a ritual to perform on routine releases. Routine releases are gated by the test pyramid in `06-test-strategy.md`.

When UAT fails, the team's response is to **strengthen the relevant integration / E2E test** so future releases catch the same regression earlier. UAT failures that are caught only at UAT — and not by the test pyramid — are signals that the pyramid has a gap.

---

## 13. Tools

- **Session logs:** Markdown files in `docs/uat-sessions/` (when established).
- **Defect tracker:** GitHub Issues, label `uat-defect`.
- **Test data:** Faker-generated where possible; hand-curated where realism matters (e.g. realistic asset names for Enterprise UAT).
- **Screen recording (optional, for hard-to-describe defects):** screen-recorder of choice; recordings linked from defect issues.

---

## 14. References

- `02-srs.md` — the contract UAT is verifying
- `06-test-strategy.md` — automated tests that gate routine releases
- `09-sla.md` (forthcoming) — uptime / response targets that UAT helps the team meet
- CLAUDE.md "Plan tiers and limits" — limits referenced by Script 8.3

---

*End of 07 UAT Plan.*
