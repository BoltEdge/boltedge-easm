# SRS Module 14 — Settings (Org + User)

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 14 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies the user and organisation settings surfaces — profile management, organisation configuration, member management, API keys, integrations management, billing, and audit log access.

Module 09 covers integrations behaviour; this module is about the settings UI surface that lets a user reach those features.

---

## FR-SET-001 — Settings landing page

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The `/settings` route group shall provide a sidebar of subsections, each accessible by URL:

- `/settings/account` — current user profile + MFA
- `/settings/organization` — org name, slug, country, industry, size, website (Owner / Admin)
- `/settings/members` — invitations, member list, role management
- `/settings/api-keys` — API key CRUD
- `/settings/billing` — plan + Stripe portal + receipts
- `/settings/integrations` — Slack / Jira / PagerDuty / webhook / email + audit-log webhook stream
- `/settings/audit-log` — tenant-scoped audit log viewer (FR-AUDIT-003)

---

## FR-SET-002 — User profile

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/settings/account` shall let any authenticated user edit:

**Acceptance criteria:**
- AC-1 First name, last name, job title, company, country.
- AC-2 Password change (requires current password + meets NFR-SEC-002).
- AC-3 MFA enrolment / disable (FR-AUTH-012, FR-AUTH-015).
- AC-4 Email change (FR-AUTH-022).
- AC-5 Account deletion (FR-AUTH-019).

---

## FR-SET-003 — Organisation settings

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/settings/organization` shall let an Owner edit:

**Acceptance criteria:**
- AC-1 Organisation name (slug is immutable after creation).
- AC-2 Country, industry, company size, website.
- AC-3 Audit-log every change.

---

## FR-SET-004 — Member management

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/settings/members` shall let an Admin / Owner:

**Acceptance criteria:**
- AC-1 View the full member list with role, last login, status.
- AC-2 Invite new members by email + role (FR-RBAC-004).
- AC-3 Revoke pending invitations (FR-RBAC-005).
- AC-4 Change a member's role (FR-RBAC-006).
- AC-5 Remove a member (FR-RBAC-007).
- AC-6 [GAP] Suspend a member within the organisation (FR-RBAC-008 partial).

---

## FR-SET-005 — API key management

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/settings/api-keys` shall let an Admin:

**Acceptance criteria:**
- AC-1 Create a new API key with a friendly name; the plaintext key is shown **once** at creation (NFR-SEC-011).
- AC-2 List active API keys (without re-showing plaintext).
- AC-3 Revoke / delete an API key.
- AC-4 Plan-limit-aware (`api_keys` quota).
- AC-5 Audit-log create / delete.

---

## FR-SET-006 — Billing settings

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/settings/billing` shall present (per Module 10):

**Acceptance criteria:**
- AC-1 Current plan + plan_status + next renewal / expiry.
- AC-2 Plan-tier comparison cards with Subscribe / Upgrade / Downgrade buttons.
- AC-3 Stripe Customer Portal link for payment-method management.
- AC-4 Trial-request action for paid tiers (Module 10 FR-BILL-004).
- AC-5 Billing event history.
- AC-6 Receipt download links for past invoices.

---

## FR-SET-007 — Onboarding nudges

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

The settings surface shall integrate with the platform's onboarding nudges:

- AC-1 Each settings page may carry a `<PageHint>` describing what the page does on first visit, dismissable per-user.
- AC-2 The dashboard's setup checklist (driven by `/dashboard/onboarding-progress`) tracks settings actions like "invite a teammate" → links to `/settings/members`.

---

*End of module 14.*
