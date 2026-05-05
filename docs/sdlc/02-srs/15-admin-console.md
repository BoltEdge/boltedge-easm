# SRS Module 15 — Admin / Superadmin Console

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 15 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies the platform-administration console accessible only to users with the `is_superadmin` flag. The console manages tenants, users, abuse, broadcast announcements, contact requests, audit log, active scans, and platform health.

Mention of "admin" in this module always means **superadmin** (platform-level), distinct from organisation Admin role.

---

## FR-ADM-001 — Hidden access

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The console shall be reachable at `/admin/*` and:

**Acceptance criteria:**
- AC-1 Return a generic HTTP 404 to non-superadmins for every `/admin/*` route — neither the route's existence nor the user's privilege state shall be revealed.
- AC-2 Authentication is required (the user must be logged in to be evaluated as superadmin).
- AC-3 The superadmin flag is granted only via a Flask CLI command; there is no UI to grant or revoke it (intentional, prevents privilege escalation).
- AC-4 The check re-fetches the user from the database on every request — JWT-only trust is not sufficient.
- AC-5 Superadmin login also requires MFA (FR-AUTH-017).

---

## FR-ADM-002 — Console layout

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The admin console shall present a left-side navigation grouped as:

- **Dashboard** — platform-wide stats, plan distribution, KPI overview
- **People & Tenants** — Organizations, Users, Billing
- **Requests & Communication** — Contact Requests, Broadcast
- **Activity & Operations** — Active Scans, Quick Scans, Audit Log
- **Platform Health** — Health

---

## FR-ADM-003 — Organisations management

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/admin/organizations` shall let a superadmin:

**Acceptance criteria:**
- AC-1 List all orgs paginated with search, plan filter, and archived filter.
- AC-2 View detail (`/admin/organizations/<id>`): plan, members, usage counts, custom limit overrides, billing context, archived/suspended toggles.
- AC-3 Change an org's plan (any tier) — auto-detects associated trial requests and emails the requester (Module 10 FR-BILL-005).
- AC-4 Set per-org custom limits (`limit_overrides` JSON) overriding plan defaults.
- AC-5 Archive / restore an org.
- AC-6 Suspend / unsuspend an org (blocks all member logins with `ACCOUNT_SUSPENDED`).
- AC-7 Hard-delete an org and cascade all data (with confirmation and audit log).

---

## FR-ADM-004 — Users management

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/admin/users` shall let a superadmin:

**Acceptance criteria:**
- AC-1 List all users paginated with search, role filter, organisation filter, suspended filter, verified filter, superadmin filter.
- AC-2 Bulk-select with sticky action bar; bulk actions: suspend, unsuspend, resend verification, force-verify, delete. Superadmin and self-targets are skipped automatically with reason.
- AC-3 Per-row actions: send email (FR-ADM-005), open request (FR-ADM-006), impersonate (FR-AUTH-020), reset password, force-verify, resend verification, suspend/unsuspend, delete.
- AC-4 User detail page (`/admin/users/<id>`): full profile, all org memberships, recent audit log (last 20 by this user), open contact requests from this user, capability buttons inline.
- AC-5 The list username is clickable — links to detail page.

---

## FR-ADM-005 — Send email to a user

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A superadmin shall be able to compose and send an ad-hoc branded email to any user.

**Acceptance criteria:**
- AC-1 Subject (≤ 200 chars) + plain-text body (≤ 8000 chars).
- AC-2 Body is HTML-escaped before insertion into the email shell — admin-supplied raw HTML is not honoured.
- AC-3 Email originates from `no-reply@nanoasm.com` via Resend.
- AC-4 Audit-log `admin.user_email_sent` with subject + 500-char body excerpt + delivery status.
- AC-5 Returns HTTP 502 with `EMAIL_NOT_SENT` if Resend is misconfigured / unavailable; the audit log still records the attempt.

---

## FR-ADM-006 — Create request on behalf of user

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A superadmin shall be able to open a `ContactRequest` on a user's behalf — useful when a user reported something via phone / email outside the platform.

**Acceptance criteria:**
- AC-1 Type: general / trial / demo. Subject optional. Message required. Internal note optional (never sent to user).
- AC-2 The created `ContactRequest` carries a provenance line in `admin_notes` identifying the admin who created it on behalf of which user.
- AC-3 The internal note is stored after the provenance line.
- AC-4 Audit-log `admin.user_request_created`.

---

## FR-ADM-007 — Contact requests management

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/admin/contact-requests` shall present the queue of all contact requests with type filter, status filter, search. A superadmin may:

**Acceptance criteria:**
- AC-1 View detail with full message, internal notes, requester context.
- AC-2 Reply via a built-in compose UI (sends an email, marks request as replied).
- AC-3 Update status (open / in_progress / replied / closed / spam).
- AC-4 Audit-log status changes.

---

## FR-ADM-008 — Broadcast announcements

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/admin/broadcast` shall let a superadmin create dismissible banner announcements:

**Acceptance criteria:**
- AC-1 Kind (info / warning / critical), title, optional body, optional target organisation (NULL = all), optional expiry.
- AC-2 Active announcements are shown to authenticated users in their organisation via `GET /auth/announcements` and rendered above page content.
- AC-3 Dismissed announcement IDs are stored client-side; dismissal survives reload.
- AC-4 Audit-log `admin.announcement_created` / `admin.announcement_deleted`.

---

## FR-ADM-009 — Active scans monitor

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/admin/scans` shall present a live view of in-flight scan + discovery jobs across all organisations, auto-refreshing every 15 seconds. A superadmin may cancel a job from this view.

---

## FR-ADM-010 — Quick scan abuse view

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/admin/quick-scans` shall present (per Module 13):

**Acceptance criteria:**
- AC-1 Quick Scan log paginated with date, IP, target, status, risk score.
- AC-2 Top-IPs leaderboard (last 24 hours).
- AC-3 IP block-list management (FR-QSC-008).

---

## FR-ADM-011 — Platform health view

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/admin/health` shall present:

**Acceptance criteria:**
- AC-1 Database ping + connection-pool stats.
- AC-2 Job queue depths (pending scans, pending discoveries, pending reports).
- AC-3 Error rates (count of `failed` jobs in trailing 24h).
- AC-4 Uptime indicator (process start time, current time).
- AC-5 Platform-wide totals (orgs, users, assets, scans, findings, monitors).

---

## FR-ADM-012 — Platform stats

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/admin/dashboard` shall present:

**Acceptance criteria:**
- AC-1 Counts: total organisations (active vs archived), total users, total assets, total scans (all-time, last 30 days), total findings.
- AC-2 Plan distribution chart.
- AC-3 New signups last 7 / 30 days.

---

## FR-ADM-013 — All admin actions audit-logged

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Every superadmin action shall produce an audit log entry in the `admin` category, with the actor's email captured in metadata. Admin grants do not set `plan_expires_at` (admin-set plans don't expire).

---

## FR-ADM-014 — Free-tier extension (admin)

**Priority:** P2 — Could
**Status:** [GAP: not yet implemented — pivot 2.7]

A superadmin shall be able to extend a Free org's `expires_at` (Module 10 FR-BILL-015).

---

## FR-ADM-015 — Verification cleanup tool

**Priority:** P2 — Could
**Status:** [GAP: not yet implemented]

A superadmin shall be able to view and bulk-correct users in the broken `email_verified=true` + no-OAuth + no-verification-stamp state (the regression patched in `auth/routes.py`'s self-healing guard). Useful one-shot cleanup; the runtime guard is the durable fix.

---

*End of module 15.*
