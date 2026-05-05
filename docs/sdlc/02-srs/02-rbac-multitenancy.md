# SRS Module 02 — Multi-tenancy & RBAC

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 02 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies how organisations (tenants) are created, how members join, what roles exist, what each role can do, and how cross-tenant data isolation is enforced.

Cross-cutting NFR-SEC-007 (RBAC enforcement) and NFR-SEC-008 (tenant isolation) apply throughout.

---

## FR-RBAC-001 — Organisation creation at registration

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Every new email/password or OAuth registration that does not arrive via an invitation creates a personal Organization with the registering user as the sole `Owner`.

**Acceptance criteria:**
- AC-1 The Organisation slug is derived from the email's local part with conflict suffixing (`alice` → `alice-2` if taken).
- AC-2 The Organisation defaults to the `free` plan with `plan_status="active"` and a `Free` tier 90-day expiry timestamp (see Module 10).
- AC-3 The user's `OrganizationMember` row links them with role `Owner`, `is_active=true`, and a `joined_at` timestamp.

---

## FR-RBAC-002 — Roles and capabilities

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system defines exactly four organisation-scoped roles, in order of decreasing capability:

| Role | Allowed actions (high-level) |
|---|---|
| **Owner** | Everything Admin can do, plus: change billing, delete the organisation, transfer ownership, change another member's role to / from Owner. |
| **Admin** | Manage members (invite, remove, role-change below Owner), manage integrations, scheduled scans, API keys, audit log. Not billing, not org delete. |
| **Analyst** | Run scans and discoveries, triage findings, manage assets and groups, manage monitors, generate reports. Cannot manage members, integrations, or org settings. |
| **Viewer** | Read-only access to assets, groups, scans, findings, monitors, reports, and audit log. Cannot mutate any data. |

A separate platform-level role `superadmin` exists outside the organisation hierarchy (Module 15).

**Acceptance criteria:**
- AC-1 Every authenticated user has exactly one active role per organisation they belong to.
- AC-2 Capabilities are enforced at the route layer via `@require_role(...)` decorators (NFR-SEC-007).
- AC-3 The capability matrix is documented in the Security Policy (doc 05) and surfaced in `/settings/members` UI.

---

## FR-RBAC-003 — Single-organisation membership baseline

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A user may be a member of multiple organisations across their account lifetime, but the active session shall scope to **exactly one** active organisation. Cross-organisation views are not provided.

**Acceptance criteria:**
- AC-1 If a user has multiple `OrganizationMember(is_active=true)` rows, the active one for a given login is determined by [TBD — current behaviour: pick the first match].
- AC-2 [GAP] Switching between organisations within a single session is not supported.

---

## FR-RBAC-004 — Invite a new member

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Admin or Owner shall be able to invite a person to their organisation by email + role.

**Acceptance criteria:**
- AC-1 The system creates a `PendingInvitation` with a unique token, the chosen role, and an expiry (default 7 days).
- AC-2 The invitee receives a branded email with a link `/invitations/<token>`.
- AC-3 If the invitee already has an account, accepting the invite adds an `OrganizationMember` row and signs them in.
- AC-4 If the invitee does not have an account, the invite link routes to a registration form pre-filled with their email; on registration, they skip email verification and are added as a member with the invited role.
- AC-5 An invite to a role of `Owner` is permitted only if the inviter is themselves an Owner.
- AC-6 An invite to an email already a member of the same organisation returns HTTP 409.
- AC-7 Audit-log `user.invited` and `user.invitation_accepted`.

---

## FR-RBAC-005 — Revoke a pending invitation

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Admin / Owner shall be able to revoke a pending invitation; the token is marked as revoked and is no longer accepted.

---

## FR-RBAC-006 — Change member role

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

**Acceptance criteria:**
- AC-1 An Admin may change another member's role between Admin / Analyst / Viewer.
- AC-2 An Owner may additionally promote a member to Owner or demote an Owner to Admin (provided ≥1 Owner remains).
- AC-3 The system shall not permit demoting the last Owner.
- AC-4 Audit-log `user.role_changed`.

---

## FR-RBAC-007 — Remove a member

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

**Acceptance criteria:**
- AC-1 An Admin / Owner may remove an Analyst or Viewer.
- AC-2 An Owner may remove an Admin.
- AC-3 An Owner may remove another Owner only if ≥1 Owner remains after.
- AC-4 The removed user's `OrganizationMember.is_active` is set to false; the user account itself is not deleted (they may still belong to other orgs).
- AC-5 Audit-log `user.removed`.

---

## FR-RBAC-008 — Suspend a user (in-organisation)

**Priority:** P1 — Should
**Status:** [PARTIAL — currently only superadmin can suspend]

[GAP — currently delegated to superadmin / `User.is_suspended`]. An Owner / Admin shall be able to suspend a member in their own organisation, blocking that member's login while preserving their data.

---

## FR-RBAC-009 — Tenant data isolation

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

See NFR-SEC-008. Every persistence query that returns or modifies tenant-owned data shall be filtered by `organization_id` matched to the requesting member's active organisation.

**Acceptance criteria:**
- AC-1 The `@require_auth` decorator populates `g.current_organization_id` from the active `OrganizationMember`.
- AC-2 No business-logic code path bypasses this filter to return data from another organisation.
- AC-3 Cross-tenant access attempts (manipulated IDs) return HTTP 404, not 403, to avoid existence enumeration.
- AC-4 The test suite includes negative IDOR cases for at least: assets, scan jobs, findings, monitors, reports, members, integrations, API keys, audit log entries.

---

## FR-RBAC-010 — Permission enumeration endpoint

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

`GET /auth/me` shall return the caller's role plus a flat permissions object (e.g., `{ manage_members: true, view_audit_log: true, … }`) so the frontend can hide UI for actions the user cannot perform.

This is a UX optimisation; the authoritative check is always at the backend route layer (NFR-SEC-007).

---

## FR-RBAC-011 — Plan-feature gating

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Some capabilities are gated by the organisation's plan tier (e.g., audit-log webhook stream is Enterprise Gold only). The system shall reject calls to gated endpoints with HTTP 403 + `code="FEATURE_NOT_AVAILABLE"` when the active plan does not include the feature.

The plan / feature matrix lives in `app/billing/routes.py:PLAN_CONFIG` and is mirrored in `/settings/billing` UI.

---

## FR-RBAC-012 — Plan-limit enforcement

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Quantitative plan limits (assets, scans/month, members, scheduled scans, API keys, monitored assets, discoveries/month, etc.) shall be enforced at the corresponding mutation endpoints with HTTP 403 + `code="PLAN_LIMIT"` when exceeded.

**Acceptance criteria:**
- AC-1 Limits are enforced at the moment of creation, not lazily on next read.
- AC-2 The error response includes the failing limit name, current usage, and the plan ceiling.
- AC-3 Per-org `limit_overrides` (set by superadmin) take precedence over plan defaults.

---

## FR-RBAC-013 — Owner transfer

**Priority:** P2 — Could
**Status:** [GAP: not implemented]

An Owner shall be able to transfer organisation ownership to another existing member (Admin or higher) and immediately lose Owner privileges, retaining whichever role they specify.

---

*End of module 02.*
