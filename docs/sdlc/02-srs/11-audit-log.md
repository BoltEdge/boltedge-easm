# SRS Module 11 — Audit Log

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 11 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies the in-platform audit log — what events get recorded, how it is queried, exported, and how superadmins can search it across the platform. The outbound webhook stream of audit events is a separate feature — see Module 16.

---

## FR-AUDIT-001 — Audit log entry shape

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Each audit log entry (`AuditLog` row) shall record:

- `id`, `public_id`, `created_at`
- `organization_id` (NULL for platform-level admin actions)
- `user_id` + `user_email` (for resilience if the user is later deleted)
- `action` (free-form string, e.g., `auth.login`, `finding.status_changed`, `admin.user_suspended`)
- `category` (`auth`, `asset`, `group`, `scan`, `discovery`, `finding`, `monitor`, `report`, `settings`, `user`, `export`, `billing`, `admin`, `tool`)
- `target_type` and `target_id` (the affected entity)
- `target_label` (human-friendly description of the target)
- `description` (free-form one-line summary)
- `metadata_json` (JSON blob of structured detail)
- `ip_address`

Entries are append-only (no in-place edit).

---

## FR-AUDIT-002 — Audit log coverage

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system shall write audit log entries for every action listed in NFR-SEC-014 — auth events, role changes, settings changes, scan / discovery / finding lifecycle, exports, admin / superadmin actions, and Stripe webhook events.

---

## FR-AUDIT-003 — Tenant-scoped audit log view

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/settings/audit-log` (also reachable via direct route `/audit-log`) shall present, for a user with `view_audit_log` permission:

**Acceptance criteria:**
- AC-1 A reverse-chronological list of audit entries scoped to the user's organisation.
- AC-2 Filters: category, action, user, target type, target id, free-text search across description / target label / action, date range.
- AC-3 Pagination (default 50/page, configurable up to 200).
- AC-4 Per-row entry with timestamp, user, action, category, target, description.
- AC-5 Click-through to a per-entry detail view showing the metadata JSON.

---

## FR-AUDIT-004 — Audit log CSV export

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A user with `export_audit_log` permission shall be able to export the filtered audit log as CSV. Export is capped at 5000 rows per call (paginate larger exports). Audit-log `export.audit_log`.

---

## FR-AUDIT-005 — Audit log retention

**Priority:** P0 — Must
**Status:** [PARTIAL — no automated roll-off]

Audit log entries shall be retained for **at least 1 year**, target 2 years (NFR-DATA / `02-srs.md` §6.3). Older entries may be pruned by background cleanup; the cleanup is logged.

[GAP — automated roll-off not implemented; entries currently accumulate indefinitely.]

---

## FR-AUDIT-006 — Append-only guarantee

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

No application code path shall allow editing or deleting an individual audit log entry. The only mutation permitted is the platform-wide retention roll-off (FR-AUDIT-005). [GAP — currently enforced by convention only; consider DB-level revoke of UPDATE/DELETE on the audit_log table for the application user.]

---

## FR-AUDIT-007 — Platform-wide audit log (superadmin)

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A superadmin shall be able to view the audit log across **all organisations** at `/admin/audit-log`, with the same filters as the tenant view plus an `organization_id` filter. Useful for incident investigation and compliance review.

---

## FR-AUDIT-008 — Audit-log resilience to write failure

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`log_audit()` shall **never raise** into the calling code. If the audit write fails (DB error, savepoint failure), the calling business operation continues; the failure is surfaced via `current_app.logger.warning(...)`.

This is intentional — losing an audit entry is preferable to losing the user-visible action that produced it. Operators must monitor application logs for "Failed to write audit log" warnings as a leading indicator of audit-write trouble.

---

*End of module 11.*
