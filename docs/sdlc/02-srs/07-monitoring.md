# SRS Module 07 — Continuous Monitoring

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 07 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies how an organisation configures continuous monitoring of an asset or asset group, what changes are detected, how alerts are raised and routed, and how monitor schedules interact with plan limits.

---

## FR-MON-001 — Create a monitor

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Analyst (or higher) shall be able to create a monitor:

**Acceptance criteria:**
- AC-1 Target: one asset or one asset group.
- AC-2 Monitor types (multi-select): `dns`, `ssl`, `ports`, `headers`, `tech`, `cve`, or `all`.
- AC-3 Cadence: per-plan default (Starter weekly; Pro every 3 days; Silver / Gold daily; Custom hourly).
- AC-4 Alert threshold: minimum severity that triggers an alert (info / low / medium / high / critical).
- AC-5 Plan-limit-aware (`monitored_assets` cap).
- AC-6 Audit-log `monitor.created`.

---

## FR-MON-002 — Monitor lifecycle

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A monitor has an `enabled` boolean. The user may pause / resume the monitor without losing its history. Disabled monitors do not consume the `monitored_assets` quota [TBD — confirm quota counts active only].

---

## FR-MON-003 — Monitor sweep execution

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

At each scheduled cadence, the system shall:

**Acceptance criteria:**
- AC-1 Run a Standard scan profile against the monitor's target asset(s) (no group-level scan; one ScanJob per asset).
- AC-2 Compare the resulting findings to the previous sweep's findings.
- AC-3 Generate a `MonitorAlert` per material change (FR-MON-004).
- AC-4 Update the monitor's `last_scan_job_ids` so the user can drill into what changed.
- AC-5 Each scan counts against the org's `scans_per_month` plan limit.

---

## FR-MON-004 — Material change types

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The following are considered material changes worthy of an alert:

| Change | Severity inheritance |
|---|---|
| New finding (above the alert threshold) | Inherits finding severity |
| Resolved finding (clean diff) | `info` |
| New port detected | Same as finding template severity |
| Closed port detected | `info` |
| New service banner / tech-stack change | `low` |
| Certificate expiry within 30 days | `medium` (escalates to `high` ≤ 14 days, `critical` ≤ 7 days) |
| Certificate replaced by an unexpected issuer | `high` |
| New DNS record | `low` |
| Removed DNS record | `info` |
| New subdomain detected (when group-monitor) | `medium` |

The user may suppress alert generation for any of these types per-monitor.

---

## FR-MON-005 — Monitor alert detail

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A `MonitorAlert` row shall record:

- The monitor it came from
- The asset it concerns
- Severity (FR-MON-004)
- A change-type code (e.g., `new_finding`, `port_opened`, `cert_expiring`)
- A short title and a longer description
- Status (`open`, `acknowledged`, `resolved`)
- Timestamp + `notified_via` (which channels were notified)

---

## FR-MON-006 — Alert routing

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Generated alerts shall route through the org's notification rules (Module 09). The `notified_via` array records every channel that was hit (in_app, email, slack, jira, pagerduty, webhook).

---

## FR-MON-007 — Alert acknowledgement

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Analyst shall be able to acknowledge / resolve an alert; status transitions are audit-logged.

---

## FR-MON-008 — Alert listing

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/monitoring` shall present a list of recent alerts filterable by monitor, severity, status, and time window. Bulk acknowledge / resolve is supported.

---

## FR-MON-009 — Monitor configuration page

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/monitoring/settings` shall let the user configure:

- Default cadence overrides
- Default alert severity threshold
- Quiet hours / timezone (no email or in-app banner notifications during these hours)
- Per-channel routing preferences (matched against Module 09's notification rules)

---

## FR-MON-010 — Tuning rules (false-positive suppression)

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

`/monitoring/tuning` shall let the user define rules that auto-acknowledge or suppress alerts matching specific patterns (e.g., "any port-change alert on assets in group `Test`").

---

## FR-MON-011 — Monitor execution failure handling

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

When a monitor sweep fails (the underlying scan errors out, network unreachable, etc.), the system shall:

**Acceptance criteria:**
- AC-1 Mark the scan job as `failed` with a sanitised user-friendly error (FR-SCAN-012).
- AC-2 Update the monitor's `last_run_status` so the user can see the failure on the monitor's detail page.
- AC-3 NOT generate an alert from the failure itself (fail-closed: missing data ≠ change).
- AC-4 Retry the next scheduled sweep; do not auto-disable the monitor on isolated failures.

---

## FR-MON-012 — Plan-limit feature gating

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The monitoring feature is plan-gated:

- **Free:** No monitors.
- **Starter+:** Monitors enabled.

The gate returns HTTP 403 / `FEATURE_NOT_AVAILABLE` on lower plans (FR-RBAC-011). The frontend renders an "upgrade to enable monitoring" prompt instead of the monitoring page on lower plans.

---

## FR-MON-013 — Group-targeted monitor

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A monitor whose target is an asset group shall:

**Acceptance criteria:**
- AC-1 Sweep every asset currently in the group at each cadence.
- AC-2 Adjust automatically as assets are added to / removed from the group.
- AC-3 Count one slot per asset against the `monitored_assets` quota.

---

*End of module 07.*
