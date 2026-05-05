# SRS Module 05 — Scanning

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 05 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies the scan profile system, the engine pipeline, the scan job lifecycle, retry / cancellation behaviour, and the relationship between scans and findings.

---

## FR-SCAN-001 — Scan profiles (system-defined)

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system shall ship the following system-defined scan profiles, available to every organisation regardless of plan (subject to FR-SCAN-002 plan gating):

| Profile | Engines | Typical duration |
|---|---|---|
| **Quick** | Shodan host lookup; basic reconnaissance | ≤ 60 s (NFR-PERF-004) |
| **Standard** | Shodan + Nmap top-1000 ports + CVE enrichment | ≤ 10 min (NFR-PERF-005) |
| **Deep** | Standard + Nuclei vulnerability templates + wider port range (1–5000) | ≤ 30 min (NFR-PERF-006) |
| **Full** | Deep + SSLyze TLS analysis + full port range (1–65535) | ≤ 60 min (NFR-PERF-007) |

System profiles are immutable.

**Acceptance criteria:**
- AC-1 Profile descriptions in the UI describe **what the scan does**, not the underlying tool names ("Comprehensive scan covering every engine — port scanning, vulnerability checks, and TLS analysis", not "Nuclei + SSLyze + Nmap").
- AC-2 The Standard profile is the system default for new scans.

---

## FR-SCAN-002 — Plan-tier gating of scan profiles

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Profiles that are heavier than the plan permits shall be unavailable to that plan's organisations:

- **Free / Starter:** Quick + Standard
- **Professional:** Quick + Standard + Deep
- **Silver / Gold / Custom:** Quick + Standard + Deep + Full

UI hides the disallowed profiles; backend rejects with HTTP 403 / `FEATURE_NOT_AVAILABLE` if requested directly.

---

## FR-SCAN-003 — Custom scan profiles

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

An Admin shall be able to create org-defined scan profiles by selecting which engines to enable, scan-engine-specific options (Nmap port range, Nuclei severity filter, Shodan options, etc.), and a timeout.

**Acceptance criteria:**
- AC-1 Custom profiles are visible only within their owning organisation.
- AC-2 Custom profile creation is plan-gated (Professional+).
- AC-3 The Owner / Admin may delete a custom profile if no scheduled scan references it.

---

## FR-SCAN-004 — Launch a scan

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Analyst (or higher) shall be able to launch a scan against:

- A single asset
- An asset group (one scan job per asset, parallelised)
- All assets in the organisation (one scan job per asset, parallelised)

**Acceptance criteria:**
- AC-1 The user selects target + profile; the system creates one `ScanJob` per asset.
- AC-2 The system enforces the plan's `scans_per_month` limit, counting **both manual and monitor-driven scans** (FR-RBAC-012).
- AC-3 The endpoint returns HTTP 202 with the scan job's display ID for single-target scans, or a batch summary for group / org scans.
- AC-4 The job runs asynchronously in the background (NFR-PERF-003).
- AC-5 Audit-log `scan.started` per job.

---

## FR-SCAN-005 — Scan job lifecycle

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A scan job transitions through:

```
queued → running → completed | failed | cancelled
```

**Acceptance criteria:**
- AC-1 `started_at` is stamped on `running` transition; `finished_at` is stamped on `completed` / `failed` / `cancelled`.
- AC-2 `result_json` carries the engine-by-engine output on `completed`.
- AC-3 `error_message` carries a **user-friendly** message on `failed` (NFR-SEC-016 sanitisation applies — never raw stack traces).
- AC-4 Findings produced by the scan are persisted to the `Finding` table linked to the scan job and asset.
- AC-5 Audit-log `scan.completed` / `scan.failed` / `scan.cancelled`.

---

## FR-SCAN-006 — Cancel a scan

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Analyst may cancel a `queued` or `running` scan job:

**Acceptance criteria:**
- AC-1 The cancel handler sets the job's status to `cancelled` and stamps `finished_at`.
- AC-2 The orchestrator's per-job AbortController (where applicable) interrupts in-flight HTTP requests.
- AC-3 Cancellation does not retroactively delete findings already persisted before the cancel.
- AC-4 If the cancel races a successful completion, the completion wins (the job's status is `completed`, not overwritten with `cancelled`).

---

## FR-SCAN-007 — Concurrency cap on bulk scans

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

When a user launches a scan against many assets at once (group or org), the system shall cap the number of concurrent scans launched to a sensible default (e.g., 3) to avoid bursting the same target host or upstream API rate limits.

---

## FR-SCAN-008 — Scheduled scans

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Admin shall be able to schedule recurring scans:

**Acceptance criteria:**
- AC-1 Schedule definition: target (asset / group / all), profile, cadence (cron-like or "every N days").
- AC-2 The scheduler executes the schedule at the configured cadence, respecting plan limits (over-budget runs skip with logged reason).
- AC-3 The user may pause / unpause / delete schedules.
- AC-4 The schedule's last-run and next-run times are visible.
- AC-5 Audit-log on schedule create / update / delete.

---

## FR-SCAN-009 — Scan results page

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/scan-jobs/<id>` shall present:

**Acceptance criteria:**
- AC-1 Status, target asset, profile name + brief description, start / finish / duration.
- AC-2 Findings list grouped by severity, with link to each finding's detail.
- AC-3 Asset and group context (so the analyst sees what was scanned and why).
- AC-4 Compliance framework chips on each finding (Module 06).
- AC-5 Scan-engine-level breakdown (which engines ran, what they returned).
- AC-6 Action buttons: re-run, cancel (if running), delete.

---

## FR-SCAN-010 — Re-run a scan

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

A user may re-run any past scan with a single click. The system creates a new `ScanJob` with the same target and profile and links to the previous job for change-comparison.

---

## FR-SCAN-011 — Scan job comparison

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

A user shall be able to view a side-by-side diff of two scan results for the same asset, highlighting:

- Findings new in the second run
- Findings present in the first but absent in the second
- Findings present in both (and whether their severity / detail changed)

This is the basis of monitor change-detection (Module 07).

---

## FR-SCAN-012 — Sanitised scan-failure messaging

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

When a scan fails, the user-facing error message shall not expose Python exception types, stack traces, or internal hostnames. Specific causes that get distinguishable user-friendly messages:

- Network unreachable / DNS failure → "Could not reach the target during scanning. It may be offline, blocking our scanners, or behind a firewall."
- Timeout → "Scan timed out before all engines could finish. Try a lighter scan profile."
- SSRF block → "The target resolves to a private or reserved network and can't be scanned."
- Internal error → "Scan failed due to an internal error. Our team has been notified."

(Implemented in `app/scanner/errors.py:user_facing_error_message()`.)

---

## FR-SCAN-013 — Scan job listing and filtering

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/scan` shall present a paginated list of recent scan jobs with status counts (running, queued, completed, failed). Filterable by status, target, asset, and time range.

---

## FR-SCAN-014 — Manual scan job deletion

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Admin may delete a scan job. Deletion cascades to its findings. Audit-log `scan.deleted`.

---

## FR-SCAN-015 — Scan-engine-key flexibility

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

External scan engines that require API keys (Shodan, GitHub) shall:

- AC-1 Be optional — missing keys disable the corresponding engine but do not break the scan.
- AC-2 Surface a clear "no API key configured" indicator in the affected engine's results.
- AC-3 Use the platform-level key by default (operator-supplied environment variable), not per-tenant keys [TBD — per-tenant keys are out of scope at this stage].

---

*End of module 05.*
