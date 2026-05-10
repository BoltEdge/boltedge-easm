# Finding Provenance Tags + Configurable Alert Scope — Design

**Date:** 2026-05-11
**Status:** Approved (pending user review of this spec)
**Surfaces:** Findings list, scan-job results, settings, monitoring config

## Goal

Two related improvements to finding visibility and notification noise:

1. **Provenance tags** on findings — each row gains a single small pill (NEW / SEEN BEFORE / RESOLVED BEFORE) so users can tell at a glance whether a finding is fresh, recurring, or a regression of a previously-fixed issue. Display is **disabled by default** and toggled on per-user.

2. **Configurable alert scope** for monitoring — by default, MonitorAlerts only fire for genuinely new findings (suppressing recurrences). An owner/admin can flip an org-level setting to receive alerts on recurrences too, and individual monitors can override the org default.

## Why now

The current orchestrator dedup behavior (in `backend/app/scanner/orchestrator.py:768-915`) updates existing findings in place and never auto-reopens resolved ones. This is correct for data hygiene but creates two user-visible problems:

- A scan that re-detects a resolved finding silently bumps `last_seen_at`. The UI still shows the row as "resolved" even though the scan just confirmed the issue is back.
- The monitoring change detector (`change_detector.py:156-178`) fires `new_finding` MonitorAlerts whenever a finding is in the latest scan but wasn't in the immediately previous one. It misses the case where a finding was seen 3 scans ago — that fires again as if "new".

The provenance tags surface this state without changing dedup behavior. The configurable alert scope lets users decide whether to be paged on regressions or stay quiet.

## Decisions made during brainstorming

| Question | Decision |
|---|---|
| Where does the provenance display toggle live? | **Per-user preference** persisted in `User.prefs_json`. Default OFF. |
| Tag semantics (stacked vs exclusive)? | **Exclusive, with priority** RESOLVED BEFORE > NEW > SEEN BEFORE. One pill per finding. |
| Display-only or also filter? | **Display-only first.** No "show only NEW" filter pill in v1. |
| Where does the alert-on-recurrence setting live? | **Both** — org-level default + per-monitor override. |
| Split alert config (seen-before vs resolved-before separately)? | **Single combined flag** for v1. Splitting is a clean future extension. |

## Out of scope

- Per-tag filters on the findings list (e.g. "show only NEW") — display-only first; revisit after launch.
- Email/Slack/webhook copy changes for MonitorAlerts.
- Dashboard widgets showing "X new findings since last visit".
- Bulk re-open workflow (orchestrator still doesn't auto-reopen resolved findings; that's a separate decision).
- Splitting `alert_on_recurrence` into separate flags for SEEN BEFORE vs RESOLVED BEFORE.

## Data model

### `Finding` — one new column

```python
previously_resolved_at = db.Column(db.DateTime, nullable=True, index=True)
```

- Set on the **first** transition from `resolved=False → resolved=True`. Once set, never cleared — even if the row is later unresolved or auto-reappears in a later scan.
- Indexed because the provenance derivation reads it on every finding response.
- Migration backfill: `UPDATE finding SET previously_resolved_at = resolved_at WHERE resolved_at IS NOT NULL` so existing resolved rows tag correctly on first page load after deploy.

### `User` — one new column

```python
prefs_json = db.Column(db.JSON, nullable=False, default=dict)
```

JSON blob holding user-scoped preferences. v1 ships with one key:

```json
{ "showProvenanceTags": false }
```

The blob shape is intentionally extensible — future per-user prefs land here without further migrations.

### `Organization` — one new column

```python
alert_on_recurrence = db.Column(db.Boolean, nullable=False, default=False)
```

Default `False` matches the safe/quiet posture: only truly new findings fire MonitorAlerts. Owner/Admin can flip in settings.

### `Monitor` — one new column

```python
alert_on_recurrence_override = db.Column(db.Boolean, nullable=True, default=None)
```

`NULL` = inherit org default (typical). Explicit `True` or `False` = override for this monitor. Lets quiet orgs surface regressions on critical monitors only, and vice versa.

## Backend logic

### Provenance derivation

A pure function used by every endpoint that returns a `Finding`:

```python
def derive_provenance(f: Finding) -> str:
    if f.previously_resolved_at is not None:
        return "resolved_before"
    if f.first_seen_at == f.last_seen_at:
        return "new"
    return "seen_before"
```

Surfaced as a derived field on the response (snake_case backend, camelCase frontend):

- `GET /findings` — each item carries `provenance`
- `GET /findings/<id>` — detail response carries `provenance`
- `GET /scan-jobs/<id>/findings` — same shape

The derivation runs in Python (not SQL) since the comparison is trivial and we already load the full row.

### `mark_resolved` helper

Centralised in `app/findings/helpers.py` (new file) and called from both single-finding `PATCH /findings/<id>` and the bulk `POST /findings/bulk-status` endpoints:

```python
def mark_resolved(f: Finding, user_id: int, reason: str | None) -> None:
    now = now_utc()
    if f.previously_resolved_at is None:
        f.previously_resolved_at = now
    f.resolved = True
    f.resolved_at = now
    f.resolved_by = user_id
    f.resolved_reason = reason
```

Idempotent on `previously_resolved_at`: re-resolving an already-resolved row doesn't move the timestamp.

### `should_alert_on_recurrence` helper

In `app/monitoring/change_detector.py` (or a small `monitoring/helpers.py`):

```python
def should_alert_on_recurrence(monitor: Monitor, org: Organization) -> bool:
    if monitor.alert_on_recurrence_override is not None:
        return monitor.alert_on_recurrence_override
    return bool(org.alert_on_recurrence)
```

### `change_detector` gate

In the existing "new findings" loop in `_diff_for_asset` (around `change_detector.py:156-178`):

```python
for fk, finding in current_map.items():
    if fk in prev_map:
        continue  # already in prev scan

    is_recurrence = bool(
        finding.first_seen_at
        and latest_job.started_at
        and finding.first_seen_at < latest_job.started_at
    )
    if is_recurrence and not should_alert_on_recurrence(monitor, org):
        continue  # quiet mode for this monitor — skip

    # ... existing MonitorAlert creation unchanged ...
```

`alert_type="resolved"` (finding disappeared) and `alert_type="severity_change"` are unchanged — they fire as before.

## API surface

### User preferences

- `GET /settings/preferences` returns the `prefs_json` content (creates an empty `{}` shell if NULL).
- `PATCH /settings/preferences` merges a JSON patch into `prefs_json`. Only top-level keys defined in an allowlist are accepted (`showProvenanceTags` for v1).

### Organization alert default

- `PATCH /settings/organization` (existing route) extended to accept `alertOnRecurrence: boolean`. Owner/Admin only.

### Monitor override

- `PATCH /monitors/<id>` (existing route) extended to accept `alertOnRecurrenceOverride: boolean | null`. Existing role gate applies.

## Frontend

### Pill component

A small `<ProvenanceTag value={...} />` component renders one of three pills:

| Tag | Background | Border | Text | Tooltip |
|---|---|---|---|---|
| `resolved_before` | `bg-amber-500/[0.08]` | `border-amber-500/30` | `text-amber-300` | "Was previously resolved. Detected again — likely a regression." |
| `new` | `bg-teal-500/[0.08]` | `border-teal-500/30` | `text-teal-300` | "First detection. Never seen before this scan." |
| `seen_before` | `bg-white/[0.04]` | `border-white/10` | `text-white/65` | "Seen in a previous scan. No new state." |

Pill sits to the right of the severity badge in the findings table row. Tooltip on hover.

### Render gate

The pill column only renders when `prefs.showProvenanceTags === true`. Without it, the row layout is identical to today (no shifted columns).

### Toggle UI

Two surfaces:

1. **Findings page header** — a small checkbox above the table: "Show provenance tags". Bound to `prefs.showProvenanceTags` (writes back via `PATCH /settings/preferences`).
2. **Settings → Preferences** (existing or new page) — same checkbox lives there too, so users who want to set it once and forget don't need to re-find the findings page.

### Scan-job results page

Wherever the per-scan-job finding table is rendered (likely the asset detail page or scan-job detail page), use the same `<ProvenanceTag />` component gated by the same user pref.

### Org settings — alert scope

In Settings → Monitoring (or wherever org-monitoring config lives), add a radio:

- **Alert on new findings only** (default, quiet)
- **Alert on new findings + recurrences** (chatty)

Owner/Admin only — disabled with a tooltip for lower roles.

### Per-monitor override

On each monitor's edit panel, add a three-state selector:

- **Use org default** (NULL — typical)
- **Alert on new only** (force quiet)
- **Alert on new + recurrences** (force chatty)

Lives near the existing monitor frequency/scope controls.

## Acceptance criteria

- Findings list, finding detail, and scan-job results responses all include a `provenance` field with one of `"new" | "seen_before" | "resolved_before"`.
- Resolving a finding sets `previously_resolved_at` (idempotent — re-resolving doesn't shift it).
- Backfill migration runs: existing rows with `resolved_at IS NOT NULL` get `previously_resolved_at = resolved_at`.
- With `prefs.showProvenanceTags = false` (default), no provenance pills render.
- With `prefs.showProvenanceTags = true`, every finding row shows exactly one pill (priority: resolved_before > new > seen_before).
- `Org.alert_on_recurrence = false` (default) means change-detection only creates `new_finding` MonitorAlerts when `finding.first_seen_at >= scan.started_at`.
- Setting `Org.alert_on_recurrence = true` makes the gate behave as before (fires on all detections not present in the comparison scan).
- `Monitor.alert_on_recurrence_override = true|false` overrides the org default for that monitor.
- `resolved` and `severity_change` MonitorAlert types are unaffected.

## Risks

- **Backfill is one-shot**: existing rows where `resolved_at` was cleared by some other code path (un-resolve flow, if any) lose their resolution history. Acceptable — `previously_resolved_at` starts tracking from today forward for those rows.
- **`prefs_json` shape drift**: as more keys land in the JSON blob, the allowlist on `PATCH /settings/preferences` must be kept in sync. Single source of truth via a constant `ALLOWED_PREF_KEYS` to mitigate.
- **Alert-config UX**: a user toggling org-level `alert_on_recurrence` after launch may see a surge of recurrence alerts on the next monitor cycle if many monitored assets have findings with `first_seen_at` predating their last scan. Worth flagging in the settings UI with a brief explainer.

## Migrations

Three additive nullable/default-friendly column adds in one Alembic migration:

```
finding:        + previously_resolved_at (datetime, nullable, index)
user:           + prefs_json             (json, NOT NULL, default {})
organization:   + alert_on_recurrence    (boolean, NOT NULL, default false)
monitor:        + alert_on_recurrence_override (boolean, nullable)
```

Plus the data backfill SQL:

```sql
UPDATE finding
SET previously_resolved_at = resolved_at
WHERE resolved_at IS NOT NULL;
```

All defaults are safe — no application code change is required between migration and code deploy.
