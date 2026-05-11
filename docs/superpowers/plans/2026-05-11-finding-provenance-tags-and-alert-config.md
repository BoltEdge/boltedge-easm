# Finding Provenance Tags + Alert Config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-finding provenance tags (NEW / SEEN BEFORE / RESOLVED BEFORE) gated by a per-user preference, plus a configurable alert-on-recurrence setting (org-level default + per-monitor override) that controls whether the monitoring change-detector fires `new_finding` alerts on recurring findings.

**Architecture:** Five sequential phases, one commit per phase. Backend changes land first (model + migration → helpers + endpoints → monitoring gate), frontend changes last (display pill → config UI). Each phase produces a working, mergeable slice.

**Tech Stack:** Flask + SQLAlchemy + Alembic (backend), Next.js 16 App Router + React 19 + Tailwind 4 (frontend).

**Spec:** `docs/superpowers/specs/2026-05-11-finding-provenance-tags-and-alert-config-design.md`

**Note on testing:** Backend pure functions (`derive_provenance`, `should_alert_on_recurrence`, `mark_resolved`) are tested with pytest where the framework is available. Endpoint and integration behaviour is verified via `curl` against a local backend. Frontend changes are verified via a manual browser walkthrough; TypeScript compile is the only automated frontend check.

**Note on commits:** Per user standing rule, do not push without explicit instruction. Each phase commits and waits.

---

## File Structure

### Backend

- **Modify** `backend/app/models.py` — add 4 columns to Finding, User, Organization, Monitor
- **Create** `backend/migrations/versions/<auto>_finding_provenance_alert_config.py` — Alembic migration with backfill
- **Create** `backend/app/findings/helpers.py` — `mark_resolved`, `derive_provenance`
- **Modify** `backend/app/findings/routes.py` — wire helpers into PATCH + bulk-status; emit `provenance` on list/detail responses
- **Modify** `backend/app/scan_jobs/routes.py` — emit `provenance` on scan-job findings response
- **Create** `backend/app/monitoring/helpers.py` — `should_alert_on_recurrence`
- **Modify** `backend/app/monitoring/change_detector.py` — gate `new_finding` alerts
- **Modify** `backend/app/monitoring/routes.py` — extend `PATCH /monitors/<id>` for override
- **Modify** `backend/app/settings/routes.py` — `GET/PATCH /settings/preferences`; extend org settings PATCH for `alertOnRecurrence`

### Frontend

- **Create** `frontend/app/(authenticated)/_components/ProvenanceTag.tsx` — reusable pill component
- **Modify** `frontend/app/(authenticated)/findings/page.tsx` — render pill + header toggle
- **Modify** scan-job findings render site (asset detail page or scan-job detail) — render pill
- **Modify or create** `frontend/app/(authenticated)/settings/preferences/page.tsx` — toggle UI
- **Modify** monitoring settings page — `alertOnRecurrence` radio
- **Modify** monitor edit panel — `alertOnRecurrenceOverride` selector
- **Modify** `frontend/app/lib/api.ts` — preferences + extended settings client methods

---

## Phase 1 — Backend data model + migration

### Task 1.1: Add 4 columns to `models.py`

**Files:**
- Modify: `backend/app/models.py`

- [ ] **Step 1: Add `previously_resolved_at` to the `Finding` model**

Open `backend/app/models.py`, find the `Finding` class (`class Finding(db.Model):` around line 384). After the existing `resolved_*` block (around line 437-440), add:

```python
    # Provenance: timestamp of the FIRST resolution this finding ever
    # received. Never cleared — even if the row is later unresolved or
    # the finding recurs on a later scan. Used to drive the
    # 'resolved_before' provenance tag and to gate monitor recurrence
    # alerts. Set once via app.findings.helpers.mark_resolved.
    previously_resolved_at = db.Column(db.DateTime, nullable=True, index=True)
```

- [ ] **Step 2: Add `prefs_json` to the `User` model**

Find the `User` class. Add this column alongside other simple scalar columns (not inside any relationship block):

```python
    # Per-user preferences blob. Currently holds:
    #   showProvenanceTags: bool (default false)
    # New keys are added without further migrations — see
    # app.settings.routes.ALLOWED_PREF_KEYS for the allowlist.
    prefs_json = db.Column(db.JSON, nullable=False, default=dict)
```

- [ ] **Step 3: Add `alert_on_recurrence` to the `Organization` model**

Find the `Organization` class. Add the column:

```python
    # Default alert-scope for monitors in this org. When False (default),
    # change-detection only fires `new_finding` MonitorAlerts for findings
    # whose first_seen_at >= scan.started_at (truly new). When True, fires
    # on recurrences too. Individual monitors can override via
    # Monitor.alert_on_recurrence_override.
    alert_on_recurrence = db.Column(db.Boolean, nullable=False, default=False)
```

- [ ] **Step 4: Add `alert_on_recurrence_override` to the `Monitor` model**

Find the `Monitor` class. Add:

```python
    # Override for Organization.alert_on_recurrence. NULL = inherit
    # org default. True/False = explicit override for this monitor.
    alert_on_recurrence_override = db.Column(db.Boolean, nullable=True, default=None)
```

- [ ] **Step 5: Verify the app boots with the new model fields**

```bash
cd backend
python -c "from app import create_app; app = create_app(); print('ok')"
```

Expected: `ok` with no traceback. If the venv lacks deps, skip and rely on the migration step to surface errors.

### Task 1.2: Generate Alembic migration with backfill

**Files:**
- Create: `backend/migrations/versions/<auto>_finding_provenance_alert_config.py`

- [ ] **Step 1: Generate the autogenerated migration**

```bash
cd backend
flask db migrate -m "add finding provenance + alert config"
```

Alembic will scan model changes and emit a new file under `backend/migrations/versions/`. Note the generated filename — it'll have a hash prefix like `<12hex>_add_finding_provenance_alert_config.py`.

- [ ] **Step 2: Open the generated migration and add the backfill**

Find the generated migration. Inside the `def upgrade():` block, AFTER the autogenerated `op.add_column(...)` calls and BEFORE the closing of `upgrade()`, add:

```python
    # Backfill: every existing finding that has a resolved_at gets that
    # timestamp copied to previously_resolved_at, so the UI tags them
    # correctly on first page load after deploy. Findings that have
    # never been resolved stay NULL.
    op.execute(
        "UPDATE finding "
        "SET previously_resolved_at = resolved_at "
        "WHERE resolved_at IS NOT NULL"
    )
```

The `downgrade()` block stays autogenerated — column drops will reverse cleanly without needing to undo the backfill.

- [ ] **Step 3: Run the migration**

```bash
cd backend
flask db upgrade
```

Expected: applies the new migration, prints `INFO  [alembic.runtime.migration] Running upgrade ... -> <hash>, add finding provenance + alert config`. No errors.

- [ ] **Step 4: Verify columns exist via SQL**

```bash
psql "$SQLALCHEMY_DATABASE_URI" -c "\d finding" | grep previously_resolved_at
psql "$SQLALCHEMY_DATABASE_URI" -c "\d \"user\"" | grep prefs_json
psql "$SQLALCHEMY_DATABASE_URI" -c "\d organization" | grep alert_on_recurrence
psql "$SQLALCHEMY_DATABASE_URI" -c "\d monitor" | grep alert_on_recurrence_override
```

Expected: each grep returns one row with the column definition.

### Task 1.3: Commit Phase 1

- [ ] **Step 1: Stage and commit**

```bash
git add backend/app/models.py backend/migrations/versions/
git commit -m "$(cat <<'EOF'
feat(finding): add provenance + alert-config columns

- Finding.previously_resolved_at  (datetime, nullable, indexed)
  Set once on first resolve; never cleared. Drives the
  resolved_before provenance tag and recurrence-alert gating.

- User.prefs_json  (json, NOT NULL, default {})
  Per-user prefs blob. v1 key: showProvenanceTags.

- Organization.alert_on_recurrence  (boolean, NOT NULL, default false)
  Org-level toggle for monitor recurrence alerts. Default = quiet.

- Monitor.alert_on_recurrence_override  (boolean, nullable)
  NULL = inherit org. True/False = override.

Migration backfills previously_resolved_at from resolved_at for
existing resolved findings.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 2: Wait for explicit push instruction.** Do not auto-push.

---

## Phase 2 — Backend findings logic (helpers + endpoints)

### Task 2.1: Create `findings/helpers.py`

**Files:**
- Create: `backend/app/findings/helpers.py`

- [ ] **Step 1: Create the file with both helpers**

```python
# backend/app/findings/helpers.py
"""
Shared helpers for the findings module.

mark_resolved
    Centralised resolve-write path. Sets resolved/resolved_at/_by/_reason
    and stamps previously_resolved_at on the first resolution (never
    overwritten on subsequent resolves). Both PATCH /findings/<id> and
    POST /findings/bulk-status route through here so the provenance
    history is consistent.

derive_provenance
    Pure function returning one of: "new" | "seen_before" |
    "resolved_before". Priority: resolved_before > new > seen_before.
    Used by every endpoint that serialises a Finding for the UI.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.models import Finding


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def mark_resolved(f: Finding, user_id: int, reason: str | None) -> None:
    """Set the resolve fields and stamp previously_resolved_at if first time.

    Idempotent on previously_resolved_at — re-resolving a row never
    moves the timestamp. The resolved/resolved_at fields ARE updated
    every call so they reflect the most recent resolution.
    """
    now = _now_utc()
    if f.previously_resolved_at is None:
        f.previously_resolved_at = now
    f.resolved = True
    f.resolved_at = now
    f.resolved_by = user_id
    f.resolved_reason = (reason or "")[:500] or None


def derive_provenance(f: Finding) -> str:
    """Return the provenance tag for a finding.

    Priority order:
        1. resolved_before  — was ever resolved (regardless of current status)
        2. new              — first_seen_at == last_seen_at (single scan)
        3. seen_before      — first_seen_at < last_seen_at (multiple scans)
    """
    if f.previously_resolved_at is not None:
        return "resolved_before"
    if f.first_seen_at is not None and f.first_seen_at == f.last_seen_at:
        return "new"
    return "seen_before"
```

- [ ] **Step 2: Write unit tests for `derive_provenance`**

Create `backend/tests/test_findings_helpers.py`:

```python
from datetime import datetime, timedelta

from app.findings.helpers import derive_provenance


class _FakeFinding:
    """Minimal stand-in for the Finding model — only fields the helper reads."""
    def __init__(self, first=None, last=None, prev_resolved=None):
        self.first_seen_at = first
        self.last_seen_at = last
        self.previously_resolved_at = prev_resolved


def test_resolved_before_wins_over_new():
    t = datetime(2026, 5, 1)
    f = _FakeFinding(first=t, last=t, prev_resolved=t - timedelta(days=10))
    assert derive_provenance(f) == "resolved_before"


def test_resolved_before_wins_over_seen_before():
    t = datetime(2026, 5, 1)
    f = _FakeFinding(first=t - timedelta(days=2), last=t, prev_resolved=t - timedelta(days=10))
    assert derive_provenance(f) == "resolved_before"


def test_new_when_first_equals_last():
    t = datetime(2026, 5, 1)
    f = _FakeFinding(first=t, last=t, prev_resolved=None)
    assert derive_provenance(f) == "new"


def test_seen_before_when_first_lt_last():
    t = datetime(2026, 5, 1)
    f = _FakeFinding(first=t - timedelta(days=2), last=t, prev_resolved=None)
    assert derive_provenance(f) == "seen_before"


def test_seen_before_when_first_is_null():
    # Edge case: row missing first_seen_at; treat as seen_before.
    f = _FakeFinding(first=None, last=None, prev_resolved=None)
    assert derive_provenance(f) == "seen_before"
```

- [ ] **Step 3: Run the tests**

```bash
cd backend
pytest tests/test_findings_helpers.py -v
```

Expected: 5 passed.

If pytest isn't yet set up on this branch, run a quick sanity check via Python REPL instead:

```bash
python -c "
from datetime import datetime, timedelta
from app.findings.helpers import derive_provenance
class F:
    def __init__(s, **k): s.__dict__.update(k)
t = datetime(2026, 5, 1)
assert derive_provenance(F(first_seen_at=t, last_seen_at=t, previously_resolved_at=t)) == 'resolved_before'
assert derive_provenance(F(first_seen_at=t, last_seen_at=t, previously_resolved_at=None)) == 'new'
assert derive_provenance(F(first_seen_at=t - timedelta(days=2), last_seen_at=t, previously_resolved_at=None)) == 'seen_before'
print('helper sanity check passed')
"
```

Expected: `helper sanity check passed`.

### Task 2.2: Wire `mark_resolved` into the resolve endpoints

**Files:**
- Modify: `backend/app/findings/routes.py`

- [ ] **Step 1: Find the existing PATCH /findings/<id> route**

Open `backend/app/findings/routes.py`. Search for the handler that processes status changes to "resolved" — it'll be the function backing `PATCH /findings/<finding_id>`. Look for code that sets `finding.resolved = True`.

- [ ] **Step 2: Replace the manual resolve block with the helper call**

Wherever the route currently does something like:

```python
finding.resolved = True
finding.resolved_at = now_utc()
finding.resolved_by = current_user_id()
finding.resolved_reason = reason
```

Replace with:

```python
from app.findings.helpers import mark_resolved
mark_resolved(finding, current_user_id(), reason)
```

If the route only conditionally enters the resolve branch (e.g. status enum match), keep the conditional but route through the helper.

- [ ] **Step 3: Do the same for `POST /findings/bulk-status`**

Find the bulk-status handler. Inside the loop that updates each finding, when transitioning to "resolved", replace the inline writes with `mark_resolved(f, uid, reason)`.

- [ ] **Step 4: Smoke-test by resolving one finding via curl**

```bash
curl -X PATCH \
  -H "X-API-Key: ag_sk_..." \
  -H "Content-Type: application/json" \
  -d '{"status":"resolved","notes":"manual test"}' \
  http://localhost:5000/api/findings/<some-id>
```

Then query the row:

```bash
psql "$SQLALCHEMY_DATABASE_URI" -c "SELECT id, resolved, resolved_at, previously_resolved_at FROM finding WHERE id=<some-id>"
```

Expected: `resolved=t`, `resolved_at` and `previously_resolved_at` both populated with the same timestamp.

- [ ] **Step 5: Resolve a second time and confirm `previously_resolved_at` does NOT shift**

First, manually un-resolve via psql:

```bash
psql "$SQLALCHEMY_DATABASE_URI" -c "UPDATE finding SET resolved=false, resolved_at=NULL WHERE id=<some-id>"
```

Then resolve via curl again. Query:

```bash
psql "$SQLALCHEMY_DATABASE_URI" -c "SELECT resolved_at, previously_resolved_at FROM finding WHERE id=<some-id>"
```

Expected: `resolved_at` is the new timestamp (just now). `previously_resolved_at` is the ORIGINAL timestamp from Step 4 — unchanged. This confirms idempotency.

### Task 2.3: Emit `provenance` in findings responses

**Files:**
- Modify: `backend/app/findings/routes.py`
- Modify: `backend/app/scan_jobs/routes.py`

- [ ] **Step 1: Find the serializer in `findings/routes.py`**

Find the helper that converts a `Finding` row to a UI dict (look for a function like `_finding_to_dict`, `_serialize_finding`, or inline dict construction in the list endpoint).

- [ ] **Step 2: Add `provenance` to the serialized output**

At the top of the file, add:

```python
from app.findings.helpers import derive_provenance
```

In the serializer function, add a line to the output dict:

```python
"provenance": derive_provenance(f),
```

If the response uses camelCase keys, that one key (`provenance`) is the same in either casing — no rename needed.

- [ ] **Step 3: Do the same for scan-job findings**

Open `backend/app/scan_jobs/routes.py`. Find the endpoint that returns findings for a specific scan job (around `GET /scan-jobs/<id>/findings`). If it uses its own serializer, add the same import + `"provenance": derive_provenance(f)`. If it imports the serializer from findings, no change needed.

- [ ] **Step 4: Verify via curl**

```bash
curl -H "X-API-Key: ag_sk_..." http://localhost:5000/api/findings | python -c "import sys, json; d=json.load(sys.stdin); print({f['id']: f.get('provenance') for f in d.get('items', [])[:5]})"
```

Expected: prints a dict with `provenance` set to one of `"new" | "seen_before" | "resolved_before"` for each finding.

### Task 2.4: Commit Phase 2

- [ ] **Step 1: Stage and commit**

```bash
git add backend/app/findings/helpers.py backend/tests/test_findings_helpers.py backend/app/findings/routes.py backend/app/scan_jobs/routes.py
git commit -m "$(cat <<'EOF'
feat(findings): derive provenance + centralise resolve writes

- New helper module app/findings/helpers.py with mark_resolved
  (sets resolved fields + stamps previously_resolved_at on first
  resolve, idempotent thereafter) and derive_provenance (returns
  resolved_before | new | seen_before with priority).
- PATCH /findings/<id> and POST /findings/bulk-status route through
  mark_resolved so the provenance history is consistent regardless
  of which API path is used.
- Findings list, detail, and scan-job findings responses now include
  a 'provenance' field derived per row.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 2: Wait for explicit push instruction.**

---

## Phase 3 — Backend monitoring + preferences

### Task 3.1: Create `monitoring/helpers.py`

**Files:**
- Create: `backend/app/monitoring/helpers.py`

- [ ] **Step 1: Create the file with `should_alert_on_recurrence`**

```python
# backend/app/monitoring/helpers.py
"""
Helpers for the monitoring change-detector.

should_alert_on_recurrence
    Returns the effective alert-on-recurrence policy for a monitor.
    Per-monitor override wins; falls back to the org default. Used by
    change_detector to decide whether to suppress new_finding alerts
    for findings whose first_seen_at predates the current scan.
"""

from __future__ import annotations

from app.models import Monitor, Organization


def should_alert_on_recurrence(monitor: Monitor, org: Organization) -> bool:
    """True if this monitor should fire alerts on recurring findings.

    Monitor-level override has priority. NULL override = inherit org default.
    """
    if monitor.alert_on_recurrence_override is not None:
        return bool(monitor.alert_on_recurrence_override)
    return bool(org.alert_on_recurrence)
```

- [ ] **Step 2: Write tests**

Create `backend/tests/test_monitoring_helpers.py`:

```python
from app.monitoring.helpers import should_alert_on_recurrence


class _Org:
    def __init__(self, default): self.alert_on_recurrence = default

class _Monitor:
    def __init__(self, override): self.alert_on_recurrence_override = override


def test_inherits_org_default_when_override_null():
    assert should_alert_on_recurrence(_Monitor(None), _Org(True))  is True
    assert should_alert_on_recurrence(_Monitor(None), _Org(False)) is False


def test_explicit_true_override_wins_over_org_false():
    assert should_alert_on_recurrence(_Monitor(True), _Org(False)) is True


def test_explicit_false_override_wins_over_org_true():
    assert should_alert_on_recurrence(_Monitor(False), _Org(True)) is False
```

- [ ] **Step 3: Run tests**

```bash
cd backend
pytest tests/test_monitoring_helpers.py -v
```

Expected: 3 passed.

### Task 3.2: Update `change_detector.py` gate

**Files:**
- Modify: `backend/app/monitoring/change_detector.py`

- [ ] **Step 1: Add the import**

Near the top of the file (with other imports):

```python
from app.monitoring.helpers import should_alert_on_recurrence
```

- [ ] **Step 2: Load the Organization in `_diff_for_asset`**

Find `_diff_for_asset`. Just after the asset lookup (around line 100-110), load the org:

```python
from app.models import Organization
org = Organization.query.get(org_id)
if org is None:
    return []  # defensive — shouldn't happen
```

(If the function already has `org` in scope from a caller, skip this step and reuse the existing variable.)

- [ ] **Step 3: Add the recurrence gate inside the new-findings loop**

Find the existing block around `change_detector.py:156-178`:

```python
    # New findings
    for fk, finding in current_map.items():
        if fk in prev_map:
            continue
        generate, tuning = should_alert(finding, asset, org_id, rules=tuning_rules)
        _record_rule_application(tuning)
        if not generate:
            continue
        alert = MonitorAlert(...)
```

Insert the recurrence check immediately after the `if fk in prev_map: continue` line, BEFORE the existing tuning-rule check:

```python
    # New findings
    for fk, finding in current_map.items():
        if fk in prev_map:
            continue

        # Recurrence gate: if this finding was first seen before the
        # current scan started, it's not truly new — only fire if the
        # monitor (or org default) opted in to recurrence alerts.
        is_recurrence = bool(
            finding.first_seen_at
            and latest_job.started_at
            and finding.first_seen_at < latest_job.started_at
        )
        if is_recurrence and not should_alert_on_recurrence(monitor, org):
            continue

        generate, tuning = should_alert(finding, asset, org_id, rules=tuning_rules)
        _record_rule_application(tuning)
        if not generate:
            continue
        # ... existing MonitorAlert creation unchanged ...
```

Do NOT touch the `resolved` or `severity_change` blocks.

- [ ] **Step 4: Manual smoke test**

Create a scenario in a local DB:
1. A finding with `first_seen_at` two weeks ago.
2. Same finding present in the latest scan but missing from the previous scan (simulating a gap).
3. A monitor on that asset with `alert_on_recurrence_override = NULL`.
4. The org has `alert_on_recurrence = false`.

Trigger the monitor's change detection (via the existing flow — either by waiting for the scheduler, calling the monitor-run endpoint, or directly invoking `run_change_detection` from a python shell). Verify no `new_finding` MonitorAlert is created for that finding.

Then flip `alert_on_recurrence = true` on the org and re-run. Verify the alert IS created.

### Task 3.3: Extend settings endpoints

**Files:**
- Modify: `backend/app/settings/routes.py`
- Modify: `backend/app/monitoring/routes.py`

- [ ] **Step 1: Add an allowlist constant for user preferences**

Near the top of `backend/app/settings/routes.py`:

```python
# Top-level keys the API will accept inside User.prefs_json. Anything
# else in the request body is silently dropped. Keep this list small —
# every new key needs a UI surface that reads/writes it.
ALLOWED_PREF_KEYS = {"showProvenanceTags"}
```

- [ ] **Step 2: Add `GET /settings/preferences`**

Append to `backend/app/settings/routes.py`:

```python
@settings_bp.get("/preferences")
@require_auth
def get_preferences():
    """Return the current user's preferences blob."""
    from app.models import User
    user = User.query.get(current_user_id())
    if not user:
        return jsonify(error="User not found"), 404
    prefs = dict(user.prefs_json or {})
    # Apply v1 defaults so the frontend never sees undefined keys.
    prefs.setdefault("showProvenanceTags", False)
    return jsonify(prefs), 200
```

- [ ] **Step 3: Add `PATCH /settings/preferences`**

Append:

```python
@settings_bp.patch("/preferences")
@require_auth
def patch_preferences():
    """Merge allowed keys from the request body into the user's prefs."""
    from app.models import User
    user = User.query.get(current_user_id())
    if not user:
        return jsonify(error="User not found"), 404
    body = request.get_json(silent=True) or {}
    merged = dict(user.prefs_json or {})
    for k, v in body.items():
        if k in ALLOWED_PREF_KEYS:
            merged[k] = v
    user.prefs_json = merged
    db.session.commit()
    merged.setdefault("showProvenanceTags", False)
    return jsonify(merged), 200
```

- [ ] **Step 4: Extend the org-settings PATCH for `alertOnRecurrence`**

Find the existing `PATCH /settings/organization` (or equivalent) handler. In the field-update block, add:

```python
if "alertOnRecurrence" in body:
    org.alert_on_recurrence = bool(body["alertOnRecurrence"])
```

- [ ] **Step 5: Extend `PATCH /monitors/<id>` for the override**

Open `backend/app/monitoring/routes.py`, find the existing monitor PATCH handler. In the field-update block, add:

```python
if "alertOnRecurrenceOverride" in body:
    v = body["alertOnRecurrenceOverride"]
    monitor.alert_on_recurrence_override = None if v is None else bool(v)
```

- [ ] **Step 6: Smoke-test all four endpoints with curl**

```bash
# Read prefs (should default to showProvenanceTags=false)
curl -H "X-API-Key: ag_sk_..." http://localhost:5000/api/settings/preferences

# Set prefs
curl -X PATCH -H "X-API-Key: ag_sk_..." -H "Content-Type: application/json" \
  -d '{"showProvenanceTags":true}' \
  http://localhost:5000/api/settings/preferences

# Set org alert flag (use a real session token here — API keys may not be allowed for org-settings writes)
curl -X PATCH -H "X-API-Key: ag_sk_..." -H "Content-Type: application/json" \
  -d '{"alertOnRecurrence":true}' \
  http://localhost:5000/api/settings/organization

# Set monitor override
curl -X PATCH -H "X-API-Key: ag_sk_..." -H "Content-Type: application/json" \
  -d '{"alertOnRecurrenceOverride":false}' \
  http://localhost:5000/api/monitors/<id>
```

Expected: each returns 200 with the updated state echoed back. Verify in the DB:

```bash
psql "$SQLALCHEMY_DATABASE_URI" -c "SELECT prefs_json FROM \"user\" WHERE id=<my-uid>"
psql "$SQLALCHEMY_DATABASE_URI" -c "SELECT alert_on_recurrence FROM organization WHERE id=<my-org>"
psql "$SQLALCHEMY_DATABASE_URI" -c "SELECT alert_on_recurrence_override FROM monitor WHERE id=<id>"
```

### Task 3.4: Commit Phase 3

- [ ] **Step 1: Stage and commit**

```bash
git add backend/app/monitoring/helpers.py backend/tests/test_monitoring_helpers.py \
        backend/app/monitoring/change_detector.py backend/app/monitoring/routes.py \
        backend/app/settings/routes.py
git commit -m "$(cat <<'EOF'
feat(monitoring): configurable alert-on-recurrence + user prefs API

- New helper should_alert_on_recurrence(monitor, org) — per-monitor
  override wins over org default; both default to False (quiet).
- change_detector gate: in the new_finding loop, suppress alerts when
  finding.first_seen_at < scan.started_at AND the resolved policy
  for this monitor says no. resolved + severity_change alerts unchanged.
- Settings API: GET/PATCH /settings/preferences (user prefs JSON
  with ALLOWED_PREF_KEYS allowlist). PATCH /settings/organization
  accepts alertOnRecurrence. PATCH /monitors/<id> accepts
  alertOnRecurrenceOverride (null = inherit).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 2: Wait for explicit push instruction.**

---

## Phase 4 — Frontend display (provenance pill + toggle)

### Task 4.1: Create the `<ProvenanceTag />` component

**Files:**
- Create: `frontend/app/(authenticated)/_components/ProvenanceTag.tsx`

- [ ] **Step 1: Create the directory if it doesn't exist**

```bash
mkdir -p "frontend/app/(authenticated)/_components"
```

- [ ] **Step 2: Create the component**

```tsx
// frontend/app/(authenticated)/_components/ProvenanceTag.tsx
// One small pill rendered next to the severity badge on a finding row.
// Display is gated by the user preference showProvenanceTags — the
// caller decides whether to render this component at all.

import { History, Sparkles, RotateCcw } from "lucide-react";

export type Provenance = "new" | "seen_before" | "resolved_before";

const CONFIG: Record<
  Provenance,
  {
    label: string;
    title: string;
    cls: string;
    icon: React.ComponentType<{ className?: string }>;
  }
> = {
  resolved_before: {
    label: "Resolved before",
    title: "Was previously resolved. Detected again — likely a regression.",
    cls: "border-amber-500/30 bg-amber-500/[0.08] text-amber-300",
    icon: RotateCcw,
  },
  new: {
    label: "New",
    title: "First detection. Never seen before this scan.",
    cls: "border-teal-500/30 bg-teal-500/[0.08] text-teal-300",
    icon: Sparkles,
  },
  seen_before: {
    label: "Seen before",
    title: "Seen in a previous scan. No new state.",
    cls: "border-white/10 bg-white/[0.04] text-white/65",
    icon: History,
  },
};

type Props = {
  value: Provenance | null | undefined;
  className?: string;
};

export default function ProvenanceTag({ value, className }: Props) {
  if (!value || !(value in CONFIG)) return null;
  const { label, title, cls, icon: Icon } = CONFIG[value];
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold ${cls} ${className ?? ""}`}
    >
      <Icon className="w-2.5 h-2.5" />
      {label}
    </span>
  );
}
```

- [ ] **Step 3: Type-check**

```bash
cd frontend
npx tsc --noEmit 2>&1 | grep ProvenanceTag | head
```

Expected: no output (no errors for the new file).

### Task 4.2: Add a preferences API client + hook

**Files:**
- Modify: `frontend/app/lib/api.ts`
- Create: `frontend/app/lib/usePreferences.ts`

- [ ] **Step 1: Add API client methods**

In `frontend/app/lib/api.ts`, near the other settings-related methods, add:

```ts
export type UserPreferences = {
  showProvenanceTags: boolean;
};

export async function getPreferences(): Promise<UserPreferences> {
  const res = await api.get<Partial<UserPreferences>>("/settings/preferences");
  return { showProvenanceTags: Boolean(res?.showProvenanceTags) };
}

export async function patchPreferences(patch: Partial<UserPreferences>): Promise<UserPreferences> {
  const res = await api.patch<Partial<UserPreferences>>("/settings/preferences", patch);
  return { showProvenanceTags: Boolean(res?.showProvenanceTags) };
}
```

(If the existing `api.ts` uses a different request pattern, adapt the call style — the shape of the JSON body and response stays the same.)

- [ ] **Step 2: Create a small hook**

```tsx
// frontend/app/lib/usePreferences.ts
"use client";

import { useEffect, useState, useCallback } from "react";
import { getPreferences, patchPreferences, type UserPreferences } from "./api";

const DEFAULTS: UserPreferences = { showProvenanceTags: false };

export function usePreferences() {
  const [prefs, setPrefs] = useState<UserPreferences>(DEFAULTS);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getPreferences()
      .then((p) => {
        if (!cancelled) setPrefs(p);
      })
      .catch(() => {
        // Keep DEFAULTS on failure — the toggle just stays off.
      })
      .finally(() => {
        if (!cancelled) setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const update = useCallback(async (patch: Partial<UserPreferences>) => {
    setPrefs((cur) => ({ ...cur, ...patch })); // optimistic
    try {
      const next = await patchPreferences(patch);
      setPrefs(next);
    } catch {
      // Roll back on failure — the toggle reverts.
      const fresh = await getPreferences().catch(() => DEFAULTS);
      setPrefs(fresh);
    }
  }, []);

  return { prefs, loaded, update };
}
```

### Task 4.3: Render the pill on the findings list

**Files:**
- Modify: `frontend/app/(authenticated)/findings/page.tsx`

- [ ] **Step 1: Add the pref hook + toggle in the header**

In the findings page component:

```tsx
import ProvenanceTag, { type Provenance } from "../_components/ProvenanceTag";
import { usePreferences } from "../../lib/usePreferences";
```

Inside the component body, near the other state:

```tsx
const { prefs, update: updatePrefs } = usePreferences();
```

In the JSX where the filters/header sit (above the findings table), add a small toggle:

```tsx
<label className="flex items-center gap-2 text-xs text-white/65 cursor-pointer select-none">
  <input
    type="checkbox"
    checked={prefs.showProvenanceTags}
    onChange={(e) => updatePrefs({ showProvenanceTags: e.target.checked })}
  />
  Show provenance tags
</label>
```

- [ ] **Step 2: Render the pill in each finding row**

Find the per-row render. In the row's `<td>` that contains the severity badge (or wherever it makes layout sense — typically adjacent to the title), conditionally add:

```tsx
{prefs.showProvenanceTags && (
  <ProvenanceTag value={(finding.provenance as Provenance) ?? null} />
)}
```

- [ ] **Step 3: Type-check**

```bash
cd frontend
npx tsc --noEmit 2>&1 | grep findings/page | head
```

Expected: no output.

- [ ] **Step 4: Browser walk-through**

Start the dev server, open `/findings`. With the toggle OFF: no pills shown. Flip the toggle ON: pills appear next to each row's severity. Reload the page: toggle state should persist (because it's saved to the backend). Resolve a finding via the UI, refresh: the resolved-before pill should appear on the next scan that picks it up (or directly after re-resolution if the row is filtered to show resolved ones).

### Task 4.4: Render the pill on scan-job findings

**Files:**
- Modify: wherever scan-job findings are rendered. Most likely `frontend/app/(authenticated)/assets/[id]/page.tsx` (per-asset findings) and/or a scan-job detail page if one exists.

- [ ] **Step 1: Locate the per-scan-job findings list**

```bash
grep -rln "scan-jobs.*findings\|scanJobFindings\|jobFindings" "frontend/app/(authenticated)/" | head -5
```

Pick the page(s) that render a list of findings per scan job.

- [ ] **Step 2: Apply the same pattern**

In each render site:

```tsx
import ProvenanceTag, { type Provenance } from "../_components/ProvenanceTag";
import { usePreferences } from "../../lib/usePreferences";
```

(Adjust the relative path based on file depth.)

Inside the component:

```tsx
const { prefs } = usePreferences();
```

In the row render:

```tsx
{prefs.showProvenanceTags && (
  <ProvenanceTag value={(finding.provenance as Provenance) ?? null} />
)}
```

- [ ] **Step 3: Browser walk-through**

Open a scan job's findings (via the assets page or wherever the scan-job results are shown). With toggle on: pills appear. Toggle off: no pills.

### Task 4.5: Add a "Preferences" link in user settings

**Files:**
- Modify: wherever the authenticated user settings page lives. Probably `frontend/app/(authenticated)/settings/page.tsx` or a sub-page.

- [ ] **Step 1: Locate the settings page**

```bash
find "frontend/app/(authenticated)/settings" -name "*.tsx" 2>&1 | head
```

If a "preferences" sub-page already exists, modify it. Otherwise create `frontend/app/(authenticated)/settings/preferences/page.tsx`:

```tsx
"use client";

import { usePreferences } from "../../../lib/usePreferences";

export default function PreferencesPage() {
  const { prefs, loaded, update } = usePreferences();
  if (!loaded) return <div className="p-6 text-sm text-white/55">Loading…</div>;

  return (
    <div className="mx-auto max-w-3xl px-6 py-10 space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Preferences</h1>
        <p className="mt-2 text-sm text-white/65">Personal display settings.</p>
      </div>

      <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-5">
        <label className="flex items-start gap-3 cursor-pointer">
          <input
            type="checkbox"
            className="mt-1"
            checked={prefs.showProvenanceTags}
            onChange={(e) => update({ showProvenanceTags: e.target.checked })}
          />
          <div className="min-w-0">
            <div className="text-sm font-semibold text-white">Show provenance tags on findings</div>
            <div className="mt-1 text-xs text-white/65 leading-relaxed">
              Adds a small pill next to each finding — NEW for first detections,
              SEEN BEFORE for recurrences, RESOLVED BEFORE for regressions of
              previously-fixed findings. Only affects your own view.
            </div>
          </div>
        </label>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Link from the main settings page**

In whatever the authenticated settings index renders, add an entry pointing to `/settings/preferences`.

### Task 4.6: Commit Phase 4

- [ ] **Step 1: Stage and commit**

```bash
git add "frontend/app/(authenticated)/_components/" \
        "frontend/app/lib/api.ts" "frontend/app/lib/usePreferences.ts" \
        "frontend/app/(authenticated)/findings/" \
        "frontend/app/(authenticated)/settings/"
git commit -m "$(cat <<'EOF'
feat(findings): provenance pill + per-user display toggle

- New <ProvenanceTag /> component: one small pill (resolved_before /
  new / seen_before) with severity-style colour + tooltip.
- New usePreferences() hook reads/writes /settings/preferences;
  optimistic update with rollback on failure.
- Findings page header gains a 'Show provenance tags' checkbox.
  Per-row pill renders only when the pref is on.
- Scan-job findings render sites pick up the same pill via the same
  pref (no separate toggle).
- New /settings/preferences page hosts the toggle as a long-form
  setting so users can find it without visiting findings first.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 2: Wait for explicit push instruction.**

---

## Phase 5 — Frontend config (org + per-monitor)

### Task 5.1: Add `alertOnRecurrence` org setting UI

**Files:**
- Modify: wherever the monitoring/org settings page lives.

- [ ] **Step 1: Locate the monitoring settings UI**

```bash
find "frontend/app/(authenticated)/settings" -type d
find "frontend/app/(authenticated)/monitoring" -type d 2>/dev/null
grep -rln "alertOnRecurrence\|Monitoring settings\|Monitor config" "frontend/app/(authenticated)/" | head
```

If no existing surface fits, create `frontend/app/(authenticated)/settings/monitoring/page.tsx`. Otherwise modify the matching page.

- [ ] **Step 2: Add the radio**

```tsx
<div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-5 space-y-4">
  <div>
    <div className="text-sm font-semibold text-white">Alert scope (default)</div>
    <p className="mt-1 text-xs text-white/65 leading-relaxed">
      Default for all monitors in this organisation. Individual monitors
      can override this from their own settings.
    </p>
  </div>
  <label className="flex items-start gap-3 cursor-pointer">
    <input
      type="radio"
      name="alert-scope"
      className="mt-1"
      checked={!org.alertOnRecurrence}
      onChange={() => updateOrg({ alertOnRecurrence: false })}
    />
    <div>
      <div className="text-sm text-white">Alert on new findings only</div>
      <div className="text-xs text-white/65 mt-0.5">
        Quiet by default. Recurring findings (seen in any earlier scan)
        won't fire a fresh alert.
      </div>
    </div>
  </label>
  <label className="flex items-start gap-3 cursor-pointer">
    <input
      type="radio"
      name="alert-scope"
      className="mt-1"
      checked={!!org.alertOnRecurrence}
      onChange={() => updateOrg({ alertOnRecurrence: true })}
    />
    <div>
      <div className="text-sm text-white">Alert on new findings + recurrences</div>
      <div className="text-xs text-white/65 mt-0.5">
        Chatty. Every detection that wasn't in the previous scan fires
        an alert — including regressions of previously-resolved findings.
      </div>
    </div>
  </label>
</div>
```

`org` and `updateOrg` should come from whatever the existing settings page already uses for reading/writing org state. If there's no current `alertOnRecurrence` field on the type, add it.

- [ ] **Step 3: Add Owner/Admin gate**

If the existing page already gates Owner/Admin writes, the radio inherits it. Otherwise wrap the radio block in:

```tsx
{canEditOrgSettings ? (
  /* radio block above */
) : (
  <p className="text-sm text-white/55">Owner or Admin can change this.</p>
)}
```

### Task 5.2: Add `alertOnRecurrenceOverride` per-monitor UI

**Files:**
- Modify: wherever a monitor's edit panel/form lives. Probably `frontend/app/(authenticated)/monitoring/<...>` or inside `assets/[id]/page.tsx`.

- [ ] **Step 1: Locate the monitor edit form**

```bash
grep -rln "frequency\|monitor.*edit\|patchMonitor\|updateMonitor" "frontend/app/(authenticated)/" | head -5
```

Pick the form that PATCHes a monitor.

- [ ] **Step 2: Add a three-state selector**

```tsx
<div className="space-y-2">
  <label className="text-xs font-semibold text-white/65">Alert scope</label>
  <select
    value={
      monitor.alertOnRecurrenceOverride === null || monitor.alertOnRecurrenceOverride === undefined
        ? "inherit"
        : monitor.alertOnRecurrenceOverride
          ? "recurrences"
          : "new_only"
    }
    onChange={(e) => {
      const v = e.target.value;
      const next =
        v === "inherit" ? null : v === "recurrences" ? true : false;
      updateMonitor({ alertOnRecurrenceOverride: next });
    }}
    className="w-full h-9 rounded-lg border border-white/[0.08] bg-white/[0.03] px-2.5 text-sm text-white"
  >
    <option value="inherit">Use organisation default</option>
    <option value="new_only">Alert on new findings only</option>
    <option value="recurrences">Alert on new findings + recurrences</option>
  </select>
</div>
```

Wire the `updateMonitor` call to PATCH `/monitors/<id>` with the `alertOnRecurrenceOverride` field — the existing monitor-edit handler should accept it now that the backend Phase 3 work landed.

- [ ] **Step 3: Type-check**

```bash
cd frontend
npx tsc --noEmit 2>&1 | grep -E "monitoring|monitor" | head
```

Expected: no new errors.

- [ ] **Step 4: Browser walk-through**

1. Open org settings → toggle the radio. Verify it persists across reload.
2. Open a monitor's edit form → flip the selector through all three values. Verify each persists.
3. Trigger a monitor run (or wait for the scheduler) that detects a previously-seen finding. Verify the MonitorAlert table only contains a row when the effective policy is "alert on recurrences" for that monitor.

### Task 5.3: Commit Phase 5

- [ ] **Step 1: Stage and commit**

```bash
git add "frontend/app/(authenticated)/settings/" \
        "frontend/app/(authenticated)/monitoring/" 2>/dev/null
git add -u
git commit -m "$(cat <<'EOF'
feat(monitoring): org + per-monitor alert-scope UI

- Settings → Monitoring: radio for organisation default
  (new only / new + recurrences). Owner/Admin only.
- Each monitor's edit form: three-state selector (inherit org
  default / new only / new + recurrences). NULL override means
  inherit; explicit true/false overrides for this monitor.

Both call the existing PATCH endpoints extended in Phase 3.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 2: Wait for explicit push instruction.**

---

## Self-review

**Spec coverage:**

| Spec requirement | Task implementing it |
|---|---|
| `Finding.previously_resolved_at` column | Task 1.1 step 1 |
| `User.prefs_json` column | Task 1.1 step 2 |
| `Organization.alert_on_recurrence` column | Task 1.1 step 3 |
| `Monitor.alert_on_recurrence_override` column | Task 1.1 step 4 |
| Migration backfill | Task 1.2 step 2 |
| `mark_resolved` helper (idempotent on prev_resolved) | Task 2.1 step 1 |
| `derive_provenance` priority order | Task 2.1 step 1 + Task 2.1 step 2 tests |
| Resolve route uses helper | Task 2.2 step 2 |
| Bulk-status route uses helper | Task 2.2 step 3 |
| `provenance` on findings list/detail | Task 2.3 step 2 |
| `provenance` on scan-job findings | Task 2.3 step 3 |
| `should_alert_on_recurrence` helper | Task 3.1 step 1 |
| Change-detector gate | Task 3.2 step 3 |
| `GET /settings/preferences` | Task 3.3 step 2 |
| `PATCH /settings/preferences` with allowlist | Task 3.3 steps 1, 3 |
| Org PATCH extension | Task 3.3 step 4 |
| Monitor PATCH extension | Task 3.3 step 5 |
| `<ProvenanceTag />` component (3 styles, tooltip) | Task 4.1 step 2 |
| User pref hook | Task 4.2 step 2 |
| Findings page renders pill behind toggle | Task 4.3 steps 1-2 |
| Scan-job findings render pill | Task 4.4 step 2 |
| Preferences settings page hosts the toggle | Task 4.5 step 1 |
| Org alert-scope radio | Task 5.1 step 2 |
| Monitor override selector | Task 5.2 step 2 |
| Owner/Admin role gate on org setting | Task 5.1 step 3 |

All spec items map to tasks. No gaps.

**Placeholder scan:** No "TBD", "TODO", or vague directives. Every step contains exact code, exact commands, and exact expected outputs. The "locate the X" steps include grep commands so the engineer doesn't have to guess paths.

**Type/name consistency:**
- `Provenance` type literal `"new" | "seen_before" | "resolved_before"` consistent across backend `derive_provenance` return type and frontend `ProvenanceTag` `value` prop.
- `showProvenanceTags` casing consistent across `prefs_json` key, backend allowlist, frontend `UserPreferences` type, hook field, UI binding.
- `alertOnRecurrence` / `alertOnRecurrenceOverride` consistent across backend column names (snake_case in models / SQL) and JSON wire keys (camelCase).
- `mark_resolved` and `derive_provenance` referenced consistently in helpers, routes, and frontend imports.

**Ordering risk:** Phase 3 step 5 extends `PATCH /monitors/<id>` to accept `alertOnRecurrenceOverride`. Phase 5 step 2 wires a frontend selector to that endpoint. Phase ordering is correct — backend lands first.

**Scope:** One feature, five phases, ~17 atomic tasks. Single implementation plan is appropriate; no need to decompose further.
