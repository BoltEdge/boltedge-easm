# KEV + EPSS Finding Enrichment — Design Spec

**Date:** 2026-05-13
**Status:** Approved, ready for implementation plan
**Author:** Nano EASM team

## Goal

Add real-world exploit context to every CVE-based finding by integrating two free, authoritative threat-intel feeds:

- **CISA Known Exploited Vulnerabilities (KEV)** — CVEs with observed real-world exploitation
- **EPSS (Exploit Prediction Scoring System)** — probabilistic likelihood (0–1) of exploitation in the next 30 days, maintained by FIRST.org

The user-facing payoff is a "this is actively exploited" signal alongside CVSS, closing one of the visibility gaps versus Cyberint and similar competitors at near-zero ongoing cost.

## Scope

### In scope
- Backend module that fetches, caches, and exposes KEV + EPSS data
- DB cache tables for both feeds
- Extension of the existing `cve_enricher` analyzer to populate three new finding columns and structured details fields
- Daily background refresh of the full KEV feed
- Per-CVE on-demand EPSS lookup with a 7-day cache TTL
- One-time backfill script for existing unresolved CVE findings
- Minimal UI surface: KEV badge + EPSS line in the finding details panel

### Explicitly out of scope (later specs)
- Filter / sort options on the findings list by KEV or EPSS
- Dashboard widget showing KEV-listed finding counts
- Email or webhook alerts when a new finding lands on a KEV-listed CVE
- Daily re-check that updates historical findings when a CVE is *added* to KEV after the finding was created — backfill is one-shot only
- Bulk EPSS CSV ingestion — per-CVE API is sufficient at current scan volume

### Explicit behaviour decisions
- **Severity is NOT changed by KEV listing.** KEV is a badge / tag / sortable column only. A CVSS 6.5 KEV-listed CVE remains severity=medium, gaining `kev_listed=true` and the `kev` tag. Rationale: avoids disruption to existing customer alerts and dashboards. Severity-bumping behaviour can be added later as an opt-in policy if customers request it.
- **Failures are silent.** A KEV refresh failure or an EPSS API outage never breaks a scan. Findings are stored without the threat-intel fields and the next scan retries.

## Architecture

One new utility module, called by both the live scan analyzer and the backfill script. No new pipeline stages, no new analyzer classes.

```
Scan runs
  ↓
ShodanEngine produces vulns dict
  ↓
cve_enricher.analyze() iterates CVEs
  ↓
For each CVE: threat_intel.enrich_cve(cve_id)
  ├─ lookup_kev(cve_id) — DB read of kev_entry (indexed PK)
  └─ lookup_epss(cve_id) — DB read of epss_cache; if stale or missing,
                            fetch from FIRST.org API and upsert
  ↓
FindingDraft populated with kev_listed, epss_score, epss_percentile,
details.kev, details.epss, tags (+ "kev" when listed)
  ↓
Persisted to finding table

Daily 02:00 UTC (APScheduler):
  refresh_kev_feed() pulls full JSON from CISA, upserts kev_entry rows

Backfill (one-off, run on deploy):
  scripts/backfill_threat_intel.py iterates unresolved CVE findings
  → calls enrich_cve(cve_id) → updates the row in place
```

### Why the utility-module pattern wins over alternatives

- **New analyzer class:** `BaseAnalyzer` reads engine data and produces drafts. Mutating drafts from another analyzer fights the pattern.
- **Orchestrator post-step:** clean but introduces a new pipeline stage. Overkill for what is effectively a function call.
- **Inline in `cve_enricher`:** the backfill script can't run an analyzer (no `ScanContext`). Extracting the lookup into its own module lets the script reuse the same code.

## Components

### 1. `backend/app/scanner/threat_intel.py` *(new)*

Public API:

```python
def lookup_kev(cve_id: str) -> dict | None:
    """Returns KEV entry as dict if CVE is listed; None otherwise.
    Never raises — DB errors return None and log."""

def lookup_epss(cve_id: str) -> dict | None:
    """Returns {score, percentile, fetched_at} from cache.
    If cache stale or missing, fetches from FIRST.org and upserts.
    Never raises — API errors return None and log."""

def enrich_cve(cve_id: str) -> dict:
    """Convenience wrapper. Returns {kev: <dict|None>, epss: <dict|None>}."""

def refresh_kev_feed() -> int:
    """Pulls full KEV JSON from CISA, upserts kev_entry rows.
    Returns the count of entries upserted. Run daily by APScheduler.
    On HTTP error, logs and returns 0 — last-known DB rows continue serving."""
```

External endpoints:
- KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (~1.5 MB, ~1500 entries, no auth)
- EPSS: `https://api.first.org/data/v1/epss?cve=CVE-XXXX-YYYY` (no auth, polite rate)

HTTP timeout: 10s for KEV refresh, 5s for per-CVE EPSS.

### 2. `kev_entry` table *(new)*

```sql
CREATE TABLE kev_entry (
    cve_id VARCHAR(20) PRIMARY KEY,
    date_added DATE NOT NULL,
    vendor VARCHAR(255),
    product VARCHAR(255),
    vulnerability_name VARCHAR(500),
    known_ransomware BOOLEAN NOT NULL DEFAULT FALSE,
    required_action TEXT,
    due_date DATE,
    short_description TEXT,
    fetched_at TIMESTAMP NOT NULL
);
CREATE INDEX ix_kev_entry_fetched_at ON kev_entry (fetched_at);
```

Mirrors CISA's published JSON shape. PK on `cve_id` so `lookup_kev` is O(1).

### 3. `epss_cache` table *(new)*

```sql
CREATE TABLE epss_cache (
    cve_id VARCHAR(20) PRIMARY KEY,
    score DOUBLE PRECISION NOT NULL,
    percentile DOUBLE PRECISION NOT NULL,
    model_version VARCHAR(20),
    fetched_at TIMESTAMP NOT NULL
);
CREATE INDEX ix_epss_cache_fetched_at ON epss_cache (fetched_at);
```

`fetched_at` drives the 7-day TTL check inside `lookup_epss`.

### 4. `Finding` model — three new columns

```python
kev_listed = db.Column(db.Boolean, nullable=False, default=False, index=True)
epss_score = db.Column(db.Float, nullable=True, index=True)
epss_percentile = db.Column(db.Float, nullable=True)
```

The two indexed columns support the future filter / sort UI without another migration.

Migration adds the three columns and chains from the most recent head.

### 5. `cve_enricher.py` — extended

The `_build_cve_finding` method calls `threat_intel.enrich_cve(cve_id)` once per CVE and:

- Sets `FindingDraft.kev_listed = bool(result["kev"])`
- Sets `FindingDraft.epss_score = result["epss"]["score"]` if EPSS present
- Sets `FindingDraft.epss_percentile = result["epss"]["percentile"]` if EPSS present
- Adds `details.kev` and `details.epss` with the raw blobs
- Appends `"kev"` to tags when listed; appends `"epss-high"` when EPSS percentile ≥ 0.9

The `FindingDraft` dataclass in `app/scanner/base.py` gains three optional fields (`kev_listed`, `epss_score`, `epss_percentile`). The orchestrator's draft→Finding persistence step copies them through. Both updates are mechanical.

### 6. APScheduler job — daily KEV refresh

In `app/scheduler.py`, register a daily 02:00 UTC job that calls `refresh_kev_feed()`. Heartbeat the result (entries upserted) to the existing health system.

### 7. Backfill script — `backend/scripts/backfill_threat_intel.py`

CLI entry point, run once per environment after migration. Steps:

1. Refresh KEV feed first so the cache is hot
2. Iterate `Finding` rows where `finding_type='cve'` AND `resolved=false` AND `ignored=false`, ordered by id
3. For each: extract the CVE ID from `details_json.cve_id` (set by `cve_enricher`); skip if missing
4. Call `enrich_cve(cve_id)` and update the row's three new columns plus `details.kev` and `details.epss`
5. Commit in batches of 100; log progress every 1000 rows
6. Idempotent — re-running just refreshes `fetched_at` and any stale data

Run command:
```bash
docker compose exec easm-backend python -m scripts.backfill_threat_intel
```

### 8. UI changes — finding details panel only

In the existing finding details panel component, when a finding's `kev_listed` is true, render:

```
[KEV badge] Actively Exploited
Added to CISA KEV on {date_added}
{vulnerability_name}
Known ransomware use: {yes / no}
Required action by: {due_date if present}
```

When `epss_score` is set, render below CVSS:

```
EPSS {epss_score * 100}% (top {(1 - epss_percentile) * 100}% of all CVEs)
```

Both blocks link out to the canonical sources (CISA KEV catalog, FIRST EPSS docs).

No new components — extend the existing panel. No filter or sort UI changes.

## Error handling

| Failure mode | Behaviour |
|---|---|
| KEV refresh — CISA endpoint unreachable | Log error; keep serving from last DB rows. Heartbeat reports failure. |
| KEV refresh — JSON malformed | Log error; abort upsert; old rows remain valid. |
| EPSS per-CVE — API timeout / non-2xx | Log warning; return None; finding stored without EPSS fields; next scan retries. |
| DB error on cache lookup | Log error; return None; scan continues with finding-stored-without-fields. |
| Backfill — single-row update fails | Log row id + error; continue to next row; final summary reports failed count. |

The product invariant: **a scan never fails because of threat-intel enrichment.** Every error path returns a None / falsy value that the analyzer handles as "no enrichment data for this CVE."

## Test plan

### Unit
- `lookup_kev` returns dict when row exists; None when not; None when DB raises
- `lookup_epss` returns cached value when `fetched_at` within 7 days; fetches and upserts when stale; returns None on API timeout
- `enrich_cve` aggregates both correctly when both succeed, when only one succeeds, when both fail
- `refresh_kev_feed` upserts new rows, updates changed rows, leaves unchanged rows alone, returns correct count
- `_build_cve_finding` (in `cve_enricher`) populates all new fields on the draft, adds the right tags

### Integration
- Mock the CISA + FIRST endpoints with fixture JSON. Run a scan that produces a CVE finding for a known KEV-listed CVE. Assert the persisted `Finding` row has `kev_listed=true`, populated `epss_score`, and `details.kev` / `details.epss` blobs.
- Run the backfill script against a seeded DB with 50 mixed findings (KEV-listed, EPSS-only, neither). Assert correct fields after the run. Re-run; assert idempotent.

### Manual
- Trigger a scan on a real domain known to have KEV-listed CVEs. Inspect the finding details panel in the browser. Verify the badge renders, the EPSS line renders, both links open the right pages.

## Rollout

1. Migration: add `kev_entry`, `epss_cache`, three Finding columns
2. Deploy backend
3. Run the backfill script (`python -m scripts.backfill_threat_intel`) once per environment. The script refreshes the KEV feed before iterating, so the cache is hot immediately — no waiting for the daily 02:00 UTC job.
4. New scans automatically enrich going forward

Rollback is trivial: revert the deploy. The three new Finding columns can be left in place (they're nullable / default-false and don't affect existing queries). Tables can stay empty.

## Open questions

None — all major decisions were resolved during brainstorming.

## References

- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- EPSS: https://www.first.org/epss/
- Existing CVE pipeline: `backend/app/scanner/analyzers/cve_enricher.py`
- Finding model: `backend/app/models.py` (class `Finding` ~line 404)
