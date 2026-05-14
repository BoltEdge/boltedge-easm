# KEV + EPSS — CVE Enrichment

**Module:** `backend/app/scanner/threat_intel.py` + extension of `backend/app/scanner/analyzers/cve_enricher.py`
**Detects:** Not a standalone detector — enriches CVE findings produced by other engines (Shodan, Nuclei) with two threat-intelligence signals:

- **CISA KEV** (Known Exploited Vulnerabilities): is this CVE actively being exploited in the wild?
- **EPSS** (Exploit Prediction Scoring System): probabilistic likelihood of exploitation in the next 30 days

**Plan gate:** Always-on for any plan that produces CVE findings. No customer-side toggle.
**Severity:** **Not changed.** Badge-only contract — a KEV-listed CVE keeps its CVSS-derived severity but gains the `kev` tag and `kev_listed=true` column for filtering/sorting

## Required setup

None. Both data sources are free public feeds:

- CISA KEV: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- FIRST.org EPSS: https://api.first.org/data/v1/epss

No API keys, no accounts. Just outbound HTTPS access from the backend container.

## Optional setup

None.

## How to verify

```bash
# Confirm the KEV cache is populated (refreshed daily at 02:00 UTC)
docker compose exec easm-db psql -U easm_user -d easm -c "
SELECT COUNT(*) AS kev_entries, MAX(fetched_at) AS last_refresh FROM kev_entry;
"
# Expected: ~1500 rows; last_refresh within the last 24h

# Confirm the EPSS cache has entries (populated on-demand per CVE)
docker compose exec easm-db psql -U easm_user -d easm -c "
SELECT COUNT(*) AS epss_entries FROM epss_cache;
"

# Force-refresh KEV right now (rather than wait for the daily job):
docker compose exec easm-backend python -c "
from app import create_app
app = create_app()
with app.app_context():
    from app.scanner.threat_intel import refresh_kev_feed
    n = refresh_kev_feed()
    print(f'Refreshed {n} KEV entries')
"

# Find an existing CVE finding that's been KEV-enriched:
docker compose exec easm-db psql -U easm_user -d easm -c "
SELECT public_id, severity, title, kev_listed, epss_score
FROM finding
WHERE kev_listed=true
ORDER BY epss_score DESC NULLS LAST
LIMIT 5;
"
```

## Operational notes

- **KEV refresh runs daily** at 02:00 UTC via APScheduler. ~1500 entries; small (<1 MB)
- **EPSS lookups happen at finding-creation time**, cached per-CVE for 7 days. The first scan that surfaces a new CVE pays a single API request; subsequent scans hit the cache
- Both feeds **fail closed silently** — if CISA or FIRST is unreachable, scans continue and CVE findings are stored without the enrichment fields. The next refresh / lookup retries
- KEV-listed findings can be filtered via `kev=1` on the `/findings` query, or sorted by `sort=epss` for descending exploit-likelihood ordering — both wired through the existing findings list page
- **Backfill** historic findings after first deploy with:
  ```bash
  docker compose exec easm-backend python -m scripts.backfill_threat_intel
  ```
  Idempotent; refreshes KEV first, then walks every unresolved `finding_type=cve` row and updates the three new columns + the `details_json.kev` / `details_json.epss` blobs

## Findings produced

KEV + EPSS does NOT produce its own findings — it enriches the CVE findings already produced by other engines. The enrichment adds:

- `Finding.kev_listed` — indexed boolean column
- `Finding.epss_score` — indexed float column
- `Finding.epss_percentile` — float column
- `Finding.details_json.kev` — the full CISA KEV row (date_added, vulnerability_name, required_action, due_date, known_ransomware)
- `Finding.details_json.epss` — `{score, percentile, fetched_at, model_version}`
- `kev` tag on the finding when listed
- `epss-high` tag when `epss_percentile >= 0.9`

These surface in the UI as:
- A red "KEV — Actively Exploited" pill on the finding row + details dialog
- A "By exploit likelihood (EPSS)" sort option on the findings list
- A "KEV" filter toggle on the findings page
- The full KEV context block in the finding details dialog

**Customer-facing category:** unchanged — same as the underlying CVE finding (Vulnerabilities)
