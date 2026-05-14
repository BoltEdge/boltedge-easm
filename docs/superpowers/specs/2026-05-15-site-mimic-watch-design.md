# Site Mimic Watch — Design Spec

**Date:** 2026-05-15
**Status:** Approved, ready for implementation plan
**Author:** Nano EASM team

## Goal

Detect sites that mimic a customer's pages — typosquats serving cloned login pages, brand-impersonation pages on unrelated hostnames, or freshly-registered domains that have already started cloning the customer's content. Closes one of the bigger Cyberint-comparable gaps without paid feeds and without adding a new top-level customer-facing module.

**Naming:** customer-facing = "Site Mimic Watch". Internal module = `mimic_engine` / `mimic_analyzer`. Deliberately avoids the "Phishing Detection" / "Anti-Phishing" framing of competing vendors per the project's no-vendor-naming rule.

**Bundled with Lookalike monitoring.** When a customer enables Lookalike on a watched domain, they automatically get Site Mimic Watch on the same domain. Single toggle, single plan cap (`lookalike_watch_domains`).

## Scope

### In scope
- Two candidate-discovery sources feeding one matcher pipeline:
  - **Lookalike-driven** — Mimic engine consumes the existing Lookalike engine's `verified_hits` and deep-checks any with live HTTP
  - **CT-log-driven** — new 15-minute background poller queries `crt.sh` for certs whose SAN list contains any watched-domain brand keyword
- Four match signals computed per candidate against a per-asset baseline:
  - DOM structural hash (tag tree fingerprint)
  - Favicon perceptual hash
  - Key-string extraction (title, h1, brand-keyword token set)
  - Visual perceptual hash (rendered screenshot via Playwright + Chromium)
- Severity bucketing from composite score (weighted average + max-single-signal override)
- Per-asset baseline lifecycle: capture on enable, refresh weekly, manual refresh from the asset detail page, delete on disable
- Screenshot storage in S3 with per-org cap and 90-day TTL on finding screenshots
- Findings produced under existing `lookalike` customer category with `finding_type=mimic` and tag `site-mimic`
- Asset detail page extended with a baseline-status row + storage usage indicator
- Finding details dialog shows side-by-side baseline + candidate when both screenshots are available

### Explicitly out of scope (separate specs / future work)
- Telegram channel monitoring (already deferred)
- Mobile app store monitoring (fake apps using customer brand on Apple/Google Play)
- Social media impersonation detection (fake LinkedIn / X profiles)
- Managed takedown service (service business, not engineering)
- Per-asset multi-page baseline (v1 captures only `/`)
- Tag-based "site-mimic only" sub-filter on /findings (tag is present, defer chip UI)
- Live pixel-diff overlay in the finding dialog
- Customer-tunable composite-score threshold
- Real-time CT log streaming via Cert Stream (crt.sh polling is sufficient for v1)
- Bitbucket / self-hosted GitLab as additional Mimic inputs (different design entirely)

### Explicit behaviour decisions
- **No new customer category.** Findings carry `category=lookalike` with `tag=site-mimic` so users can sub-filter. Avoids chip-row clutter on /findings; conceptually a mimic IS a deeper kind of lookalike.
- **No separate toggle.** The existing Lookalike toggle on the asset detail page enables both features. One feature, one cap.
- **Brand keyword auto-derived.** From the watched domain — `nanoeasm.com` → keyword `nanoeasm` via tldextract. No customer config.
- **Storage cap is soft.** Over-cap orgs still get findings, just without screenshot URLs. Hash-based detection never blocked by storage.
- **All failures silent.** Playwright crash, S3 outage, crt.sh rate-limit — each path returns gracefully so the parent Lookalike scan completes regardless.
- **Self-match guard.** Engine refuses to produce a finding when candidate hostname equals the asset's own value.
- **`MIMIC_ENABLED` is the master switch.** Deployments without the S3 bucket configured don't burn cycles.

## Architecture

```
INPUT A — Lookalike hits (existing pipeline):
  Weekly Lookalike scan completes for watched asset
       │
       ▼
  MimicEngine reads ctx.get_engine_data("lookalike")
  Picks verified_hits where HTTP responded 2xx/3xx
       │
       ▼
  → Matcher pipeline

INPUT B — CT log polling (new background ingestion):
  Every 15 min: _run_ct_log_monitor(app)
       │
       ▼  for each unique brand_keyword across watched assets
  GET https://crt.sh/?q=<brand_keyword>&output=json
       │
       ▼  dedupe by cert_id (UNIQUE constraint on (cert_id, hostname))
  Insert new rows into ct_log_candidate (status=NULL)
       │
       ▼
  Next MimicEngine run for an asset whose brand_keyword matches
  pulls unprocessed rows (LIMIT 20, oldest first)
       │
       ▼
  → Matcher pipeline

MATCHER (shared for both inputs):
  For each candidate hostname:
    1. Skip if hostname == asset.value (self-match guard)
    2. HTTP GET https://<hostname>/ (10s timeout, follow redirects)
    3. If 4xx/5xx/timeout → mark candidate fetch_failed, skip
    4. Compute four signals against mimic_baseline for the asset:
       - structural_score   = 1 - hamming(struct_hash, baseline) / 64
       - favicon_score      = 1 - hamming(favicon_phash, baseline) / 64
       - text_score         = jaccard(key_strings, baseline)
       - visual_score       = 1 - hamming(visual_phash, baseline) / 64
    5. composite = max(weighted_avg, max_single_signal)
       weights: visual=0.45, favicon=0.30, structural=0.15, text=0.10
    6. Severity bucket:
       ≥ 0.85 → critical
       ≥ 0.70 → high
       ≥ 0.55 → medium
       ≥ 0.40 → low
       < 0.40 → no finding
    7. Upload candidate screenshot to S3 (subject to org cap)
    8. Mark candidate processed in DB

  MimicAnalyzer reads engine output, produces FindingDrafts:
    template_id=mimic-detected, finding_type=mimic,
    tag=site-mimic, severity from composite bucket,
    details.mimic_screenshot_url, details.scores[]
```

### Why one engine that reads two input sources

The matcher logic is identical regardless of where the candidate hostname came from. A separate engine per input source would duplicate the entire pipeline. Instead the engine reads both inputs and converges them before scoring.

## Components

### New backend modules

| Module | Purpose | Key dependencies |
|---|---|---|
| `app/scanner/engines/mimic_engine.py` | Reads lookalike's `verified_hits` + `ct_log_candidate` rows; runs each through the matcher; returns scored matches | `page_renderer`, `page_signals`, `mimic_storage` |
| `app/scanner/analyzers/mimic_analyzer.py` | Converts engine output → `FindingDraft` rows. Severity from signal mix; one finding per scored match | Existing analyzer base |
| `app/services/page_renderer.py` | Playwright wrapper. Renders a URL to a JPEG (q=75, 1280×720), 10-second budget, 1-concurrent default. Returns `(image_bytes, width, height, render_ms)` | `playwright`, `Pillow` |
| `app/services/page_signals.py` | Pure functions: `structural_hash(html)`, `favicon_perceptual_hash(image_bytes)`, `extract_key_strings(html)`, `visual_perceptual_hash(image_bytes)`, `hash_distance(a, b)` | `BeautifulSoup`, `imagehash`, `Pillow` |
| `app/services/ct_log_monitor.py` | Polls `crt.sh?q=<brand>` every 15 min for each unique brand keyword across all watched assets; dedupes by `cert_id`; inserts new rows into `ct_log_candidate` | `requests`, `tldextract` |
| `app/services/mimic_storage.py` | Uploads JPEG to S3 (or local dev path); enforces per-org storage cap before upload; refuses if exceeded; supports finding-retention lifecycle | `boto3` |

### New DB tables

```sql
-- One baseline per watched asset; refreshed weekly. Stores hashes
-- (small) plus an S3 key for the baseline screenshot (kept so the
-- finding dialog can show side-by-side comparisons).
CREATE TABLE mimic_baseline (
    asset_id           INTEGER PRIMARY KEY REFERENCES asset(id) ON DELETE CASCADE,
    structural_hash    VARCHAR(64)  NOT NULL,
    favicon_phash      VARCHAR(64)  NULL,
    visual_phash       VARCHAR(64)  NOT NULL,
    key_strings_json   JSON         NOT NULL,
    baseline_image_key VARCHAR(255) NULL,
    captured_at        TIMESTAMP    NOT NULL,
    last_refresh_at    TIMESTAMP    NOT NULL
);

-- Queue of CT-log-discovered candidate hostnames waiting to be checked.
-- Bounded by per-keyword 50-candidate-per-poll cap + hourly cleanup.
CREATE TABLE ct_log_candidate (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    brand_keyword   VARCHAR(64)  NOT NULL,
    hostname        VARCHAR(255) NOT NULL,
    cert_id         VARCHAR(40)  NOT NULL,
    cert_logged_at  TIMESTAMP    NULL,
    discovered_at   TIMESTAMP    NOT NULL,
    processed_at    TIMESTAMP    NULL,
    processed_status VARCHAR(20) NULL,
    expires_at      TIMESTAMP    NOT NULL,
    UNIQUE(cert_id, hostname)
);
CREATE INDEX ix_ct_log_candidate_brand_unprocessed
    ON ct_log_candidate (brand_keyword, processed_at);
CREATE INDEX ix_ct_log_candidate_expires_at
    ON ct_log_candidate (expires_at);
```

### Plan config

New per-tier limit `mimic_storage_mb` added to `PLAN_CONFIG` in `app/billing/routes.py`:

| Plan | mimic_storage_mb |
|---|---|
| Free | 0 (feature unavailable) |
| Starter | 20 |
| Professional | 100 |
| Enterprise Silver | 500 |
| Enterprise Gold | 2000 |
| Custom | -1 (unlimited) |

The existing `lookalike_watch_domains` limit gates whether the feature can be enabled at all — Free customers (0) never reach the Mimic engine.

### Reuse / extend existing modules

| Existing | Change |
|---|---|
| `app/scanner/engines/__init__.py` | Register `MimicEngine` in `ALL_ENGINES` |
| `app/scanner/analyzers/__init__.py` | Register `MimicAnalyzer` in `ALL_ANALYZERS` (before `ExposureScorer`) |
| `app/scanner/orchestrator.py` | `_compute_enabled_engines` adds `mimic` when `profile.use_lookalike=True` AND asset has `lookalike_watch=True` AND `MIMIC_ENABLED=true` |
| `app/scanner/templates.py` | Add `mimic-detected` finding template with severity-from-engine pattern |
| `app/scheduler.py` | Two new jobs: `_run_ct_log_monitor` (15 min), `_run_ct_log_cleanup` (hourly) |
| `app/assets/routes.py` | Asset GET endpoint includes `mimicBaseline` (captured_at, last_refresh_at, storage_used_mb) |
| `app/assets/routes.py` | New endpoint `POST /assets/<id>/mimic-baseline-refresh` for the manual refresh button |
| Migration | Adds `mimic_baseline`, `ct_log_candidate` tables; seeds `mimic-detected` template via templates.py registration |

### Env vars (new)

| Var | Purpose |
|---|---|
| `MIMIC_ENABLED` | Master switch (default `false`). Defaults to off so deployments without S3 set up don't fail loudly. |
| `MIMIC_S3_BUCKET` | S3 bucket name. Required when `MIMIC_ENABLED=true`. |
| `MIMIC_S3_REGION` | Region (defaults `us-east-1`). |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | Standard AWS auth. Skip if using IAM role on the EC2 instance. |

### Docker image impact

Backend image grows ~200 MB to fit Playwright's Chromium binary. Build adds these `apt-get install` lines (already present in many Playwright bases):

```
libnss3 libxss1 libasound2 libatk-bridge2.0-0 libgtk-3-0 \
libgbm-dev libxcomposite1 libxdamage1 libxrandr2 libpangocairo-1.0-0 \
libdrm2 libxkbcommon0
```

And: `pip install playwright && playwright install chromium`. Done once at build, cached on subsequent builds.

## Data flow — worked example

Attacker registers `nanoeasm.co` and serves a copy of `nanoeasm.com`. Cert hits CT log.

```
T+0s:     crt.sh records the cert for nanoeasm.co
T+0s:     CT log poller picks it up (brand_keyword=nanoeasm)
T+0s:     Insert into ct_log_candidate (unprocessed)
T+10min:  Existing weekly Lookalike scan for nanoeasm.com fires
          OR a manual trigger from the asset detail page
T+10m1s:  MimicEngine picks up ct_log_candidate + lookalike's verified_hits
T+10m2s:  Fetches nanoeasm.co/, computes signals:
            structural_score=0.94, favicon_score=1.00,
            text_score=0.85, visual_score=0.91
T+10m3s:  composite = max(weighted_avg, max_single) = 0.94 → critical
T+10m4s:  Screenshot uploaded to S3 (subject to org cap)
T+10m4s:  Finding row created on nanoeasm.com asset:
            template_id=mimic-detected, finding_type=mimic,
            category=lookalike, tag=site-mimic, severity=critical
T+10m4s:  Customer sees the alert in /findings + monitoring dashboard
```

## Baseline lifecycle

- **Captured first time** when customer toggles Lookalike monitoring on AND `MIMIC_ENABLED=true`. Scheduler immediately runs a baseline-capture task that fetches the customer's real page, computes four signal hashes, stores in `mimic_baseline`. Uploads baseline screenshot to S3 (one per asset, replaced on refresh).
- **Refreshed weekly** at the same cadence as the Lookalike scan — before running the mimic engine, re-capture the baseline so the matcher uses fresh hashes
- **Manual refresh button** on the asset detail page below the Lookalike toggle — triggers a one-off recapture for the customer-controlled case where their site changed
- **Deleted** automatically when the customer disables Lookalike monitoring (cascade from `asset_id` FK)

## Error handling

| Failure mode | Behaviour |
|---|---|
| `MIMIC_ENABLED` unset or `false` | Engine short-circuits; no candidates processed; no S3 calls |
| Playwright/Chromium crash mid-render | Per-candidate try/except; candidate marked `fetch_failed`; engine continues |
| Candidate hostname returns 4xx/5xx/timeout | Mark `processed_status=fetch_failed`; skip |
| Favicon URL 404s | Skip favicon signal; matcher proceeds with three signals; require higher visual+structural to compensate |
| Baseline missing | Log info; skip cycle; scheduler triggers a baseline-capture task; mimic runs on next cycle |
| S3 upload fails | Finding produced WITHOUT screenshot URL; log at WARNING; matcher result intact |
| `crt.sh` rate-limited / 5xx | CT log monitor returns 0 candidates that cycle; next 15-min tick retries |
| Org over storage cap | Finding produced without screenshot; `details_json.mimic_storage_full=true`; banner in UI |
| Brand keyword too short returns thousands of CT-log hits | Per-keyword cap of 50 candidates per poll; the rest get picked up on the next tick |
| `use_lookalike` profile flag not set | Engine short-circuits silently |

**Invariant: a scan never fails because the Mimic Watch stack fails.** Every error path returns gracefully; the parent Lookalike scan still produces its lookalike findings.

## Test plan

### Unit — `page_signals`
- `structural_hash` deterministic for same HTML, differs for changed HTML
- `favicon_perceptual_hash` consistent across re-encodings
- `hash_distance` symmetric and bounded
- `extract_key_strings` handles malformed HTML without crashing

### Unit — `page_renderer`
- Playwright mock; verifies 10-second timeout enforcement
- Verifies JPEG output, dimensions, quality setting
- Crash-mid-render returns None without raising

### Unit — `mimic_storage`
- S3 mock; verifies key construction (`mimic/<org_id>/<asset_id>/<finding_id>.jpg`)
- Cap-enforcement: refuses upload when exceeded
- Idempotent retry safe

### Unit — `ct_log_monitor`
- crt.sh mock; dedupe by `cert_id`; per-keyword 50-candidate cap; brand_keyword filter

### Unit — `mimic_engine`
- Matcher math: composite scoring, severity bucketing
- Both input sources merged correctly
- Candidate-self filter
- Missing baseline → log + skip

### Unit — `mimic_analyzer`
- Each severity bucket → expected template + tag
- `details_json` shape includes per-signal scores
- Multiple matches → one finding per match (no aggregation)

### Integration
- Fixture asset; mock crt.sh + Playwright + S3
- End-to-end: lookalike hit + CT log candidate → mimic engine runs → finding row with correct severity + tag
- Storage-cap exhausted → finding produced without screenshot URL
- Disable Lookalike → baseline row deleted

### Manual
- Real Playwright + real S3 against a test asset
- Verify weekly baseline refresh in the actual environment
- Verify side-by-side comparison in finding dialog
- Verify storage cap banner triggers correctly

## Rollout

1. **Migration**: add `mimic_baseline`, `ct_log_candidate` tables; add `mimic_storage_mb` to `PLAN_CONFIG`
2. **Image rebuild**: Dockerfile installs Playwright + Chromium system deps
3. **S3 bucket setup** (operator-side): create the bucket; lifecycle rule for 90-day expiry on objects with prefix `findings/`; set `MIMIC_S3_BUCKET` env var
4. **Deploy backend**: `docker compose up -d --build easm-backend`
5. **Set `MIMIC_ENABLED=true`** in `.env`, restart
6. **First baseline capture** runs automatically on the next weekly lookalike tick (or via manual refresh button)
7. **CT log poller** starts ingesting immediately; first findings within ~15-25 min for any active phishing infrastructure

### Rollback

Straight `git revert`. The new tables can stay empty. `MIMIC_ENABLED=false` switches the whole feature off without code changes. Playwright/Chromium stays in the image but does nothing if the engine isn't called.

## Open questions

None — all decisions resolved during brainstorming.

## References

- Lookalike spec (this feature builds on it): `docs/superpowers/specs/2026-05-14-lookalike-domain-detection-design.md`
- Existing LeakEngine pattern (similar two-input-source architecture): `backend/app/scanner/engines/leak_engine.py`
- Pastebin background fetcher (mirror for CT log monitor): `backend/app/services/pastebin_client.py`
- Playwright docs: https://playwright.dev/python/docs/intro
- crt.sh CT log search: https://crt.sh/
- Avoid-vendor-naming memory: `feedback_avoid_vendor_naming.md`
