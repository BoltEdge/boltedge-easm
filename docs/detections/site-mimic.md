# Site Mimic Watch

> **Status:** Designed but not yet shipped. Spec at
> `docs/superpowers/specs/2026-05-15-site-mimic-watch-design.md`.
> This document is the operator-setup reference for the feature
> once it lands.

**Module:** `backend/app/scanner/engines/mimic_engine.py` + `backend/app/scanner/analyzers/mimic_analyzer.py` (planned)
**Detects:** Sites that clone or mimic the customer's pages — login pages, homepages, branded content — hosted on attacker-controlled hostnames. Uses Lookalike's verified hits + CT-log monitoring as candidate sources, then matches each candidate against a per-asset baseline using four signals (DOM structural hash, favicon perceptual hash, key strings, full-page visual perceptual hash via Playwright + Chromium screenshot)
**Plan gate:** Bundled with Lookalike (`lookalike_watch_domains`). New `mimic_storage_mb` plan limit governs how much S3 storage each org gets for screenshots
**Severity:** Composite-score buckets — ≥0.85 → critical, ≥0.70 → high, ≥0.55 → medium, ≥0.40 → low, <0.40 → no finding

## Required setup

### Master switch

```bash
MIMIC_ENABLED=true
```

When unset or `false`, the engine short-circuits silently and no Mimic detection runs.

### S3 bucket for screenshots

```bash
MIMIC_S3_BUCKET=nano-easm-mimic-screenshots
MIMIC_S3_REGION=us-east-1
# AWS auth (only needed if not using IAM role on the EC2 instance):
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

Setup steps (operator-side, one-off):

1. **Create the S3 bucket** in your AWS account. Block public access (default).
2. **Lifecycle rule**: configure objects with prefix `findings/` to expire after 90 days. Saves on storage; matches the in-app finding-retention behaviour
3. **IAM permissions**: if using an IAM role on the EC2 instance, attach a policy granting `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject` on `arn:aws:s3:::<bucket>/*`. If using access keys, generate them with the same minimal scope
4. **Set the env vars** in `.env` and add them to `docker-compose.yml` under `easm-backend.environment:`
5. **Rebuild and restart** the backend so the env reaches the container

### Chromium baked into the backend image

The Dockerfile must `pip install playwright` and run `playwright install chromium` plus the system-package dependencies Playwright needs:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libxss1 libasound2 libatk-bridge2.0-0 libgtk-3-0 \
    libgbm-dev libxcomposite1 libxdamage1 libxrandr2 libpangocairo-1.0-0 \
    libdrm2 libxkbcommon0 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install playwright \
    && playwright install chromium
```

This adds ~200 MB to the image (Chromium binary). Cached on subsequent builds.

## Optional setup

- **Per-tier storage caps** in `PLAN_CONFIG`:
  - Free: 0 (feature unavailable)
  - Starter: 20 MB
  - Professional: 100 MB
  - Enterprise Silver: 500 MB
  - Enterprise Gold: 2000 MB
  - Custom: -1 (unlimited)

  Adjust in `backend/app/billing/routes.py` under `PLAN_CONFIG[<tier>]["limits"]["mimic_storage_mb"]`

## How to verify

```bash
# Confirm Playwright + Chromium installed
docker compose exec easm-backend python -c "
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    print('Chromium executable:', p.chromium.executable_path)
"
# Expected: a path inside the container

# Confirm S3 bucket access
docker compose exec easm-backend python -c "
import boto3, os
s3 = boto3.client('s3', region_name=os.environ.get('MIMIC_S3_REGION', 'us-east-1'))
print(s3.list_objects_v2(Bucket=os.environ['MIMIC_S3_BUCKET'], MaxKeys=1))
"

# Confirm baseline tables exist (after migration)
docker compose exec easm-db psql -U easm_user -d easm -c "
SELECT COUNT(*) FROM mimic_baseline;
SELECT COUNT(*) FROM ct_log_candidate;
"

# Watch CT log monitor activity (runs every 15 min):
docker compose logs easm-backend --tail=200 2>&1 | grep -i "ct_log_monitor\|mimic_engine"
```

## Operational notes

- **First baseline capture** runs automatically when a customer toggles Lookalike monitoring on a domain AND `MIMIC_ENABLED=true`. The scheduler enqueues a baseline-capture task immediately
- **Weekly baseline refresh** happens at the same cadence as the Lookalike scan — the engine re-captures the customer's real page before running the matcher so the baseline doesn't drift
- **Manual refresh button** on the asset detail page lets customers trigger a one-off recapture if their site changed
- **CT log polling**: every 15 min, the poller queries `crt.sh?q=<brand>` for each unique brand keyword across all watched assets. Per-keyword cap of 50 candidates per poll prevents queue explosion for short / common brand names
- **Per-candidate render budget** is 10 seconds. Most pages render in 2-4 seconds; complex SPAs may take longer
- **Concurrency** is 1 Chromium instance at a time by default (configurable). Each instance uses ~200-300 MB RAM
- **Storage accounting**: live-computed by summing `details_json.mimic_screenshot_size` across an org's open mimic findings. Cached for 60 seconds in memory to avoid recomputation in batch writes
- **Over-cap behaviour**: findings still produced; screenshot upload skipped; `details_json.mimic_storage_full=true` flag set; UI shows a banner to the customer

## Findings produced

| Template ID | Trigger | Severity |
|---|---|---|
| `mimic-detected` | Composite score ≥ 0.40 against the asset's baseline | from composite bucket |

The single template carries source-aware copy. Finding details_json includes:

- `mimic_screenshot_url` — S3 URL of the candidate screenshot (or `null` if storage cap exceeded)
- `mimic_screenshot_size` — bytes of the stored screenshot (for storage accounting)
- `mimic_storage_full` — boolean flag if upload was refused
- `composite_score` — final score 0-1
- `signal_scores` — per-signal breakdown: `{structural, favicon, text, visual}`
- `input_source` — `"lookalike_hit"` or `"ct_log_candidate"` (which discovery channel surfaced this)
- `candidate_hostname` — the suspect URL

Findings carry:
- `category=lookalike` (reuses the Lookalike Domains customer category)
- `finding_type=mimic`
- `tag=site-mimic`

**Customer-facing category:** Lookalike Domains (no new category)

## Related features

- [lookalike.md](lookalike.md) — bundled with this feature. Site Mimic Watch is automatically enabled when Lookalike monitoring is enabled AND `MIMIC_ENABLED=true`
