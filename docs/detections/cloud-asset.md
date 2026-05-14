# Cloud Asset Detection

**Module:** `backend/app/scanner/engines/cloud_asset_engine.py` + `backend/app/scanner/analyzers/cloud_asset_analyzer.py`
**Detects:** Cloud-hosted assets (S3 buckets, Azure blobs, GCS buckets, container registries, serverless functions) referenced by the customer's domain. Checks for public-read misconfiguration, bucket-name takeover potential, and exposed registry images
**Plan gate:** Deep scan profile only — `cloud_asset` is added to enabled engines when the profile is named "Deep" (see `_compute_enabled_engines` in `app/scanner/orchestrator.py`)
**Severity:** Public-readable bucket with directory listing → critical; bucket exists but private → info; unclaimed bucket name on a CNAME → high (takeover risk)

## Required setup

None at deploy time. The engine works against the public cloud APIs (S3 ListBucket, etc.) without credentials.

## Optional setup

None. Adding cloud-provider credentials does NOT improve detection — public-readable buckets are detectable anonymously, and authenticated probes would actually reduce the signal we're trying to surface ("can the world see this?").

## How to verify

```bash
# Trigger a Deep scan on a domain you own that uses S3 / GCS / Azure storage.
# Watch engine activity:
docker compose logs easm-backend --tail=200 2>&1 | grep -i "cloud_asset"

# Cloud-asset findings:
docker compose exec easm-db psql -U easm_user -d easm -c "
SELECT public_id, severity, title FROM finding
WHERE category='cloud' AND ignored=false AND resolved=false
ORDER BY id DESC LIMIT 10;
"
```

## Operational notes

- The engine inputs come from the **discovery layer**, not from active probing. Discovery enumerates cloud candidates per asset (e.g. CNAME pointing at `*.s3.amazonaws.com`, hostname matching `*.azureedge.net`)
- For each candidate, the engine sends a HEAD / GET to the public API endpoint and inspects the response — no API keys required
- Cloud takeover detection runs by checking if the CNAME-referenced bucket / container is unclaimed (HTTP 404 + canonical "no such bucket" / "container not found" response shape)
- Public-readable bucket directory listings are the highest-signal finding here; the engine extracts a sample of object names when present (capped at 20) so the operator can confirm the leak without running their own probes

## Findings produced

| Template ID | Trigger | Severity |
|---|---|---|
| `cloud-s3-public-listing` | S3 bucket allows `ListBucket` to anonymous callers | critical |
| `cloud-s3-public-read` | S3 bucket allows `GetObject` but not listing | high |
| `cloud-s3-takeover-vulnerable` | CNAME points at an S3 bucket that doesn't exist (claimable) | high |
| `cloud-azure-blob-public` | Azure blob container allows anonymous read | high |
| `cloud-azure-blob-takeover-vulnerable` | CNAME points at an unclaimed Azure resource | high |
| `cloud-gcs-public-listing` | Google Cloud Storage bucket allows public listing | critical |
| `cloud-gcs-takeover-vulnerable` | CNAME points at an unclaimed GCS bucket | high |
| `cloud-container-registry-public` | Container registry exposes image manifests publicly | high |
| `cloud-serverless-function-info` | Cloudflare Worker / Lambda function URL detected | info (inventory) |

**Customer-facing category:** Service Exposure
