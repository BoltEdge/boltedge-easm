# Lookalike Domain Detection

**Module:** `backend/app/scanner/engines/lookalike_engine.py` + `backend/app/scanner/analyzers/lookalike_analyzer.py`
**Detects:** Typosquats, homoglyph confusables, TLD swaps, vowel-swap variants, IDN/punycode tricks. Generates ~250-1000 plausible variants per watched domain via DNSTwist, then verifies each via DNS A-record + HTTP HEAD on port 80/443 + crt.sh certificate-transparency search
**Plan gate:** `lookalike_watch_domains` (Free=0, Starter=1, Pro=3, Silver=10, Gold=25, Custom=∞). Per-asset opt-in via the toggle on the asset detail page
**Severity:** Live HTTPS + recent cert → high; DNS + cert → medium; DNS only OR cert only → low; nothing → no finding

## Required setup

None. The engine uses two free sources:

- **dnstwist** (Python package, declared in `requirements.txt`) — variant generation
- **crt.sh** — public certificate-transparency log search, no auth

The DNS + HTTP probes use the container's standard resolver and outbound HTTP.

## Optional setup

None.

## How to verify

```bash
# Confirm dnstwist is installed:
docker compose exec easm-backend python -c "from dnstwist import Fuzzer; print('dnstwist OK')"
# Expected: "dnstwist OK"

# Confirm the system profile exists (created by the migration):
docker compose exec easm-db psql -U easm_user -d easm -c "
SELECT id, name, is_system, use_lookalike FROM scan_profile
WHERE name='Lookalike Scan';
"
# Expected: one row, is_system=true, use_lookalike=true

# Find currently-watched assets:
docker compose exec easm-db psql -U easm_user -d easm -c "
SELECT id, value, asset_type, lookalike_watch, last_lookalike_scan_at
FROM asset
WHERE lookalike_watch=true
ORDER BY last_lookalike_scan_at DESC NULLS LAST
LIMIT 10;
"

# After enabling on an asset, trigger a manual scan from the asset detail page
# ("Run scan now" button) and watch engine logs:
docker compose logs easm-backend --tail=200 2>&1 | grep -i "lookalike_engine"
```

## Operational notes

- **Engine self-rate-limits at 6 days.** A second manual scan within 6 days short-circuits — the engine returns the existing baseline data without re-probing crt.sh
- **Weekly scheduler at 03:00 UTC** (`_run_lookalike_schedule`) enqueues scan jobs for every watched asset whose `last_lookalike_scan_at` is older than 6 days. Daily check, weekly effective cadence
- **Variant volume**: dnstwist generates 4000+ candidates for typical brand-length domains. The engine filters to the high-signal families (typo, homoglyph, vowel-swap, etc.) and caps homoglyph at 250 to stay under crt.sh rate limits
- **Findings dedupe** on `(parent_asset_id, variant_domain)` so weekly re-scans update the existing Finding rather than duplicating
- **First lookalike scan per asset** can take 5-10 min on a healthy domain; subsequent scans within 6 days short-circuit instantly

## Findings produced

| Template ID pattern | Trigger | Severity |
|---|---|---|
| `lookalike-<variant_domain>` (dynamically generated) | Variant has at least one positive signal | per signal mix |

The analyzer doesn't use the curated template registry for lookalike — finding title, description, and remediation are constructed dynamically from the variant's verification data. Findings carry:

- `category=lookalike` (the customer category)
- `tag=lookalike`
- `tag=<variant_family>` (one of: addition, homoglyph, omission, replacement, transposition, vowel-swap, etc.)
- `details.variant_domain`, `details.variant_family`, `details.dns_a_records`, `details.http_80_status`, `details.http_443_status`, `details.cert_seen_count`, `details.cert_first_seen`

**Customer-facing category:** Lookalike Domains

## Related features

- [site-mimic.md](site-mimic.md) — bundled with this feature. When Lookalike monitoring is enabled on an asset AND `MIMIC_ENABLED=true`, the Site Mimic Watch engine deep-checks live Lookalike hits for page-clone evidence
