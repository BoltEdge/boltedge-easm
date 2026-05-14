# Shodan — Host Intelligence

**Module:** `backend/app/scanner/engines/shodan_engine.py`
**Detects:** Open ports, running services, banner information, OS fingerprints, historical exposure, and known CVEs associated with the asset's IP. Drives the bulk of the platform's vulnerability detection because Shodan's vuln dataset is what `cve_enricher` (and downstream KEV/EPSS enrichment) operates on
**Plan gate:** Runs on all paid tiers via the default Standard / Deep scan profiles. `use_shodan` profile flag controls per-scan
**Severity:** From CVSS score on each CVE (`>=9.0` → critical, `>=7.0` → high, `>=4.0` → medium, `>0` → low). Unknown CVSS defaults to high

## Required setup

```bash
SHODAN_API_KEY=<your shodan key>
```

A Shodan API key is required. Without it, the engine logs at INFO and returns empty data — every other engine still runs, but you get no host-intel and no CVE findings.

## Optional setup

None. Shodan's free tier works but is rate-limited; the Membership / Freelancer / Corporate tiers raise the query budget and unlock historical data (`shodan_include_history` profile flag).

## How to verify

```bash
# Confirm the env var reaches the container
docker compose exec easm-backend env | grep SHODAN_API_KEY

# Trigger a scan on a domain you own; look for engine activity
docker compose logs easm-backend --tail=200 2>&1 | grep -i "shodan"
# Expected: lines showing Shodan API calls and CVE counts

# Or call directly:
curl -s "https://api.shodan.io/api-info?key=$SHODAN_API_KEY" | python -m json.tool
# Expected: JSON showing your plan, query credits, scan credits
```

## Operational notes

- Shodan bills by query credits — every scan that hits the API consumes credits proportional to the host being scanned (IP lookups, history depth, DNS depth)
- Quick scan profile uses minimal Shodan depth; Deep scan profile uses `shodan_include_history` + `shodan_include_cves` + `shodan_include_dns`
- The engine **never blocks a scan on Shodan failure** — if the API is down or the key is rate-limited, you lose host-intel for that scan but other engines still run
- Shodan-driven CVE findings are enriched with KEV + EPSS data via `app/scanner/threat_intel.py` (see [kev-epss.md](kev-epss.md))
- Cost rationale in `CLAUDE.md` assumes Shodan Corporate at ~$0.001/credit — re-run the margin math in the file if you change tier

## Findings produced

| Template ID | Trigger | Severity |
|---|---|---|
| `cve-<id>` (dynamically generated) | A CVE reported by Shodan for the host | From CVSS |
| Various port / service templates via `port_risk` analyzer | Open ports Shodan returns | From port_risk severity table |

**Customer-facing category:** Vulnerabilities (for CVEs), Service Exposure (for open ports)
