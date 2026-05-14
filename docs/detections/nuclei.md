# Nuclei — CVE & Misconfiguration Templates

**Module:** `backend/app/scanner/engines/nuclei_engine.py` + `backend/app/scanner/analyzers/nuclei_analyzer.py`
**Detects:** Specific CVEs, default-credential checks, exposed admin endpoints, configuration-specific misconfigurations. Nuclei is a community-maintained template registry — thousands of probe templates across vulnerability families
**Plan gate:** `use_nuclei` profile flag. Deep scan profile enables it; Standard does not
**Severity:** From each Nuclei template's declared severity (`info`, `low`, `medium`, `high`, `critical`)

## Required setup

None at deploy time — the `nuclei` binary is baked into the backend Docker image, and the template registry is pre-populated:

```dockerfile
RUN curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip" ...
RUN nuclei -update-templates -silent || true
```

## Optional setup

- **`nuclei_severity_filter`** in the scan profile — comma-separated severity list (e.g. `critical,high`). Defaults to running all severities
- **`nuclei_templates`** in the scan profile — JSON list of specific template IDs or directories to limit which templates run. Defaults to running everything ProjectDiscovery ships
- **Template updates** — run `docker compose exec easm-backend nuclei -update-templates` periodically to pull new templates from the upstream registry. New templates appear within hours of a fresh CVE being disclosed

## How to verify

```bash
docker compose exec easm-backend which nuclei
# Expected: /usr/local/bin/nuclei

docker compose exec easm-backend nuclei -version
# Expected: version banner

# Template registry path:
docker compose exec easm-backend ls ~/.config/nuclei-templates/ | head -10
# Expected: cves/, default-logins/, exposures/, http/, etc.

# Trigger a Deep-profile scan and look for Nuclei engine activity:
docker compose logs easm-backend --tail=200 2>&1 | grep -i "NucleiEngine\|nuclei_analyzer"
```

## Operational notes

- Nuclei runtime is variable — anywhere from 30 seconds (filtered templates) to several minutes (full registry). Deep scan profile budgets ~5-10 minutes total
- Templates are deduplicated by template_id at the analyzer level so the same CVE template firing on two ports produces one finding, not two
- Findings produced by Nuclei pass through the CVE enricher (see [shodan.md](shodan.md) and [kev-epss.md](kev-epss.md)) so each CVE finding picks up KEV + EPSS context
- Updating templates can introduce new CVE coverage immediately — worth automating a weekly `nuclei -update-templates` in CI or via a scheduled job
- Some templates make outbound DNS / HTTP calls that look like attacks to the target; this is unavoidable for active vulnerability scanning

## Findings produced

Nuclei produces dynamic finding IDs based on the template that fired. Common ones land in the `cve-<cve_id>` family (handled by the CVE enricher pipeline). Examples:

| Template family | Examples |
|---|---|
| CVE templates | `cve-2021-44228` (Log4Shell), `cve-2023-4966` (Citrix Bleed), `cve-2024-23897` (Jenkins file read) |
| Default credentials | `default-login-jenkins`, `default-login-tomcat`, `default-login-grafana` |
| Exposed admin panels | `admin-panel-detect`, `airflow-default-login`, `kibana-admin-panel` |
| Configuration exposures | `actuator-env-exposed`, `springboot-heapdump`, `phpinfo-exposed` |
| Technology fingerprints | `apache-detect`, `nginx-version`, `wordpress-detect` |

**Customer-facing category:** Vulnerabilities (CVE templates), Misconfigurations (default-login + admin-panel templates)
