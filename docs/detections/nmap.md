# Nmap Port Scanning

**Module:** `backend/app/scanner/engines/nmap_engine.py` + `backend/app/scanner/analyzers/port_risk.py`
**Detects:** Open TCP ports, running service versions, OS fingerprints. Findings come from the `port_risk` analyzer which classifies each open port by risk (e.g. exposed RDP/SMB/Redis = high; HTTP/HTTPS = info)
**Plan gate:** `use_nmap` profile flag. Deep scan profile enables it by default; Standard does not (Nmap is slow)
**Severity:** From the analyzer's per-port risk table — RDP/SMB/Telnet/FTP exposed = high; admin tool ports = medium; common web ports = info

## Required setup

None at deploy time — the `nmap` binary is baked into the backend Docker image:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends nmap dnsutils ...
```

The Python wrapper `python-nmap` (declared in `requirements.txt`) handles the subprocess invocation.

## Optional setup

- **`nmap_port_range`** in the scan profile — defaults to `1-1000`. Standard scans honour this; Deep scans use `1-65535`
- **`nmap_scan_type`** — defaults to `standard`. Other supported values are profile-specific

## How to verify

```bash
# Confirm nmap is in the image:
docker compose exec easm-backend which nmap
# Expected: /usr/bin/nmap

docker compose exec easm-backend nmap --version
# Expected: version banner

# Trigger a Deep-profile scan; watch engine activity:
docker compose logs easm-backend --tail=200 2>&1 | grep -i "NmapEngine"
```

## Operational notes

- Nmap is slow. A `1-65535` Deep scan can take several minutes per host. Quick / Standard profiles skip Nmap deliberately
- Some cloud providers (AWS, GCP) detect port scans and may temporarily rate-limit the source IP. Test against a host you own first
- The engine respects `path_timeout` for connect-port probes but the full scan budget is governed by the orchestrator's per-engine timeout
- Findings from Nmap feed downstream into the **DB Probe** engine for any database ports it identifies (see [db-probe.md](db-probe.md))

## Findings produced

| Template ID | Trigger | Severity |
|---|---|---|
| `port-rdp-exposed` | TCP 3389 open to the internet | high |
| `port-smb-exposed` | TCP 445 open | critical |
| `port-telnet-exposed` | TCP 23 open | high |
| `port-ftp-exposed` | TCP 21 open | medium |
| `port-redis-exposed` | TCP 6379 open + service confirmed | critical |
| `port-mongodb-exposed` | TCP 27017 open + service confirmed | critical |
| `port-mysql-exposed` | TCP 3306 open | high |
| `port-postgres-exposed` | TCP 5432 open | high |
| `port-elasticsearch-exposed` | TCP 9200 open + service confirmed | critical |
| `port-admin-panel-exposed` | TCP 8080/8443 with admin-tool fingerprint | medium |
| `port-info` | Generic open-port catalogue entry | info |

**Customer-facing category:** Service Exposure
