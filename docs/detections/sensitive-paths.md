# Sensitive Path Scanning

**Module:** `backend/app/tools/sensitive_paths.py` (invoked by `app/scanner/engines/leak_engine.py`)
**Detects:** Exposed configuration files, backups, version-control metadata, and other "shouldn't be public" paths on the customer's own assets — `/.git/HEAD`, `/.env`, `/backup.sql`, `/phpinfo.php`, `/wp-config.php.bak`, and ~30 more
**Plan gate:** `leak_detection` (Starter+) — required to enable the parent leak engine; sensitive-path probing runs whenever the leak engine runs
**Severity:** per-path, baked into the engine. `/.env` → critical; `/.git/HEAD` → high; `/.DS_Store` → low

## Required setup

None. The path list is curated in code and the probes run against the asset's own URL.

## Optional setup

None.

## How to verify

```bash
# Pick an asset that has the leak engine enabled (any paid plan tier on a Deep
# scan profile). Run a manual scan from the UI and watch the leak engine logs:
docker compose logs easm-backend --tail=200 2>&1 | grep -i "LeakEngine: checked"
# Expected: "LeakEngine: checked 30+ paths on <domain>, found <N> exposed"
```

## Operational notes

- Single HTTP GET per path with 5-second default timeout (configurable via `path_timeout` in the scan profile)
- ~30 path probes per scan; total runtime ~30-60 seconds on a healthy target
- Severity table inside the engine is the source of truth — the analyzer respects engine severity even when it differs from the template default
- "Recon paths" (`/robots.txt`, `/.well-known/security.txt`) are probed but the engine flags them severity=info and the analyzer drops them — present in the data for inventory, not as findings

## Findings produced

| Template ID | Trigger | Severity |
|---|---|---|
| `leak-git-exposed` | `/.git/HEAD`, `/.git/config` reachable | high |
| `leak-env-file` | `/.env`, `/.env.production`, etc. | critical |
| `leak-ssh-private-key` | `/id_rsa`, `/.ssh/id_rsa` | critical |
| `leak-sql-dump` | `/backup.sql`, `/dump.sql`, `/db.sql` | critical |
| `leak-wp-config-backup` | `/wp-config.php.bak`, `/wp-config.php~` | critical |
| `leak-htpasswd` | `/.htpasswd` reachable | high |
| `leak-phpinfo` | `/phpinfo.php` returns server info dump | medium |
| `leak-apache-status` | `/server-status`, `/server-info` reachable | medium |
| `leak-api-docs` | `/swagger.json`, `/openapi.json` | low |
| `leak-docker-compose` | `/docker-compose.yml` reachable | high |
| `leak-package-manifest` | `/package.json`, `/composer.json` reachable | low |
| `leak-ds-store` | `/.DS_Store` reachable | low |
| `leak-path` (fallback) | Any other path in the probe list | from engine |

**Customer-facing category:** Data Leaks
