# Health Checks — Operator Guide

This is the reference for the Nano EASM health-check system: what it
covers, how it's wired, and how to use the CLI and admin dashboard to
diagnose problems.

If you're on-call and something feels wrong, jump to
**[Quick triage](#quick-triage)**.

---

## What it covers

The health system answers six questions, every six hours, automatically:

| Question | What we check | Where it lives |
|---|---|---|
| Is the app process alive? | `GET /health` returns 200 | Public endpoint, hit by load balancers |
| Is the database reachable? | `SELECT 1` ping + connection-pool snapshot | Live on every `/admin/health` request |
| Are pending migrations applied? | `alembic_version` vs head revision | Live on every request |
| Are background workers running? | Each scheduler writes a heartbeat each cycle; we flag any one >2× overdue | Live on every request |
| Can each scan engine / analyzer / discovery module run? | Import + binary + API key + upstream ping per probe | Cached, refreshed every 6h |
| Are external APIs reachable, with quota? | Shodan credits, GitHub/GitLab token + rate-limit, Resend, Stripe, Anthropic | Cached, refreshed every 6h |

There are two surfaces:

1. **Admin dashboard** at `/admin/health` — for sit-and-watch. Auto-refreshes every 30s.
   Shows the latest probe results from the database; never blocks on a slow upstream.
2. **`flask health` CLI** — for ssh-and-debug. Same data, plus the ability to force a fresh probe run on demand.

---

## How it works

```
                                ┌──────────────────────────────────┐
                                │     health_check_result table    │
                                │  ┌────────────────────────────┐  │
                                │  │ kind | name | status | ... │  │
                                │  └────────────────────────────┘  │
                                │      one row per probe           │
                                └──────────────┬───────────────────┘
                                               │
        Writers                                │              Readers
        ─────────────────────                  │              ─────────────────────
        • Schedulers (heartbeats)              │              • GET /admin/health
        • Probe runner (every 6h)              │              • flask health *
        • POST /admin/health/probe             │              • flask health quick (system probes only)
                                               │
                                          UPSERT by
                                          (kind, name)
```

**Single row per `(kind, name)`.** Each probe has exactly one row that gets
overwritten on every run. The table stays at ~50 rows total — instant to query,
nothing to clean up. We don't store history here; if you want trend lines later,
add a sibling history table.

**`last_healthy_at`** advances only on healthy results, so the UI can compute
"down for N minutes" without a history table.

**Probes never raise.** Every probe is wrapped in a try/except that converts
exceptions into `down` status with the error message. One broken probe never
poisons the rest.

---

## Status values

| Status | Meaning |
|---|---|
| `healthy` | Probe ran cleanly, upstream/dependency reachable, no warnings. |
| `degraded` | Probe ran but with a soft issue: low Shodan credits, missing optional API token, scheduler ran but the cycle errored. The system still works. |
| `down` | Probe failed: import error, missing required dependency, upstream returning errors, scheduler heartbeat overdue. Something needs fixing. |
| `unknown` | Probe never ran (fresh deploy, table never populated) or probe couldn't determine state. |

The dashboard's overall pill rolls up to:
- **critical** if DB is unreachable OR migrations are drifting,
- **degraded** if any scheduler is down, any rollup is `down`, error rate >20%, or queue depth >50,
- **healthy** otherwise.

---

## CLI reference

All commands run inside the backend container:

```bash
docker compose exec easm-backend flask health <subcommand> [options]
```

Or, from inside the running backend container:

```bash
flask health <subcommand>
```

Every subcommand supports `-j` / `--json` for machine-readable output and
returns exit codes for scripting:

| Exit | Meaning |
|---|---|
| 0 | Healthy |
| 1 | Degraded |
| 2 | Down / critical / unknown |

### `flask health status`

The full report. This is what you run when you want to see everything.

```bash
flask health status
```

Output sections:
- **System** — DB ping, pool stats, migration drift.
- **Schedulers** — heartbeat status of `scan_schedule`, `monitor_scheduler`, `trial_expiry`, `health_probes`.
- **Engines** — last cached status of each scan engine.
- **Analyzers** — same, for analyzers.
- **Discovery** — same, for discovery modules.
- **External APIs** — Shodan / GitHub / GitLab / Resend / Stripe / Anthropic.

The Engines / Analyzers / Discovery / External APIs sections read from the
cache populated every 6h. If you've just rotated a key and want to verify
without waiting, use `--probe` on the per-section command (below) or call
`flask health probe`.

> Use this when: starting an investigation, checking after a deploy.

### `flask health quick`

Cheap checks only. Designed for cron and pre-deploy gates.

```bash
flask health quick
```

What it runs:
- DB `SELECT 1`.
- Migration drift (`alembic_version` vs head).
- Scheduler heartbeats (reads from cache; doesn't touch external services).

Completes in well under a second on a healthy system. **Never** calls Shodan,
GitHub, or any external API.

```bash
# Cron example: page if anything's broken
*/5 * * * * flask health quick -j > /tmp/health.json || /usr/local/bin/page-oncall
```

> Use this when: cron checks, pre-deploy verification, "is the platform up
> right now?" — anything where you need an answer in <1s.

### `flask health db`

DB ping + pool stats + migration drift only. Subset of `quick`.

```bash
flask health db
```

Useful when triaging a slow-app complaint — confirms whether the database is
the bottleneck, and whether the connection pool is exhausted.

What "exhausted" looks like:

```
healthy   postgres                 DB ping 4ms [4ms]
degraded  migrations               At head (n2d3e4f5)
```

If `postgres` shows `degraded` with a message like "DB pool using 3 overflow
connection(s)", the pool is undersized for current load. Increase
`SQLALCHEMY_ENGINE_OPTIONS.pool_size` in `app/extensions.py`.

If `migrations` is `down`, run `flask db upgrade` immediately — new code is
running against an old schema.

> Use this when: app feels slow, after a deploy that included a migration,
> investigating connection-pool warnings.

### `flask health schedulers`

Scheduler heartbeats only. Reads from the cache — never blocks.

```bash
flask health schedulers
```

What you'll see:

```
healthy   scan_schedule       every 1m   Idle cycle [1ms]   last heartbeat 47s ago
healthy   monitor_scheduler   every 1m   Processed 3 monitor(s) [2ms]   last heartbeat 31s ago
healthy   trial_expiry        every 1h   Trials: 0 expired, 0 free-upgrades expired [1ms]   last heartbeat 43m ago
healthy   health_probes       every 6h   62 probes (58 healthy, 3 degraded, 1 down) [3ms]   last heartbeat 4h ago
```

A scheduler is flagged `down` if its last heartbeat is older than **2× its
interval** (with a 2-minute floor). For `monitor_scheduler` (60s interval), that
means no heartbeat for 2 minutes.

If something's `down` here, the scheduler thread has either crashed or never
started. Check the backend logs for the relevant scheduler name.

> Use this when: scans/monitoring aren't firing, trial expiries aren't running,
> alerts aren't being sent.

### `flask health engines`

Cached status of every scan engine: shodan, ssl, http, dns, nmap, nuclei,
db_probe, cloud_asset, leak.

```bash
flask health engines
```

This reads the last cached probe result. Add `--probe` to refresh first:

```bash
flask health engines --probe
```

A real run takes 5-15 seconds (it pings Shodan, runs `nmap --version`,
runs `nuclei -version`, etc.) — so the dashboard / cached lookup uses
the 6-hourly snapshot. Use `--probe` when:
- You just rotated `SHODAN_API_KEY` and want to confirm.
- You just installed `nuclei` and want to verify it's on PATH.
- You're investigating a "scans always fail for engine X" complaint.

What each engine probe checks:

| Engine | Probe |
|---|---|
| `shodan` | `SHODAN_API_KEY` present + `api.info()` succeeds + credits ≥ 50 |
| `ssl` | stdlib `ssl` importable + engine class importable |
| `http` | `requests` importable + engine class importable |
| `dns` | `dnspython` importable + resolves `cloudflare.com` A record |
| `nmap` | `python-nmap` importable + `nmap` binary on PATH + `nmap --version` works |
| `nuclei` | `nuclei` binary on PATH + `nuclei -version` works |
| `db_probe` | Engine class importable |
| `cloud_asset` | Engine class importable |
| `leak` | Engine importable + reports degraded if either GITHUB_TOKEN or GITLAB_TOKEN is missing |

> Use this when: scans are returning empty results from a specific source,
> after rotating an API key, after installing a new binary on the host.

### `flask health analyzers`

Cached status of every analyzer: port_risk, cve_enricher, ssl_analyzer,
header_analyzer, dns_analyzer, tech_detector, nuclei_analyzer, api_analyzer,
exposed_db_analyzer, cloud_asset_analyzer, subdomain_takeover, leak_analyzer,
exposure_scorer.

```bash
flask health analyzers
flask health analyzers --probe
```

Analyzers don't touch anything external — they consume engine output and emit
findings. The probe is just an import + instantiate test. Anything `down` here
means the codebase has a broken module (syntax error after refactor, missing
optional dep, circular import).

> Use this when: a specific analyzer's findings stop appearing in scan results,
> after a refactor of `app/scanner/analyzers/`.

### `flask health discovery`

Cached status of every discovery module: ct_logs, dns_enum, rapiddns,
whois_asn, hackertarget, alienvault_otx, web_archive, asn_org, cidr_enum,
shodan_search, threatcrowd, cloud_enum.

```bash
flask health discovery
flask health discovery --probe
```

Probes call each module's `is_available()` self-check. A module gated on an
env var (e.g. `shodan_search` needs `SHODAN_API_KEY`) reports `degraded` when
that var is missing — degraded, not down, because the discovery system as a
whole still works without it.

> Use this when: discovery jobs return fewer assets than expected, after
> rotating a key for an API-backed discovery source.

### `flask health external`

Cached status of external APIs: shodan, github, gitlab, resend, stripe,
anthropic.

```bash
flask health external
flask health external --probe
```

What each probe does:

| API | Probe |
|---|---|
| `shodan` | `api.info()` — returns plan + credits in one call |
| `github` | `GET /rate_limit` with token — validates token, doesn't consume rate |
| `gitlab` | `GET /api/v4/user` with token — validates token |
| `resend` | `GET /domains` with key — validates key + lists configured domains |
| `stripe` | `Account.retrieve()` — only when `ENABLE_BILLING=true`, otherwise reports healthy with "skipped" |
| `anthropic` | `GET /v1/models` — only if `ANTHROPIC_API_KEY` is set |

A missing API key reports `degraded` (the service isn't enabled, but the
platform isn't broken). A 401 from a configured key reports `down` (key was
revoked or rotated and the env var didn't update — investigate).

The `shodan` probe specifically watches credit balance and reports `degraded`
when remaining credits drop below 50. This is the early-warning signal for the
cost lever called out in CLAUDE.md.

> Use this when: emails aren't sending (resend), Stripe webhooks aren't firing
> (stripe), leak detection finds nothing (github/gitlab), AI assistant errors
> (anthropic), Shodan-backed discovery returns nothing (shodan).

### `flask health probe`

Manually trigger a probe run. This is what the 6-hourly scheduler executes.

```bash
flask health probe                              # Run all probe kinds
flask health probe --kinds=engine,external_api  # Run specific kinds
flask health probe -j                           # JSON output
```

Valid kinds: `engine`, `analyzer`, `discovery`, `external_api`. (System probes
are read live; schedulers heartbeat themselves — neither is part of the runner.)

Output is a summary, not the per-probe detail (use `flask health <kind>`
afterward to see results):

```
Probed: engine, analyzer, discovery, external_api
  healthy: 28
  degraded: 3
  down: 1
  unknown: 0
  total: 32
  elapsedMs: 4127
```

> Use this when: you want fresh data and don't want to wait for the next
> 6h cycle. Equivalent to clicking "Probe now" on the admin dashboard.

---

## Operations playbook

### "The dashboard says critical"

Critical = DB unreachable OR migration drift. Start here:

1. `flask health db` — confirms which one.
2. If DB unreachable: check Postgres is running, check `SQLALCHEMY_DATABASE_URI`, check network from backend container.
3. If migration drift: `flask db current` to see DB state, `flask db upgrade` to apply pending migrations.

### "Scans aren't firing"

```bash
flask health schedulers
```

If `scan_schedule` is `down`, the scheduler thread has crashed. Restart the
backend. If it stays `down` after restart, check logs around app boot —
`init_scheduler` may be failing.

If `scan_schedule` is `healthy` but scans still aren't firing, the issue isn't
scheduling — check `flask health engines --probe` to see if the engines
themselves are broken.

### "A specific engine returns empty results"

```bash
flask health engines --probe
```

Look for the affected engine. Common causes by status:

- **`down`, message "binary not on PATH"** — install the binary on the host
  (`nmap`, `nuclei`).
- **`down`, message "API error" or "401"** — key was revoked or rotated.
  Update the env var, restart the backend, re-probe.
- **`degraded`, message "low credits"** — top up Shodan or wait for monthly
  reset.
- **`healthy` but scans still empty** — the engine works at the API level
  but isn't finding anything for that target. Not a health issue.

### "Emails aren't sending"

```bash
flask health external --probe
```

Look at `resend`:
- **`degraded`, "RESEND_API_KEY not set"** — set the env var.
- **`down`, "401"** — key revoked. Generate a new one in Resend dashboard.
- **`degraded`, "No verified domains"** — domain wasn't added to Resend, or
  DNS isn't propagated. See `docs/domain-migration.md`.

### "Trial expiries aren't running"

```bash
flask health schedulers
```

Check `trial_expiry`. It heartbeats hourly, so anything older than ~2h is
suspicious. If it's `down`, restart the backend; if it's `degraded`, check
logs for the most recent cycle's exception.

### "I rotated an API key, when will it show up?"

The 6h scheduler picks it up automatically. To see it immediately:

```bash
# From the backend container:
flask health external --probe

# Or from a browser as superadmin:
# Click "Probe now" on /admin/health
```

### "I want to monitor health from outside the platform"

The public `GET /health` endpoint returns 200 if the process is up. Hit it
from your uptime monitor (UptimeRobot, BetterStack, Pingdom).

For deeper monitoring, hit `GET /admin/health` with a superadmin session
token and parse the JSON. The overall `status` field is what to alert on.

---

## Quick triage

You're on-call, something's wrong, you don't know what:

```bash
# One-liner — gives you the verdict in <2s.
flask health quick && echo OK || echo NOT OK

# More detail.
flask health quick

# If quick is healthy but problem persists — check the cached probes.
flask health status

# If a specific kind looks stale or wrong, force-probe it.
flask health engines --probe
flask health external --probe
```

Exit codes mean you can pipe into anything that respects them:

```bash
flask health quick -j | tee /tmp/health.json
if [ $? -ge 2 ]; then
  notify-team "Platform health: critical"
fi
```

---

## Architecture: where the code lives

```
backend/app/health/
├── __init__.py              — public exports
├── framework.py             — HealthStatus enum, HealthResult, record(), fetch_*()
├── runner.py                — orchestrates probe kinds; called by 6h scheduler & CLI --probe
├── heartbeat.py             — schedulers call heartbeat() at end of each cycle
├── cli.py                   — `flask health` subcommand registrations
└── probes/
    ├── system_probe.py      — DB ping, pool, migration drift, scheduler liveness (read live)
    ├── engine_probe.py      — 9 scan engines (cached every 6h)
    ├── analyzer_probe.py    — 13 analyzers (cached every 6h)
    ├── discovery_probe.py   — 12 discovery modules (cached every 6h)
    └── external_api_probe.py — 6 external APIs (cached every 6h)

backend/app/admin/routes.py
└── GET /admin/health         — extended with probe rollups
└── POST /admin/health/probe  — manual trigger ("Probe now" button)

frontend/app/(admin)/admin/health/page.tsx
└── Cards: Migrations, Schedulers, Scan Engines, Analyzers, Discovery, External APIs
```

Migration: `n2d3e4f5a6b7_health_check_result.py` adds the
`health_check_result` table.

---

## Frequencies summary

| Check | Where | Cadence |
|---|---|---|
| `GET /health` (liveness) | Public | On demand (load balancer hits it) |
| DB ping + pool | `/admin/health` + `flask health db` | Every request |
| Migration drift | `/admin/health` + `flask health db` | Every request |
| Scheduler heartbeats | `/admin/health` + `flask health schedulers` | Read every request; written each scheduler cycle (60s / 1h / 6h) |
| Engine probes | Cached in `health_check_result` | Refreshed every 6h, or on demand via `--probe` / "Probe now" |
| Analyzer probes | Cached | Same |
| Discovery probes | Cached | Same |
| External API probes | Cached | Same |
| Public `/health` external uptime | UptimeRobot etc. | Every 30s — recommended external monitor |

The **6-hour cadence** for engine/analyzer/discovery/external probes is the
trade-off: long enough that we don't burn API quota or hammer rate limits,
short enough that "the key got revoked at 09:00" is detected before end-of-day.
The first probe run fires 30s after backend boot, so a fresh deploy populates
the dashboard immediately.
