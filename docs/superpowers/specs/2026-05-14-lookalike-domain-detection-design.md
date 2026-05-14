# Lookalike Domain Detection — Design Spec

**Date:** 2026-05-14
**Status:** Approved, ready for implementation plan
**Author:** Nano EASM team

## Goal

Detect typosquats, homoglyph attacks, TLD swaps, IDN/punycode confusables, and other lookalike domains for a customer's root domains. Surface hits as Findings on the parent asset so customers can triage with the existing workflow (suppress, resolve, accept-risk).

Closes one of the visibility gaps versus Cyberint and similar External Risk Management vendors at zero paid-feed cost.

## Scope

### In scope
- Per-asset opt-in: customer toggles "watch for lookalikes" on selected root domains
- Plan-tiered cap on watched domains (Free=0, Starter=1, Pro=3, Silver=10, Gold=25, Custom=∞)
- Comprehensive variant generation (all 16 DNSTwist families)
- Verification via DNS A-record lookup, HTTP HEAD on 80/443, and CT log search via crt.sh
- Findings persisted on the parent asset with `category="lookalike"` and severity derived from signal mix
- Weekly background scheduler that creates scan jobs for stale watched assets
- On-demand manual trigger from the asset detail page
- Engine self-rate-limits to 6 days to avoid duplicate fresh lookups when a customer manually scans repeatedly

### Explicitly out of scope (follow-up specs)
- Screenshot / visual-similarity matching against the parent domain's homepage
- WHOIS lookups (rate-limited and inconsistent across TLDs — defer)
- Takedown automation or abuse-complaint filing
- Brand-impersonation beyond domain variants (fake LinkedIn pages, mobile apps, paste-site mentions)
- Daily or hourly cadence options
- Bulk import/export of the watch list
- Custom variant generators (customer-defined regex patterns)
- Severity bumping by variant age — very-new domains are more suspicious; defer

### Explicit behaviour decisions
- **Surface is Findings, not a new top-level page.** Detected lookalikes become regular `Finding` rows on the parent root-domain asset, with `category="lookalike"`. No new top-level nav item.
- **One toggle, one cap.** "Lookalike monitoring" is a per-asset boolean, not a separate watch-list table. The plan cap counts watched assets, full stop. The first-watched-asset is implicitly the "primary" — no special is_primary flag.
- **Engine self-rate-limits at 6 days.** Customers can spam the manual trigger without burning external lookups. Scheduler runs once a week per watched domain; the 6-day window is intentionally shorter so the weekly job always proceeds.
- **Unregistered candidates are NOT findings.** A variant with no DNS, no HTTP, and no cert is dropped. Surfacing 400 unregistered variants per scan would drown the findings list.
- **Failures are silent.** crt.sh outage, slow DNS, blocked HTTP — none of these break the scan. Engine produces whatever it can and logs the rest.

## Architecture

Embeds in the existing scanner orchestrator as a new engine + analyzer pair, plus a new system profile that enables only this engine. A dedicated weekly scheduler entry creates scan jobs using that profile against watched assets. No coupling to the customer's regular scan cadence.

```
Weekly 03:00 UTC (APScheduler)
  ↓
For each Asset where lookalike_watch=true AND (last_lookalike_scan_at IS NULL
   OR last_lookalike_scan_at < now - 6 days):
   create ScanJob(asset_id, profile=Lookalike Scan, initiator="lookalike_schedule")
  ↓
Existing scheduled-scan worker picks up the queued job
  ↓
Scanner orchestrator runs with Lookalike Scan profile
  ↓
LookalikeEngine.execute():
  1. Short-circuit if asset.lookalike_watch=False OR last_lookalike_scan_at < 6 days
  2. dnstwist.DomainFuzz(asset.value).generate() → ~500 candidates
  3. For each candidate, concurrent ThreadPool (max 20):
     - dns.resolver A-record lookup
     - requests HEAD on http:// and https://
     - GET https://crt.sh/?q=<variant>&output=json
  4. Build verified_hits list (any positive signal → included)
  5. Update asset.last_lookalike_scan_at = now
  ↓
LookalikeAnalyzer.analyze(ctx):
  For each verified_hit → FindingDraft (severity from heuristic, category="lookalike")
  ↓
Orchestrator persists drafts as Finding rows on the parent asset
```

### Why scanner-orchestrator-embedded (over standalone module)

- Reuses the orchestrator's draft → Finding pipeline, dedup logic, audit logging, and result_json persistence
- Reuses the scheduled-scan worker for job execution
- Reuses the manual "Scan now" flow for on-demand triggers (just pick the Lookalike Scan profile)
- Cadence is decoupled via a dedicated weekly scheduler entry, so it doesn't ride on the customer's vulnerability scan cadence

## Components

### 1. `backend/app/scanner/engines/lookalike_engine.py` *(new)*

Inherits `BaseEngine`. Public surface:

```python
class LookalikeEngine(BaseEngine):
    name = "lookalike"
    supported_asset_types = ["domain"]

    def execute(self, ctx: ScanContext, config: Dict) -> EngineResult:
        # Reads ctx.asset via DB lookup since orchestrator passes asset_id.
        # Short-circuit guards:
        #   1. asset.lookalike_watch must be True → otherwise return empty
        #   2. last_lookalike_scan_at within 6 days → return empty with
        #      rate_limited=True; existing Finding rows from the previous
        #      run persist untouched (orchestrator never deletes findings).
        # Otherwise: generate variants, verify, persist last_lookalike_scan_at
```

Output `result.data` shape:
```python
{
    "candidate_count": int,
    "verified_hits": [
        {
            "variant_domain": str,
            "variant_family": str,         # "homoglyph", "omission", "tld-swap", ...
            "dns_a_records": list[str],    # may be empty
            "http_80_status": int | None,  # may be None
            "http_443_status": int | None,
            "cert_seen_count": int,        # 0+
            "cert_first_seen": str | None, # ISO date of earliest cert
        },
        ...
    ],
    "rate_limited": bool,                  # True if served from cached run
}
```

Concurrency: `ThreadPoolExecutor(max_workers=20)`. Per-check timeouts: DNS 3s, HTTP 5s, crt.sh 5s.

### 2. `backend/app/scanner/analyzers/lookalike_analyzer.py` *(new)*

Inherits `BaseAnalyzer`. `required_engines = ["lookalike"]`. Reads `verified_hits` from engine output, produces one `FindingDraft` per hit.

Severity heuristic:

| Signal mix | Severity |
|---|---|
| HTTP 2xx/3xx response + cert seen in last 90 days | high |
| DNS resolves + cert seen | medium |
| DNS resolves, no HTTP and no cert | low |
| Cert seen but no DNS resolution | low |
| No DNS, no HTTP, no cert | (not emitted) |

FindingDraft shape:

```python
FindingDraft(
    template_id=f"lookalike-{variant_domain}",
    title=f"Lookalike domain: {variant_domain}",
    severity=<heuristic>,
    category="lookalike",
    description=(
        f"{variant_domain} resembles {parent_domain} via the {family} variant family. "
        f"Currently {state_summary}."
    ),
    remediation=(
        "1. Look up the WHOIS / registrant for this domain to assess authorisation. "
        "2. If unauthorised, file a domain-abuse complaint with the registrar. "
        "3. Consider a UDRP / trademark complaint if the variant is being used commercially. "
        "4. Add a Google Safe Browsing or PhishTank report if there's active phishing content."
    ),
    finding_type="lookalike",
    references=[
        f"https://crt.sh/?q={variant_domain}",
        f"https://www.whois.com/whois/{variant_domain}",
    ],
    tags=["lookalike", family, severity, variant_domain.lower()],
    engine="lookalike",
    confidence="high" if dns_resolves else "medium",
    details={
        "variant_domain": variant_domain,
        "parent_domain": parent_domain,
        "variant_family": family,
        "dns_a_records": [...],
        "http_80_status": ..., "http_443_status": ...,
        "cert_seen_count": ..., "cert_first_seen": ...,
    },
    dedupe_fields={"variant_domain": variant_domain},
)
```

Dedupe scope is `(parent asset_id, template_id="lookalike-<variant>")` — same variant across repeat scans updates the existing Finding rather than creating duplicates.

### 3. `Asset` model — two new columns

```python
lookalike_watch = db.Column(db.Boolean, nullable=False, default=False, index=True)
last_lookalike_scan_at = db.Column(db.DateTime, nullable=True)
```

### 4. `ScanProfile` model — one new column

```python
use_lookalike = db.Column(db.Boolean, nullable=False, default=False)
```

Existing profiles default to `False` so their behaviour is unchanged.

### 5. Migration *(new)*

Adds the three columns above and seeds a new system profile row:

```python
ScanProfile(
    name="Lookalike Scan",
    description="Detects typosquats, homoglyph variants, TLD swaps, and IDN confusables for watched root domains.",
    is_system=True,
    is_default=False,
    is_active=True,
    use_shodan=False, use_nmap=False, use_nuclei=False, use_sslyze=False,
    use_lookalike=True,
)
```

### 6. `PLAN_CONFIG` — new key `lookalike_watch_domains`

| Plan | Cap |
|---|---|
| Free | 0 |
| Starter | 1 |
| Professional | 3 |
| Enterprise Silver | 10 |
| Enterprise Gold | 25 |
| Custom | -1 (unlimited) |

Enforced via the existing `check_limit("lookalike_watch_domains")` decorator on the toggle-on endpoint.

### 7. Scheduler entry — `backend/app/scheduler.py`

New APScheduler job, daily at 03:00 UTC:

```python
def _run_lookalike_schedule(app):
    with app.app_context():
        cutoff = datetime.now(timezone.utc) - timedelta(days=6)
        watched = Asset.query.filter(
            Asset.lookalike_watch.is_(True),
            db.or_(
                Asset.last_lookalike_scan_at.is_(None),
                Asset.last_lookalike_scan_at < cutoff,
            ),
        ).all()
        profile = ScanProfile.query.filter_by(name="Lookalike Scan", is_system=True).first()
        if not profile:
            logger.warning("Lookalike Scan profile missing; skipping cycle")
            return
        for asset in watched:
            ScanJob(
                asset_id=asset.id,
                status="queued",
                profile_id=profile.id,
                initiator="lookalike_schedule",
            )
            db.session.add(...)
        db.session.commit()
```

Daily check, weekly effective cadence (because of the 6-day staleness threshold). Self-throttling — if a customer manually triggered yesterday, the scheduler skips that asset today.

### 8. Routes — `backend/app/assets/routes.py` (extend)

| Method | Path | Auth | Effect |
|---|---|---|---|
| POST | `/assets/<id>/lookalike-watch` | analyst+ | `check_limit` first; sets `lookalike_watch=True` |
| DELETE | `/assets/<id>/lookalike-watch` | analyst+ | sets `lookalike_watch=False`; preserves `last_lookalike_scan_at` |
| POST | `/assets/<id>/lookalike-scan` | analyst+ | creates a scan job with the Lookalike Scan profile; bypasses 6-day rate-limit by clearing `last_lookalike_scan_at` first |

The existing asset GET endpoint returns `lookalikeWatch` and `lastLookalikeScanAt` so the UI toggle reflects state.

### 9. Frontend — asset detail page

One new toggle row in the asset settings panel:

```
Lookalike monitoring             [ ON / OFF ]
Currently using 2 of 3 watched domains (Professional plan)
[Run scan now]  (visible only when ON)
```

When the customer hits the plan cap, the toggle attempt returns a 402-ish error rendered inline as "You're using N of N watched domains. Upgrade or remove a watched domain to enable monitoring here."

No new filter chips on the findings list — `category="lookalike"` flows through existing `customer_category` filter logic. (Polish item for later: add "lookalike" to the customer-category mapping so it gets its own pill colour.)

## Dependencies

- `dnstwist` (new) — MIT-licensed Python package, pinned to a tested version. Used for variant generation only; we don't use its built-in resolver because we want control over concurrency, timeouts, and our own observability.
- `dnspython` (already present) — DNS A-record lookups.
- `requests` (already present) — HTTP HEAD and crt.sh GET.

No new external API keys or paid feeds.

## Error handling

| Failure mode | Behaviour |
|---|---|
| `dnstwist` raises (malformed input) | Engine logs and returns empty `verified_hits`. Scan completes with no findings. |
| DNS lookup times out | Single-candidate skip. Other checks for the same candidate proceed. |
| HTTP fetch errors (TLS, refused, timeout) | Candidate keeps its other signals; HTTP status set to None. |
| crt.sh returns 5xx / non-JSON | Cert signals null for that candidate; other signals stand. |
| Asset toggle hits plan cap | 402-ish response with `{"error": "limit_reached", "limit": "lookalike_watch_domains", "current": N, "max": N}` |
| Asset lookup misses in worker | Job marked failed via the existing scan-job error path. |
| Lookalike Scan system profile missing | Scheduler logs and skips the cycle. Migration is responsible for seeding. |

The product invariant: **a customer's other scans are never affected by lookalike failures.** The engine + analyzer fail closed, just like every other scanner component.

## Test plan

### Unit
- `LookalikeEngine` short-circuits when `asset.lookalike_watch=False`
- `LookalikeEngine` short-circuits and returns cached verified_hits when `last_lookalike_scan_at` is within 6 days
- `LookalikeEngine.execute()` calls `dnstwist.DomainFuzz` with the parent domain
- `LookalikeEngine` aggregates DNS / HTTP / crt.sh signals per candidate correctly (mock all three)
- `LookalikeEngine` drops candidates with no positive signal
- `LookalikeAnalyzer` severity heuristic — one test per signal combination
- `LookalikeAnalyzer` dedupe key stable for the same variant across repeat scans
- `check_limit("lookalike_watch_domains")` returns 402 at the cap
- `_run_lookalike_schedule` picks up stale watched assets only

### Integration
- Fixture an Asset with `lookalike_watch=True`, mock the three external calls; run a scan job with the Lookalike Scan profile; assert Findings exist on the parent asset with category="lookalike" and expected severities.
- Re-run the same scan; assert no duplicate Finding rows (dedupe).
- Toggle off `lookalike_watch`; run again; assert no new findings created.

### Manual
- Toggle a real root domain to watched in the UI, click "Run scan now", confirm findings appear within 5-10 min.

## Rollout

1. Migration: add three columns, seed Lookalike Scan system profile, add `lookalike_watch_domains` to `PLAN_CONFIG`
2. Deploy backend + frontend
3. No backfill — customers opt domains into the watch list when ready
4. First scheduled run lands within 24h; manual trigger available immediately

Rollback is straight `git revert`. The new columns and system profile can be left in place (nullable defaults, no data loss).

## Open questions

None — all major decisions were resolved during brainstorming.

## References

- DNSTwist: https://github.com/elceef/dnstwist
- crt.sh CT log search: https://crt.sh/
- Existing engine pattern: `backend/app/scanner/engines/shodan_engine.py`
- Existing analyzer pattern: `backend/app/scanner/analyzers/cve_enricher.py`
- Plan limit decorator pattern: `backend/app/auth/permissions.py`
