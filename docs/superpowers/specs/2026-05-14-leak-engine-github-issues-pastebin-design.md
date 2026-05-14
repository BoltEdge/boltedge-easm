# LeakEngine Expansion — GitHub Issues/PRs/Commits + Pastebin

**Date:** 2026-05-14
**Status:** Approved, ready for implementation plan
**Author:** Nano EASM team

## Goal

Expand the existing `LeakEngine` to surface secrets, credentials, and brand mentions across two additional sources:

1. **GitHub Issues / Pull Requests / commit messages** — same auth as today's GitHub code search; catches secrets that get pasted into bug reports, PR descriptions, or release notes
2. **Pastebin** — public pastes hosted on pastebin.com, where dumped credentials and credential lists are routinely shared

Closes the leak-coverage half of the Cyberint gap with no new customer-facing UI surface and no per-customer configuration.

This is **one of four sub-projects** in the broader leak-engine expansion. The remaining three (self-hosted GitLab, Bitbucket, Telegram channels) get their own specs and ship later.

## Scope

### In scope
- New `LeakEngine` collector method for GitHub Issues + Pull Requests via `GET /search/issues`
- New `LeakEngine` collector method for GitHub commit messages via `GET /search/commits`
- New `LeakEngine` collector method for Pastebin paste matches via SQL query against a new `paste_cache` table
- New `paste_cache` table (model + migration)
- New `app/services/pastebin_client.py` module — fetcher + body retrieval + upsert
- Two new APScheduler jobs: 60-second background fetcher, 60-minute cleanup
- Three new env vars: `PASTEBIN_FETCHER_ENABLED`, `PASTEBIN_FETCH_LIMIT`, plus the customer-side `GITHUB_TOKEN` (already exists)
- Health heartbeat on both Pastebin jobs
- Reuse of the existing `LeakAnalyzer` to convert matches into findings — same severity heuristic, same finding template shape

### Explicitly out of scope (separate specs)
- GitHub commit-content / history scanning (TruffleHog-style cloning)
- GitHub wikis (each wiki is its own clone-only git repo)
- GitHub Discussions (GraphQL-only API, separate auth dance)
- Bitbucket (no public code search exists)
- Self-hosted GitLab (sub-project #2)
- Telegram channels (sub-project #4)
- Full-text search index on `paste_cache` (ILIKE is fine at current scale; add tsvector later if needed)
- Customer-configurable keywords beyond the asset's root domain
- Real-time alerts when a new leak appears (rides existing finding-recurrence alert flow)

### Explicit behaviour decisions
- **No new profile column.** Existing `ScanProfile.use_leak` continues to gate the whole engine. When true and `GITHUB_TOKEN` is set, all three GitHub search modes run; when true and `PASTEBIN_FETCHER_ENABLED` is true, the paste cache is queried.
- **No customer-side Pastebin opt-in.** The fetcher is operator-controlled via env var. The `paste_cache` is shared across the whole platform; matches are filtered per-customer at scan time.
- **Pastebin auth is by IP whitelist, not by token.** Operator creates a Pastebin PRO account (one-off $30), whitelists the EC2 box's public IP via the Pastebin UI, sets `PASTEBIN_FETCHER_ENABLED=true`, restarts. No secret stored in env.
- **All new collectors fail closed.** Missing token, missing env var, network error, JSON parse error — the engine continues with whatever collectors did succeed. A scan never fails because Pastebin or GitHub Issues search was unavailable.
- **Findings dedupe per-source.** Each new collector uses its own `template_id` and `dedupe_fields` so the same paste / issue / commit detected across repeat scans updates the existing Finding rather than duplicating.

## Architecture

```
On-demand path (existing scan flow):
  Scanner orchestrator picks LeakEngine when profile.use_leak=true
       │
       ▼
  LeakEngine.execute()
       │
       ├─ existing: sensitive-path probe
       ├─ existing: _github_code_search       (GitHub /search/code)
       ├─ existing: _gitlab_search            (GitLab /search/blobs)
       ├─ NEW:      _search_github_issues_and_prs   (GitHub /search/issues)
       ├─ NEW:      _search_github_commit_messages  (GitHub /search/commits)
       └─ NEW:      _match_pastebin                  (SQL on paste_cache)
       │
       ▼
  Engine returns data = { sensitive_paths, github: {code, issues_prs, commits},
                          gitlab, pastebin }
       │
       ▼
  LeakAnalyzer reads engine data, produces FindingDrafts


Background ingestion path (continuous, independent of any scan):
  APScheduler every 60s
       │
       ▼
  _run_pastebin_fetcher(app)
       │
       ▼
  pastebin_client.fetch_recent_pastes_and_upsert()
       │
       ├─ GET /api_scraping.php?limit=250
       ├─ For each new paste_key: GET /api_scrape_item.php?i=<key>
       └─ Upsert into paste_cache (body truncated to 64 KB, TTL 7d)

  APScheduler every 60 min
       │
       ▼
  _run_pastebin_cleanup(app)
       │
       └─ DELETE FROM paste_cache WHERE expires_at < NOW()
```

### Why on-demand for GitHub search but background for Pastebin

GitHub's search API supports keyword queries — we can ask "any issue mentioning `nanoeasm.com`?" at scan time. Cheap and on-demand.

Pastebin's scraping API has **no keyword search**. It only returns the most recent 250 public pastes, rate-limited to one request per minute. The only way to detect a paste that mentions a customer domain is to ingest every public paste into our own searchable store and query it. Hence the background fetcher + cache pattern, modelled after the KEV-feed refresh we already ship.

## Components

### 1. `LeakEngine` extensions — `backend/app/scanner/engines/leak_engine.py`

Three new private methods, each returning a uniform dict shape so the analyzer doesn't need to special-case:

```python
def _search_github_issues_and_prs(
    self, domain: str, token: str, max_searches: int,
) -> Dict[str, Any]:
    """Search /search/issues for the domain. Returns:
        { "matches": [{ "url": str, "title": str, "type": "issue"|"pr",
                        "snippet": str, "repo": str }],
          "searches_run": int, "rate_limited": bool, "error": str|None }
    """

def _search_github_commit_messages(
    self, domain: str, token: str, max_searches: int,
) -> Dict[str, Any]:
    """Search /search/commits for the domain. Note this endpoint requires
    the special Accept header `application/vnd.github.cloak-preview+json`
    on older API versions; current API supports it natively.
    Returns same shape as above, with "commit_sha" + "repo" in each match."""

def _match_pastebin(
    self, domain: str, max_matches: int = 50,
) -> Dict[str, Any]:
    """Query paste_cache for any paste whose body contains the domain.
    SQL: SELECT paste_key, paste_url, title, body, date_pasted
         FROM paste_cache
         WHERE body ILIKE %{domain}%
         ORDER BY date_pasted DESC LIMIT max_matches.
    Returns: { "matches": [{ "url": paste_url, "key": paste_key,
                             "title": str, "snippet": str (first 300 chars
                             around the match), "date_pasted": iso }],
               "ingestion_active": bool }
    """
```

All three honour the same `GITHUB_TOKEN`/`PASTEBIN_FETCHER_ENABLED` env-var guards as their existing siblings and degrade gracefully when not configured.

The `execute()` method gains three new try/except blocks invoking these collectors and merging their output into `data`. Engine config gains `max_github_issue_searches` (default 8), `max_github_commit_searches` (default 6), `max_pastebin_matches` (default 50).

### 2. `paste_cache` model — `backend/app/models.py`

```python
class PasteCache(db.Model):
    """Rolling 7-day cache of public Pastebin pastes for leak matching."""
    __tablename__ = "paste_cache"

    paste_key   = db.Column(db.String(20), primary_key=True)
    paste_url   = db.Column(db.String(255), nullable=False)
    title       = db.Column(db.String(255), nullable=True)
    author      = db.Column(db.String(100), nullable=True)
    syntax      = db.Column(db.String(40), nullable=True)
    size_bytes  = db.Column(db.Integer, nullable=True)
    body        = db.Column(db.Text, nullable=False)
    date_pasted = db.Column(db.DateTime, nullable=False)
    fetched_at  = db.Column(db.DateTime, nullable=False, default=now_utc)
    expires_at  = db.Column(db.DateTime, nullable=False, index=True)
```

### 3. Migration

Adds `paste_cache` with indexes on `expires_at` and `fetched_at`. No changes to any other table.

### 4. `app/services/pastebin_client.py` (new module)

Public surface:
```python
PASTEBIN_SCRAPE_URL = "https://scrape.pastebin.com/api_scraping.php"
PASTEBIN_BODY_URL   = "https://scrape.pastebin.com/api_scrape_item.php"
MAX_BODY_BYTES = 65536
PASTE_TTL_DAYS = 7
FETCH_TIMEOUT = 10

def fetch_recent_pastes_and_upsert() -> int:
    """Pull the recent-pastes list, fetch body for each new key, upsert.
    Returns the count of NEW pastes ingested. Never raises."""
```

Detection of the "IP not whitelisted" response: Pastebin returns a `text/plain` body starting with `YOUR IP: X.X.X.X DOES NOT HAVE ACCESS` (not JSON). The client detects this string and logs at WARNING level, returning 0. Operator must whitelist the IP in their Pastebin PRO settings.

### 5. Scheduler entries — `backend/app/scheduler.py`

```python
def _run_pastebin_fetcher(app):
    """60-second APScheduler job. Skips silently when PASTEBIN_FETCHER_ENABLED
    is not set. Heartbeats success/failure via app.health.heartbeat."""

def _run_pastebin_cleanup(app):
    """Hourly APScheduler job. Deletes paste_cache rows where expires_at
    is in the past."""
```

Both registered inside `init_scheduler(app)` with `replace_existing=True` and `max_instances=1`. CronTrigger every 60s and IntervalTrigger every 3600s respectively. Both heartbeat through the existing `app.health.heartbeat` so operators see them on `/admin/health`.

### 6. Analyzer — `backend/app/scanner/analyzers/leak_analyzer.py`

Three new `FindingDraft` builders for the new sources. Same severity heuristic as existing code-search findings (credential pattern → critical, token pattern → high, email/username → medium, mention only → low). Template IDs:

| Source | template_id | dedupe_fields |
|---|---|---|
| GitHub Code (existing) | `leak-github-code` | `{ "url": match_url }` |
| GitHub Issue/PR | `leak-github-issue-pr` | `{ "url": match_url }` |
| GitHub Commit Msg | `leak-github-commit` | `{ "sha": commit_sha, "repo": repo }` |
| Pastebin | `leak-pastebin` | `{ "paste_key": paste_key }` |

All findings stay on the parent asset and carry `category="leak"` so the existing customer-category "Data Leaks" filter chip captures them with no UI change.

## Error handling

| Failure | Behaviour |
|---|---|
| `GITHUB_TOKEN` not set | Skip all three GitHub collectors; log info; sensitive-path probe + Pastebin still run |
| `PASTEBIN_FETCHER_ENABLED` not set | Skip the background fetcher entirely; `_match_pastebin` returns no matches (cache stays empty) |
| Pastebin response = "YOUR IP: X.X.X.X DOES NOT HAVE ACCESS" | Log warning, return 0 ingested; operator needs to whitelist the IP |
| Pastebin HTTP timeout / 5xx | Log warning, return 0; next minute's tick retries |
| Single paste body fetch fails | Skip that paste, continue with the rest of the batch |
| Paste body > 64 KB | Truncate to first 64 KB |
| DB unique-key collision on paste_key | Treat as "already ingested", skip silently |
| Cleanup job fails | Log + rollback; next hour's tick retries; cache grows until success |
| `_match_pastebin` SQL timeout | Catch, return empty matches; scan continues with whatever GitHub yielded |
| Engine raises mid-collector | Existing try/except wraps each collector individually; surviving collectors still produce findings |

The invariant: **a scan never fails because of leak-source unavailability.** Sensitive-path probing always runs; GitHub collectors run when token is set; Pastebin matches when the cache has content.

## Test plan

### Unit — engine
- `_search_github_issues_and_prs` parses GitHub `/search/issues` JSON correctly, identifies issue vs PR, builds the matches list with the right URL/title/snippet
- Same method: returns empty matches + sets `rate_limited=true` when `X-RateLimit-Remaining: 0`
- Same method: short-circuits to empty result when token missing
- `_search_github_commit_messages` parses `/search/commits` JSON, extracts `commit_sha` + `repo`
- `_match_pastebin` returns expected matches when paste bodies contain the domain (ILIKE match)
- `_match_pastebin` returns empty + `ingestion_active=false` when the cache is empty or the env flag is off

### Unit — pastebin_client
- `fetch_recent_pastes_and_upsert` correctly upserts new pastes, skips already-seen `paste_key`s, returns count of new rows
- Body truncated to `MAX_BODY_BYTES` when paste is larger
- "IP not whitelisted" text response → returns 0, logs warning
- HTTP timeout → returns 0, no crash
- Malformed JSON → returns 0, logs warning

### Unit — analyzer
- New collectors produce `FindingDraft` rows with the right `template_id`, `category="leak"`, severity matching the snippet pattern
- Dedupe keys stable across re-scans for the same paste / issue / commit

### Integration
- End-to-end scan against a fixture asset with the leak engine enabled. Mock GitHub, mock Pastebin client. Assert Finding rows produced for each source.
- Run twice with same fixtures; assert no duplicate Finding rows (dedupe).
- Cleanup job deletes only expired rows.

### Manual
- Provision a Pastebin PRO account, whitelist the EC2 box IP, set the env var, restart the backend. Watch `paste_cache` populate within 2 minutes. Trigger a scan on an asset whose domain appears in a recent paste — confirm the finding lands.

## Rollout

1. Migration: add `paste_cache` table
2. Deploy backend (`docker compose up -d --build`)
3. GitHub Issues/PRs/commit-messages coverage activates immediately for any scan with `use_leak=true` and `GITHUB_TOKEN` configured — no further setup needed
4. **Pastebin onboarding (optional, can be done later or skipped entirely):**
   1. Create a Pastebin PRO account ($30 lifetime)
   2. In Pastebin → Settings → Scraping API → whitelist the EC2 box's public IP
   3. Set `PASTEBIN_FETCHER_ENABLED=true` in `.env`
   4. Restart the backend
   5. Background fetcher starts ingesting within 60 seconds; cache populates immediately

### Rollback

Straight `git revert` of the deployment. The `paste_cache` table can be left in place (empty table is harmless). Existing leak findings continue to work — they don't depend on the new collectors.

## Open questions

None — all major decisions resolved during brainstorming.

## References

- GitHub `/search/issues` docs: https://docs.github.com/en/rest/search/search#search-issues-and-pull-requests
- GitHub `/search/commits` docs: https://docs.github.com/en/rest/search/search#search-commits
- Pastebin Scraping API docs: https://pastebin.com/doc_scraping_api
- Existing LeakEngine: `backend/app/scanner/engines/leak_engine.py`
- Existing LeakAnalyzer: `backend/app/scanner/analyzers/leak_analyzer.py`
- KEV refresh cache pattern (mirror for Pastebin fetcher): `backend/app/scanner/threat_intel.py`
