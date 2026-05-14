# Leak Engine

**Module:** `backend/app/scanner/engines/leak_engine.py` + `backend/app/scanner/analyzers/leak_analyzer.py`
**Detects:** Six sub-features depending on what's configured:

1. **Sensitive paths** — exposed config files on customer assets ([sensitive-paths.md](sensitive-paths.md))
2. **GitHub Code search** — credentials in public code referencing the customer domain
3. **GitHub Issues / Pull Requests** — credentials pasted into issue / PR descriptions
4. **GitHub commit messages** — credentials documented in commit summaries
5. **GitLab public blob search** — equivalent of GitHub code search on GitLab.com
6. **Pastebin** — customer-domain mentions in recently-published public pastes

**Plan gate:** `leak_detection` (Starter+). Standard / Deep profiles enable `use_leak=True`. Free customers do not get the leak engine.
**Severity:** Per finding-source; credentials → critical/high; mentions only → low. Per-pattern severity tuned in the analyzer's category map.

## Required setup

The sensitive-path sub-feature works with zero setup. The remote-source sub-features each require their own credential.

### GitHub (Code + Issues/PRs + Commits)

```bash
GITHUB_TOKEN=<github personal access token>
```

- Token type: classic PAT, scope = `public_repo` is enough (we only search public content)
- Rate limit: 30 search-API requests per minute per token. Engine respects this and stops gracefully at 403
- Without `GITHUB_TOKEN`: all three GitHub sub-features short-circuit silently; sensitive-path probing still runs
- Generate at https://github.com/settings/tokens — pick "Tokens (classic)" with no scopes if all you'll ever search is public code

### GitLab (public blob search)

```bash
GITLAB_TOKEN=<gitlab personal access token>
```

- Token type: any PAT with `read_api` scope
- Without a token: the engine still runs (GitLab allows anonymous search) but the per-IP rate limit is much harsher. With a token: ~2000 req/min per token
- Generate at https://gitlab.com/-/user_settings/personal_access_tokens

### Pastebin

```bash
PASTEBIN_FETCHER_ENABLED=true
```

Requires manual operator setup:

1. Buy a **Pastebin PRO account** — one-off $30 USD at https://pastebin.com/pro
2. Sign in → **Settings** → **Scraping API** → whitelist your server's public IP
3. Set `PASTEBIN_FETCHER_ENABLED=true` in `.env`
4. Add the var to `docker-compose.yml` under `easm-backend.environment:` if it's not already there (only entries declared there reach the container)
5. Restart the backend; the fetcher starts polling within 60 seconds

Without these steps the Pastebin sub-feature is silently disabled — scans still produce findings from the other sources.

## Optional setup

- **`max_github_searches`** profile flag — default 12. Raise to expand coverage at the cost of more API budget
- **`max_gitlab_searches`** profile flag — default 8
- **`max_github_issue_searches`** profile flag — default 5
- **`max_github_commit_searches`** profile flag — default 5
- **`max_pastebin_matches`** profile flag — default 50 (the cap on the SQL-side match)

## How to verify

```bash
# Confirm env vars reach the container
docker compose exec easm-backend env | grep -E "GITHUB_TOKEN|GITLAB_TOKEN|PASTEBIN"

# Confirm Pastebin fetcher is ingesting (only if enabled)
docker compose exec easm-db psql -U easm_user -d easm -c "
SELECT COUNT(*) AS rows, MAX(fetched_at) AS latest FROM paste_cache;
"
# Expected: rows > 0, latest within the last minute or two

# Trigger a scan; watch the leak engine log lines
docker compose logs easm-backend --tail=200 2>&1 | grep -i "LeakEngine"
```

## Operational notes

- The leak engine's six sub-features run independently. Any one failing (e.g. GitHub rate-limit) doesn't break the others
- GitHub Issues/PRs and commit-message searches use a separate, shorter pattern list than the code-search to keep API budget under control (signal density is lower)
- The Pastebin background fetcher writes to `paste_cache` continuously (independent of scan jobs); the leak engine queries that cache when a scan runs
- `paste_cache` rows expire after 7 days; an hourly cleanup job removes them
- 90-day TTL on Pastebin paste content is enforced by the lifecycle rule in the cleanup job — older matches drop off naturally
- See [site-mimic.md](site-mimic.md) for an upstream-related feature that consumes Lookalike output

## Findings produced

| Template ID | Source | Severity |
|---|---|---|
| `leak-git-exposed` / `leak-env-file` / `leak-ssh-private-key` / etc. | Sensitive paths | per-template |
| `leak-github-credentials` | GitHub Code Search — credentials pattern | high → critical (with secret-pattern boost) |
| `leak-github-api-key` | GitHub Code Search — API key pattern | high |
| `leak-github-cloud-creds` | GitHub Code Search — cloud creds pattern | critical |
| `leak-github-secrets` | GitHub Code Search — generic secrets | high |
| `leak-github-env-file` | GitHub Code Search — `.env` file | high |
| `leak-github-config` | GitHub Code Search — config file | medium |
| `leak-github-issue-pr` | GitHub Issues / PRs search | high |
| `leak-github-commit` | GitHub commit-message search | high |
| `leak-gitlab-credentials` / `leak-gitlab-api-key` / etc. | GitLab blob search | mirrors GitHub |
| `leak-pastebin` | Pastebin cache match | high |

**Customer-facing category:** Data Leaks
