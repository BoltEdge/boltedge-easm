# Next Scan Engines / Sources to Add

Backlog of scan-engine work that's been designed but not yet
implemented. Each entry has enough detail that you can pick it up
cold and execute without re-deriving the architecture.

Status as of the most recent backlog refresh:

| Source | Status | Plan tier |
|---|---|---|
| Sensitive-path probing | **Live** — runs on Standard/Deep/Full when `use_leak=true` | Starter+ |
| GitHub Code Search | **Live** — gated by `GITHUB_TOKEN` env var | Starter+ |
| GitLab Code Search | **Live** — gated by `GITLAB_TOKEN` env var (optional) | Starter+ |
| Secret-pattern detector library (gitleaks-style) | **Live** as a shared module (`tools/secret_patterns.py`) — currently invoked only from GitLab flow | n/a (library) |
| NPM published packages | **Pending** | Starter+ |
| Docker Hub public images | **Pending** | Starter+ |
| Postman public workspaces (dork-style) | **Pending** | Starter+ |
| Apply `secret_patterns` to existing `github_leaks` flow | **Pending** | n/a (cross-cutting) |
| HaveIBeenPwned domain breach | **Deferred — paid API** | TBD |
| Public S3/GCS/Azure bucket finder (GrayHatWarfare) | **Deferred — paid API** | TBD |

Rate-limit / shared-token concern: all token-backed sources currently
use a single operator-side env var (`GITHUB_TOKEN`, `GITLAB_TOKEN`, etc.)
shared across every customer scan. At scale this becomes a noisy-neighbour
problem and a single point of failure. See the *Operator concerns* section
at the end before adding more sources that need third-party tokens.

---

## 1 — Apply `secret_patterns` to the existing `github_leaks` flow

**Why first:** zero new infrastructure, immediate precision lift on the
flow that already produces the most findings. The detector module is
already built — GitHub just isn't using it yet.

**Scope:** ~30 lines.

**Where:** `backend/app/tools/github_leaks.py`

The GitLab tool already does this in `_enrich_blob_with_secret_matches()`
— mirror that exactly:

```python
from app.tools.secret_patterns import detect_secrets

def _enrich_match_with_secret_matches(match: Dict[str, Any]) -> Dict[str, Any]:
    """Run regex secret detectors over a GitHub Code Search match's
    snippet. Adds `secret_matches` with high-confidence hits."""
    snippet = match.get("snippet") or match.get("text_matches") or ""
    if isinstance(snippet, list):
        # GitHub returns text_matches as a list of {fragment, ...} objects
        snippet = " ".join((tm.get("fragment") or "") for tm in snippet if isinstance(tm, dict))
    if not snippet:
        return match
    matches = detect_secrets(str(snippet))
    if matches:
        match["secret_matches"] = [
            {"pattern_id": m.pattern_id, "pattern_name": m.pattern_name,
             "severity": m.severity, "redacted": m.redacted}
            for m in matches
        ]
    return match
```

Call it inside `run_github_leak_scan()` per-match in the same place
GitLab calls its enrichment. Then mirror the analyzer change: in
`backend/app/scanner/analyzers/leak_analyzer.py`, the GitHub block already
emits `sample_files` — extend each entry with `secret_matches: f.get("secret_matches") or []`
to surface the regex hits in the finding details, exactly as the GitLab
block now does.

**Also worth doing:** when one or more `secret_matches` are present,
**bump the finding severity** to the highest severity of any matched
pattern (e.g., a search returning a snippet that contains a real
`AKIA…` key elevates the finding to critical regardless of the keyword
search's nominal severity). Cleaner than hand-tuning the keyword
patterns.

**Templates:** none new needed (existing `leak-github-*` templates work
— `secret_matches` lives in `details_json`, surfaced via the finding
details panel).

---

## 2 — NPM published packages

**Why:** people accidentally publish secrets in NPM tarballs (in
`package.json`, README, build scripts, or hardcoded in JS). NPM's
registry is free, anonymous, well-documented. High signal-to-noise when
filtered by domain.

**Scope:** ~200 lines + 4 templates.

**APIs — all free, anonymous, no auth required:**

```
# Package search by keyword
GET https://registry.npmjs.org/-/v1/search?text=<query>&size=20
  → { objects: [{ package: {name, description, links, author, ...}, score, ... }, ...] }

# Per-package metadata (versions, README, dependencies)
GET https://registry.npmjs.org/<package_name>
  → { name, "dist-tags", versions: { "1.0.0": { ... } }, readme, ... }

# Tarball (gzipped tar) — for deeper scanning
GET https://registry.npmjs.org/<package>/-/<package>-<version>.tgz
```

**Rate limits:** NPM's CDN is generous — no published limit, but they
expect reasonable use. Keep per-scan budget to <50 requests.

**Implementation sketch:**

```
backend/app/tools/npm_leaks.py        — new module
backend/app/scanner/engines/leak_engine.py  — add "5. NPM package search" block
backend/app/scanner/analyzers/leak_analyzer.py  — add NPM_CATEGORY_MAP + analyzer block
backend/app/scanner/templates.py     — 4 new templates
```

**Search strategy:**

1. Search the registry for packages mentioning the domain in any field:
   `?text=<domain>` (matches description, keywords, author)
2. For each hit (cap at top 10 by relevance):
   - Pull `readme` from the package metadata (no tarball needed for v1).
   - Run `secret_patterns.detect_secrets()` over README + `package.json` excerpts.
   - Optionally: scan author email field for company-domain matches
     (high-signal: an ex-employee published with `@company.com` author).

**Categories → templates:**

| Category | When | Template ID | Severity |
|---|---|---|---|
| `npm-package-secrets` | `secret_matches` non-empty in README/package.json | `leak-npm-secrets` | inherits highest secret_match severity |
| `npm-package-mention` | Domain mentioned in description/keywords with no secret hit | `leak-npm-mention` | low (informational, possible recon material) |
| `npm-author-email` | Author email matches scanned domain | `leak-npm-author` | low |
| `npm-published-by-org` | Package author/maintainer matches org name | `leak-npm-org` | info |

**Gotchas:**
- NPM aliases (e.g., `@scope/name`) need URL-encoding — `%40scope%2Fname`.
- `readme` may be missing on legacy packages; fall back to `description`.
- Be careful with deprecated packages — check `dist-tags` for `latest`.

---

## 3 — Docker Hub public images

**Why:** secrets routinely end up in image layers (entrypoint env vars,
build-args, baked-in `.env` files). Even just image metadata + README
catches mistakes like "company.com pushed an image called `prod-api`
with a Dockerfile reference to an internal CI URL".

**Scope:** ~250 lines + 3 templates.

**APIs — all free, rate-limited per IP:**

```
# Repository search by keyword
GET https://hub.docker.com/v2/search/repositories?query=<text>&page_size=10
  → { count, results: [{ repo_name, short_description, star_count, ... }, ...] }

# Per-repo metadata (README, last_updated, official, automated)
GET https://hub.docker.com/v2/repositories/<namespace>/<repo>
  → { description, full_description (= README), last_updated, ... }

# Image tags (latest first)
GET https://hub.docker.com/v2/repositories/<namespace>/<repo>/tags?page_size=10

# Manifest fetch — needs the Docker Registry API, not Hub API. Heavier.
# Skip for v1.
```

**Rate limits:**
- Anonymous: 100 image pulls / 6h per IP (search/metadata calls separately, much higher)
- Authenticated free-tier: 200 / 6h

**Implementation sketch:**

```
backend/app/tools/docker_hub_leaks.py
backend/app/scanner/engines/leak_engine.py   — add "6. Docker Hub" block
backend/app/scanner/analyzers/leak_analyzer.py  — add DOCKER_CATEGORY_MAP + analyzer block
backend/app/scanner/templates.py             — 3 new templates
```

**Search strategy (v1 — README scan only, no layer manifest fetch):**

1. Search Hub for repos matching the domain: `?query=<domain>`.
2. For each hit (top 10 by stars + relevance):
   - Pull `full_description` (README markdown).
   - Run `secret_patterns.detect_secrets()` over the README.
   - Check tags list — if multiple recent dated tags exist, high signal
     of an actively-published image.

**Categories → templates:**

| Category | Trigger | Template ID | Severity |
|---|---|---|---|
| `docker-image-secrets` | `secret_matches` in README | `leak-docker-secrets` | inherits highest match severity |
| `docker-image-mention` | Domain in repo name or description | `leak-docker-mention` | low |
| `docker-image-internal-host` | URLs/hostnames in README that look internal | `leak-docker-internal-host` | medium |

**Phase 2 (later, separate ticket):** parse image manifests via the
Docker Registry API (`registry-1.docker.io`), download layer tarballs,
scan filesystem-level files. Heavy — 100MB+ image, gzip+tar parsing,
handles streaming. Real value but bigger lift.

**Gotchas:**
- Hub responses include both `library/` (official) and `username/` repos.
  Filter to non-`library` for leak hunting.
- `last_updated` matters: a 2018-archived repo with secrets is different
  from a 2025-actively-published one. Surface dates in finding details.
- Watch for typo-squatting domains: `compamy.com` searching may return
  legitimate `company.com` repos. Use exact domain match for the
  category-`mention` finding.

---

## 4 — Postman public workspaces (dork-style)

**Why:** Postman public workspaces routinely expose API endpoints
(internal URLs, headers including `Authorization: Bearer …`, even keys
in environment-variable example values). The Postman Cloud Search API
is paid (`X-Api-Key` required), so we can't programmatically search at
the free tier — but we CAN generate manual-investigation links the same
way the existing `GOOGLE_DORKS` feature works.

**Scope:** ~80 lines + 1 template.

**Implementation:** there's no API to call — this is a "dork generator"
that produces investigation URLs the user clicks through to verify by
hand.

**Where:** extend `tools/github_leaks.py:GOOGLE_DORKS` (or create a
parallel `tools/postman_dorks.py`) with these queries:

```python
POSTMAN_DORKS = [
    {
        "title": "Postman public workspaces mentioning {domain}",
        "query": '"{domain}" site:postman.com',
        "search_url_template": "https://www.google.com/search?q={query}",
        "description": "Public Postman workspaces and collections referencing {domain}.",
    },
    {
        "title": "Postman API examples with {domain} URLs",
        "query": '"{domain}" inurl:postman.com/workspace',
        "search_url_template": "https://www.google.com/search?q={query}",
        "description": "Postman workspace pages with {domain} URLs in path or content.",
    },
    {
        "title": "Postman Run buttons with {domain} env",
        "query": '"{domain}" "run in postman"',
        "search_url_template": "https://www.google.com/search?q={query}",
        "description": "Pages embedding 'Run in Postman' buttons with {domain} environment data.",
    },
    {
        "title": "Postman direct workspace search for {domain}",
        "query": "{domain}",
        "search_url_template": "https://www.postman.com/search?q={query}&type=team",
        "description": "Direct search of postman.com for {domain}-named workspaces.",
    },
]
```

The leak engine already aggregates `data["dorks"]` and the frontend's
finding details panel renders them as clickable links. Just append
these to the existing dork output in
`scanner/engines/leak_engine.py:execute()`.

**Template:** add a single `leak-postman-dork` template that's emitted
once per scan when `dorks` includes Postman entries — primarily a
heads-up that manual verification is recommended, since we can't
programmatically confirm anything without the paid API.

**Phase 2 (paid):** if the org has an enterprise Postman API key, fetch
public workspaces directly via `GET /apis/search` with the key. Out of
scope for the free tier.

---

## Cross-cutting follow-ups

### Token-pool / BYOK abstraction

Right now `tools/github_leaks.py` and `tools/gitlab_leaks.py` both call
`os.environ.get("<SOURCE>_TOKEN")` directly. Once a third source needs
a token (probably never for free sources, but HIBP if we ever wire it
up), this should be abstracted into something like:

```python
# app/tools/external_tokens.py
def get_external_token(source: str, *, org_id: int | None = None) -> str | None:
    """Resolve the external API token for a source.
    
    Resolution order (first match wins):
    1. Org-specific BYOK token from `external_token` table (Phase 2)
    2. Operator-side default from env (e.g., GITHUB_TOKEN)
    3. None — caller must handle the unauthenticated case gracefully.
    """
```

Don't build it speculatively — wait until BYOK is a real customer ask.

### Per-source rate-limit metrics

The `LeakEngine` currently reports `rate_limited: bool` per source. We
should surface this in the scan-job summary so customers know when a
finding-set is incomplete due to rate limiting (vs. genuinely empty).
Worth a small UI badge in the scan-results page.

### Secret-pattern findings as first-class

Today `secret_matches` are stored as enrichment metadata inside an
existing `leak-github-*` / `leak-gitlab-*` finding. When a high-confidence
pattern fires (e.g., a real AWS key), it might deserve its own
top-level finding instead of being buried in a sub-attribute. Consider
adding `leak-secret-<pattern_id>` templates and emitting one finding per
distinct secret found (deduped by `pattern_id` + `redacted` value).
Bigger UX change — defer until customers ask.

---

## Operator concerns

- **One token, all customers:** `GITHUB_TOKEN` and `GITLAB_TOKEN` are
  shared across every Standard/Deep/Full scan in the platform. If one
  customer scans 50 domains, they drain the bucket for everyone.
  Solutions in priority order: dedicated bot account (now), token pool
  (when single-token rate-limit pressure becomes visible in logs), BYOK
  (when an enterprise customer asks).
- **Attribution:** every API call shows up in the operator's GitHub /
  GitLab account audit log, including the customer's asset domain in
  the search query. If that's sensitive (e.g., a Custom-tier customer
  scanning a confidential domain), it's a leak vector of its own.
- **Token rotation:** rotating these tokens currently requires a backend
  redeploy because they're env-vars. A `secrets/external_tokens.json`
  loaded at startup with file-watch reload would let ops rotate without
  a redeploy, but that's premature until rotation actually hurts.

## Deferred — paid sources

Documented for posterity in case the cost-benefit changes:

| Source | Cost | Why we skipped |
|---|---|---|
| HaveIBeenPwned domain endpoint | ~A$5/mo per domain | High-signal but paid; needs a domain-ownership verification flow we haven't built. |
| GrayHatWarfare bucket index | ~$30/mo | High-signal for cloud bucket leaks. Worth revisiting when cloud-asset coverage is a customer priority. |
| Postman Cloud Search API | Postman paid plan | Search API gated behind paid plan; dork-generator is the free workaround above. |
| Trufflehog (the binary) | License | AGPL-3.0 — running it server-side as part of a SaaS triggers source-distribution obligations. We re-implemented the relevant detectors as the MIT-friendly `secret_patterns` module instead. |
