# Internal Agent Platform — Phase 2A: Tool Use — Design

**Date:** 2026-05-12
**Status:** Draft (pending user review)
**Builds on:** `2026-05-10-internal-agent-platform-design.md` (Phase 1 design) and `2026-05-10-agent-platform-phase1-walking-skeleton.md` (Phase 1 plan, shipped).

## Goal

Give the 6 existing agents the ability to look things up on their own, instead of relying on the founder pasting context into every prompt. Phase 1's runtime is text-in / text-out — the agents reason and draft well, but can't fetch a CVE page, read a recent finding, run `git log`, or query the GitHub API. Phase 2A adds the tool-use loop and six **read-only** tools.

Concrete success criterion: the failed Rob prompt from 2026-05-12 ("what was the latest update we made on the website?") should now succeed — the agent autonomously calls `git_read log -5` or `github_query commits/master`, reads the result, and returns a concrete answer with real commit SHAs.

## Scope

### In scope

- A multi-turn tool-use loop in `runtime.py`. The loop calls Anthropic with the agent's allowed tools, executes any returned `tool_use` blocks, appends the results to the message history, and continues until the model emits `end_turn` (or the existing `tool_call_cap_per_run` is hit).
- Six read-only tool handlers, registered in a single registry:
  - `read_internal_api(endpoint, params)` — agent calls Nano EASM's own `/api/internal/...` endpoints
  - `web_fetch(url)` — fetches a public URL, HTML→text, with caps
  - `web_search(query)` — Anthropic's native `web_search_20250305` tool
  - `git_read(command, args)` — read-only subset of git commands against the bind-mounted repo
  - `github_query(endpoint, params)` — GitHub REST API, read-only
  - `read_repo_file(path)` — read a file from the bind-mounted repo, with denylist
- Four new `/api/internal/...` endpoints so `read_internal_api` has interesting data to return:
  - `GET /api/internal/findings/recent?severity=&since=`
  - `GET /api/internal/contact-requests/recent`
  - `GET /api/internal/audit-log/recent?category=`
  - `GET /api/internal/scans/recent`
- A read-only bind-mount of the host repo (`~/boltedge-easm/`) into the `easm-backend` container at `/repo`, configured in `docker-compose.yml`.
- Per-agent tool allowlist enforcement: only tools declared in a profile's `allowed_tools` YAML field are exposed to that agent.
- Per-thread cache for idempotent tools (`web_fetch`, `read_repo_file`, `git_read`) so the same call within a thread doesn't repeat the work.

### Out of scope (deferred to Phase 2B or later)

- Any **write** tools (`github_pr_create`, `send_email`, `update_agent_memory` via tool call). Write tools require the approval-queue pattern, which is a real design problem on its own (the agent needs to gracefully continue when its tool is queued instead of executed).
- Other internal API write endpoints. No `POST` / `PUT` / `DELETE` on `/api/internal/...` in this phase.
- Tuesday + Wednesday weekly briefs (Ava `competitor-pulse`, Maya `weekly-finding-brief`). These need tools to work meaningfully, but the skills themselves are deferred to Phase 2B.
- Memory hygiene weekly job. Deferred.
- Send service for approved customer-facing drafts. Deferred.
- Hand-off between agents (allowlists already declared in profiles; queue logic is Phase 3).
- Tavily / Brave fallback for web search. Anthropic-native only in 2A; if your account lacks beta access, the tool returns an error and we revisit.

### Non-goals

- The agent platform must never make production changes via tools. All write paths still go through the existing approval queue (which Phase 2A doesn't touch).
- Phase 2A does not change any existing approval-queue behaviour.
- No tool may bypass the audit log. `read_internal_api` calls Nano EASM via HTTP just like an external client, so every call appears in `audit_log` with `category='agent'`, as established in Phase 1.

## Architecture

### Multi-turn loop in runtime

Phase 1 runtime is one shot: assemble prompt → call Anthropic → persist response. Phase 2A becomes a loop:

```
build_messages_and_system(profile, user_prompt, thread, memory_tags)
loop:
    check_within_cap(profile, monthly_cap)             # hard stop on budget
    check tool_call_cap_per_run                        # hard stop on runaway
    response = anthropic.messages.create(
        system=system,
        messages=messages,
        tools=expose_tools_for(profile.allowed_tools),
        max_tokens=4096,
    )
    if response.stop_reason == "tool_use":
        for tool_use_block in response.content:
            handler = TOOL_REGISTRY[tool_use_block.name]
            result = handler(**tool_use_block.input)   # or error str
            append tool_use_block to messages
            append tool_result block to messages
            persist AgentMessage(role='tool', content={
                "tool_name": ..., "tool_use_id": ..., "input": ..., "output": ...,
            })
        continue
    else:  # end_turn / max_tokens / stop_sequence
        persist final AgentMessage(role='assistant', content=...)
        update AgentRun(status='success', cost_usd=..., duration_ms=...)
        break
```

Persisted tool calls live as `AgentMessage` rows with `role='tool'`. Schema is unchanged; the `content` JSON just carries tool-call metadata.

### Tool registry

Single Python dict in `backend/app/agents/tools/__init__.py`:

```python
TOOL_REGISTRY: dict[str, ToolDef] = {
    "read_internal_api": ToolDef(
        name="read_internal_api",
        description="...",   # exact text passed to Anthropic
        input_schema={...},  # JSON schema for input args
        handler=read_internal_api_handler,
        idempotent=True,
        result_cap_bytes=50_000,
    ),
    ...
}
```

Each tool implementation is a small module under `backend/app/agents/tools/`:

- `internal_api.py` — `read_internal_api` handler
- `web.py` — `web_fetch`, `web_search` handlers
- `repo.py` — `git_read`, `read_repo_file` handlers
- `github.py` — `github_query` handler

### Per-agent allowlist

At run-start, `expose_tools_for(allowed_tools)` filters `TOOL_REGISTRY` to only the entries the profile declares. Anything an agent calls outside that allowlist is a runtime error (caught and returned as a tool result so the agent can recover).

### Per-thread cache

Idempotent tool calls (`web_fetch`, `read_repo_file`, `git_read log/show/blame/diff`) are keyed by `(tool_name, sorted_args_json)` and cached in-memory for the duration of a single thread's run. The cache does NOT persist across runs; each new `run_agent` starts with an empty cache. Reason: most multi-turn loops re-fetch the same data because the model needs it again in a later turn. The cache is a pure latency/cost optimisation — semantics are unchanged.

`web_search` and `github_query` are NOT cached: web search results change continuously, and GitHub queries usually want fresh data.

### Tool result handling

- Each tool handler returns either a string (success) or raises an exception with a clear message (failure). The runtime wraps exceptions into a tool_result with `is_error=True`. Agents see the error and can decide whether to retry or change tack.
- Each tool has a `result_cap_bytes`. Results exceeding the cap are truncated, with a clear marker: `"...[truncated at 50000 bytes; use git_read 'log -1' for smaller output or specify a path range]"`.
- Results are persisted in `AgentMessage.content` (JSON). Long results inflate the message rows but stay under Postgres TOAST limits comfortably.

### Repo bind-mount

`docker-compose.yml` gains one line on `easm-backend`:

```yaml
    volumes:
      - ${HOST_REPO_PATH:-./}:/repo:ro
```

`HOST_REPO_PATH` defaults to `./` (the current docker-compose working dir, which on prod is `~/boltedge-easm/`). Mount is **read-only**: even if a tool handler bug tried to write, the filesystem refuses.

Local dev caveat: if you ever `docker compose up` from a different host path, set `HOST_REPO_PATH` in your `.env` to override.

## Tools

### `read_internal_api(endpoint, params=None)`

| Field | Value |
|---|---|
| Description | "Call Nano EASM's read-only internal API. Use this to read fresh data about orgs, scans, findings, audit log, contact requests. Each endpoint has its own response shape; check the description per endpoint." |
| Input schema | `endpoint: str` (one of: `stats/weekly`, `findings/recent`, `contact-requests/recent`, `audit-log/recent`, `scans/recent`); `params: object?` (query string args) |
| Handler behaviour | Issues an HTTPS request to `http://easm-backend:5000/api/internal/<endpoint>` with the agent's own bearer key. Returns the JSON body as a string. |
| Result cap | 50 KB |
| Idempotent | Yes (cached per thread) |
| Requires scope | Matches the endpoint's scope (`read:stats`, `read:findings`, etc.). Tool rejects unknown endpoints. |

### `web_fetch(url)`

| Field | Value |
|---|---|
| Description | "Fetch a public URL and return its main text content (HTML stripped to readable text). Use for documentation pages, CVE entries, competitor product pages, blog articles." |
| Input schema | `url: str` (must be `http://` or `https://`; private IPs and localhost rejected) |
| Handler behaviour | Issues HTTP GET with `User-Agent: Nano-EASM-Agent/1.0`, 10 s timeout, follows up to 5 redirects. Converts HTML to text via `readability-lxml` or `beautifulsoup4`. |
| Result cap | 50 KB after text extraction |
| Idempotent | Yes (cached per thread) |
| Security | Rejects URLs resolving to RFC1918 / loopback / link-local / metadata IPs (same SSRF defence as `app/quick_scan/routes.py` validator). |

### `web_search(query)`

| Field | Value |
|---|---|
| Description | "Search the public web. Use for finding recent news, threat intel, competitor announcements, technical articles. Returns titles + snippets + URLs, not full page contents — use `web_fetch` to get a specific page's content." |
| Input schema | `query: str` |
| Handler behaviour | Configures Anthropic's `web_search_20250305` tool when invoking the model. Note: this is a server-side tool — the Anthropic SDK handles execution; our handler is a no-op pass-through that just declares the tool to the model. |
| Result cap | Anthropic-controlled |
| Idempotent | No (cached results would defeat the freshness purpose) |
| Failure mode | If your Anthropic account lacks beta access, the model receives a tool-unavailable error and produces a response that says "I tried to search but the tool isn't available." Visible failure, no fallback in 2A. |

### `git_read(command, args=None)`

| Field | Value |
|---|---|
| Description | "Read-only git commands against the Nano EASM repo. Supported subcommands: log, show, diff, blame, status, ls-tree, branch. Other subcommands rejected." |
| Input schema | `command: str` (one of: `log`, `show`, `diff`, `blame`, `status`, `ls-tree`, `branch`); `args: array<str>?` |
| Handler behaviour | Subprocess: `git -C /repo <command> <args...>` with `subprocess.run(..., capture_output=True, timeout=10, check=False)`. Shell injection prevented by passing args as a list, never a string. |
| Result cap | 50 KB (truncated stdout) |
| Idempotent | Yes (cached per thread for `log`, `show`, `blame`, `diff`, `ls-tree`; NOT cached for `status` since working tree state can change) |
| Security | Args containing `;`, `&&`, `|`, redirects, or beginning with `-`-prefixed unknown flags are filtered. Allowed flag set per subcommand documented in the tool's description. |

### `github_query(endpoint, params=None)`

| Field | Value |
|---|---|
| Description | "Call the GitHub REST API (read-only). Examples: 'repos/OWNER/REPO/commits', 'repos/OWNER/REPO/pulls?state=merged', 'repos/OWNER/REPO/contents/path/to/file'." |
| Input schema | `endpoint: str` (relative path after `https://api.github.com/`); `params: object?` |
| Handler behaviour | HTTPS GET with `Authorization: token $GITHUB_TOKEN_AGENTS`. Only GET. `POST`, `PUT`, `PATCH`, `DELETE` rejected at the handler level. |
| Result cap | 50 KB JSON-stringified |
| Idempotent | No (cached results could be misleading for active repos) |
| Failure mode | 403 (rate limit) returned as tool result with remaining-quota info; agent decides whether to wait or use `git_read` instead. |

### `read_repo_file(path)`

| Field | Value |
|---|---|
| Description | "Read a file from the Nano EASM repo by its path relative to repo root. Example: 'backend/app/agents/runtime.py'. Returns the file's text content." |
| Input schema | `path: str` |
| Handler behaviour | Resolves `path` against `/repo` root. Rejects path traversal (`..` segments), absolute paths, and the denylist patterns. Reads up to `result_cap_bytes`. |
| Result cap | 100 KB (files larger than this return a "too large" message suggesting `git_read show <commit>:<path>` or `head`-style alternatives) |
| Idempotent | Yes (cached per thread) |
| Denylist | `.git/*` (always); `.env*`, `*.key`, `*.pem`, `*.p12` (any file matching these patterns at any depth) |
| Security | Path traversal blocked. Symlinks rejected (refuse to follow). |

## Internal API additions

Four new endpoints in `backend/app/agents/internal_routes.py`, each gated by `require_agent_key(scope=...)`:

| Endpoint | Scope | Returns |
|---|---|---|
| `GET /api/internal/findings/recent?severity=&since=&limit=` | `read:findings` | Recent findings across orgs, no PII. Default limit 50, max 200. Fields: id, org_name, asset, severity, title, status, created_at. |
| `GET /api/internal/contact-requests/recent?since=&limit=` | `read:contact_requests` | Recent contact-form submissions. Fields: id, kind, email, message_excerpt, created_at, status. |
| `GET /api/internal/audit-log/recent?category=&since=&limit=` | `read:audit_log` | Recent audit log entries. Fields: id, actor, action, category, target, description, created_at. |
| `GET /api/internal/scans/recent?since=&limit=&status=` | `read:scans` | Recent scan jobs. Fields: id, org_name, asset, status, started_at, finished_at, finding_counts. |

All endpoints follow the same pattern as the existing `stats/weekly`:
- Read directly from SQLAlchemy models (this is the seam — agent code does NOT touch models elsewhere)
- Apply pagination caps
- Return JSON
- Audit-logged via `require_agent_key`

**Scope expansion**: the Founder Ops agent key will be re-issued with all 5 read scopes (`read:stats`, `read:findings`, `read:contact_requests`, `read:audit_log`, `read:scans`). Other agents get scopes specific to their needs (e.g. Maya gets `read:findings` + `read:audit_log`).

## Profile updates

Each agent's `agent.md` will have its `allowed_tools` and `secrets_allowed` updated:

| Agent | New `allowed_tools` |
|---|---|
| Sam | `read_internal_api`, `web_fetch`, `web_search` |
| Rob | `read_internal_api`, `web_fetch`, `web_search`, `git_read`, `github_query`, `read_repo_file` |
| Aisha | `read_internal_api`, `web_fetch`, `git_read`, `github_query`, `read_repo_file` |
| Maya | `read_internal_api`, `web_fetch`, `web_search` |
| Ava | `read_internal_api`, `web_fetch`, `web_search` |
| John | `read_internal_api`, `web_fetch`, `web_search` |

System prompts are updated to mention the available tools (one sentence per agent, e.g. "I can read internal API data, fetch web pages, and search the web for [their domain]") so the model knows the tools exist.

## Permissions and approval gates

**No change to existing approval queue.** Phase 2A tools are all read-only. They execute synchronously, the agent sees the result, and reasoning continues. No `pending_action` rows created by tool calls.

The existing approval queue continues to gate:
- Memory writes (Phase 1 behaviour, unchanged)
- Customer-facing outputs (Phase 1 behaviour, unchanged)

Phase 2B will introduce **write tools** and the approval-queued tool pattern (agent invokes tool → handler creates `pending_action` → returns `[queued]` to agent → agent finishes the run → founder approves → background worker retries).

## Build phases inside Phase 2A

| Stage | Outcome | Tasks (approx) |
|---|---|---|
| A | Multi-turn loop + tool registry skeleton + 1 trivial tool (`read_internal_api` for `stats/weekly` only). One agent (Sam) demonstrates a real tool call. | 5-7 |
| B | Three web tools (`read_internal_api` expanded with 4 new endpoints, `web_fetch`, `web_search`). All 6 agents pass their tests with their respective tool subsets. | 8-10 |
| C | Three repo tools (`git_read`, `github_query`, `read_repo_file`). Rob and Aisha pass tests with all 6 tools. Bind-mount wired in docker-compose. | 6-8 |
| D | End-to-end smoke (the "Rob's git query" scenario). Update CLAUDE.md. | 2 |

**Realistic effort: 2-3 weeks.**

## Open questions / deferred to implementation

- **GITHUB_TOKEN_AGENTS scope.** The existing `GITHUB_TOKEN` env var serves the LeakEngine. For agents, a dedicated `GITHUB_TOKEN_AGENTS` is preferable so it can be scoped to read-only `public_repo` + `read:org`. Decide at implementation time whether to issue a new token or reuse the existing one with the smaller scope.
- **Anthropic web_search beta availability.** Implementation should detect "tool not available" cleanly. If your account lacks the beta in the implementation window, drop `web_search` from the allowed lists and ship Phase 2A without it; revisit when access lands.
- **HTML→text library.** `readability-lxml` is the heavyweight option; `beautifulsoup4 + html2text` is lighter. Decide based on what's already in `requirements.txt`. Either gives acceptable quality.
- **Per-thread cache sizing.** Default to unlimited (since threads are short-lived) but expose a `MAX_TOOL_CACHE_BYTES` env var so we can cap if a thread starts ballooning.
- **Per-tool unit tests.** Each tool needs unit tests with a fake HTTP client / fake subprocess / etc. Pattern from Phase 1's `FakeAnthropicClient` carries over cleanly.
- **Existing `weekly_summary` skill.** It currently calls `_fetch_weekly_stats()` via raw `requests`. Should be refactored to use `read_internal_api` once the tool exists, so the skill goes through the same path as the agent's runtime invocations. Minor cleanup; non-blocking.

## Risks

1. **Cost runaway from multi-turn loops.** Each tool call adds an Anthropic round-trip. A confused agent could rack up tens of tool calls. Mitigation: `tool_call_cap_per_run` (already in profile, set to 50-80) hard-caps loop iterations; per-agent monthly cost cap fires `status='over-budget'` and aborts. Existing Phase 1 controls cover this; no new mitigation needed.

2. **Token bloat from large tool results.** A 50 KB web page tripled across 3 turns is 150 KB in context. Mitigation: per-tool result caps (50 KB for `web_fetch`, `git_read`, `github_query`, `read_internal_api`; 100 KB for `read_repo_file`). Truncated results are explicit about what was dropped.

3. **Anthropic native `web_search` not available.** Beta access varies. Mitigation: handler returns a clear "tool not available" error; agent gracefully reports it can't search. We add Tavily fallback in a later iteration if your account never gets access.

4. **GitHub rate limit (5000/hr).** A stuck loop could exhaust it. Mitigation: `tool_call_cap_per_run` + per-thread cache + handler returns remaining quota in the error message so the agent knows when to back off.

5. **Path-traversal / sandbox escape in `read_repo_file`.** Mitigation: resolved paths must be under `/repo`, symlinks rejected, denylist enforced. Tested with unit tests covering `../`, absolute paths, symlinks, and denylist matches.

6. **Subprocess invocation in `git_read`.** Shell injection via crafted args. Mitigation: args passed as a list to `subprocess.run`, never as a shell string; per-subcommand allowed-flag set.

7. **`.env` exposure via `read_repo_file`.** Mitigated by denylist (`.env*`). If a future founder forgets to gitignore a new secret file, it's still readable unless the pattern matches. Mitigation: documented; defence-in-depth is the gitignore-as-allowlist approach (deferred).

8. **Anthropic logging of tool results in messages.** Tool results become part of the messages sent on the *next* tool-use round. Anything in those results goes to Anthropic. With the denylist on sensitive files this is acceptable; without it, agents could read `.env` and inadvertently send secrets to Anthropic.

## Success criteria

Phase 2A is judged successful if, at the end of 2 weeks of use:

- The founder asks any of the 6 agents at least one question per workday that *requires* tool use (not pure reasoning), and the answer is correct in ≥ 90 % of cases.
- The Rob "what was the latest update on the website" prompt returns a real commit-level answer with a SHA.
- No tool has caused an unintended write, exfiltration, or production incident.
- Cost per multi-turn run averages < $0.10 (i.e. tool use doesn't blow the budget); per-agent monthly cap not exceeded.
- `read_repo_file` denylist holds (no agent has surfaced an `.env`/`.key`/`.pem` value in its output).

If any of these fail, the agent platform regresses to "scaffold without leverage" — trim or rethink before Phase 2B.
