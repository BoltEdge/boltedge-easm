# Internal Agent Platform — How It Works

> A plain-language guide to how the 6 AI agents run, where everything lives, and what stops them from doing anything stupid.

## TL;DR (30 seconds)

You hired a 6-person AI ops team: **Sam, Rob, Aisha, Maya, Ava, John**. Each has a job description (a markdown file), a private notebook (a database table), a shared whiteboard (another database table), a phone they can use to look things up (a set of tools), and an inbox where they leave drafts for you to approve (the approval queue).

When you click "Run now" in `/admin/agents`, the backend reads the agent's job description, dials Claude with the prompt and the list of tools the agent can use, executes any tool calls the agent makes, and shows you the response. Anything externally visible (emails to customers, code merges, permanent memory writes) lands in your approval queue first — never auto-sends.

---

## The team

| Persona | Role | Reports to |
|---|---|---|
| **Sam** (Founder Ops) | Coordinates the team, writes weekly summaries, task triage | You |
| **Rob** (Engineer) | Code review, bug analysis, dependency audits, debugging | Sam |
| **Aisha** (QA) | Release readiness, test plans, bug reproduction | Sam |
| **Maya** (Security Analyst) | Findings review, severity, threat intel, CVE analysis | Sam |
| **Ava** (Marketing Strategist) | Competitor pulse, positioning, sales messaging | Sam |
| **John** (Voice) | Blog drafts, support replies, marketing copy, social posts | Sam |

You're the **director**. Sam reports to you and coordinates the others. The other five do their specialised work and pass it back up via Sam.

---

## Each agent has four things

### 1. A job description

This is a markdown file on disk, version-controlled in git, that says "you are this agent, this is your role, here are your rules." For Sam, it's `backend/app/agents/profiles/founder-ops/agent.md`. The top is YAML config (which tools they can use, monthly cost cap, model to use), and the body is the system prompt the model sees.

A real excerpt from Sam's file:

```markdown
---
name: founder-ops
display_name: Sam
allowed_tools:
  - read_internal_api
  - web_fetch
  - web_search
cost_cap_monthly_usd: 50
default_model: claude-opus-4-7
---
Hi, my name is Sam. I'm the Founder Ops agent for Nano EASM. I report
directly to the director — that's the founder...
```

If you want to change how Sam behaves, edit this file. Commit. Rebuild the backend container on prod. Done. No code change required.

### 2. A private notebook (`agent_memory`)

A database table where each agent stores facts only they can see. One row per fact, tagged so the agent can find relevant ones later.

Example rows for Sam:

| key | value | tags |
|---|---|---|
| `weekly:2026-05-12` | `{signups: 5, scans: 130}` | `topic:metrics, skill:weekly-summary` |
| `customer:acme:plan_tier` | `{tier: "Pro", renewed: "2026-04-12"}` | `customer:acme, topic:plan` |
| `priority:Q3:focus` | `{focus: "MSP integrations"}` | `priority, quarterly` |

When Sam runs again next Monday, the backend will load any of Sam's memory rows that have tags matching the current task. So when Sam writes next week's summary, last week's signup number gets loaded automatically.

**Rob has his own notebook, Maya has hers, etc.** They don't share. That's deliberate — keeps each agent's context focused.

### 3. A shared whiteboard (`team_memory`)

A separate table with a small set of facts every agent reads on every run. This is where universal rules live.

The 8 facts currently on the whiteboard:

| key | gist |
|---|---|
| `brand:never_use_boltedge` | Always say "Nano EASM", never "BoltEdge" |
| `brand:no_community_framing` | Don't say "community edition" — say "free upgrades until further notice" |
| `market:global` | Customer base is global; don't pitch as Australia-only |
| `compliance:no_audit_ready_claims` | Never claim audit-ready for SOC 2 / ISO 27001 |
| `billing:disabled` | Billing currently off; don't quote prices |
| `approval:hard_gates` | Never agent-initiated: deploys, DNS, pricing, legal |
| `voice:tone` | Brand voice: terse, factual, no filler |
| `nano_easm:url` | Production URL is https://nanoeasm.com |

**Only you write to this table.** Agents can propose additions (they land in the approval queue), but they never auto-write. This prevents one agent's hallucinated "fact" from poisoning everyone's context.

### 4. A phone (tools)

This is what Phase 2A unlocked. Tools let the agent **look things up themselves** instead of relying on whatever you pasted into the prompt. Six tools currently available:

| Tool | What it does | Who uses it |
|---|---|---|
| `read_internal_api` | Calls Nano EASM's own `/api/internal/...` endpoints — recent findings, recent scans, audit log, contact requests, weekly stats | All agents |
| `web_fetch` | Fetches a URL, strips HTML to readable text. 50 KB cap. Refuses private/internal IPs. | All agents |
| `web_search` | Searches the public web (Anthropic-native search) | Sam, Rob, Maya, Ava, John (not Aisha) |
| `git_read` | Runs read-only `git log` / `git show` / `git diff` / `git blame` / `git status` / `git ls-tree` / `git branch` against the repo | Rob, Aisha |
| `github_query` | Calls the GitHub REST API (read-only) for PRs, commits, issues | Rob, Aisha |
| `read_repo_file` | Reads a file from the repo by path. Blocks `.git/`, `.env*`, `*.key`, `*.pem`, `*.p12`. | Rob, Aisha |

Each agent's profile lists which tools they're allowed. Sam can't run `git_read`; Rob can. Maya can search the web; Aisha can't (she doesn't need it).

---

## A real example: Sam writes the Monday digest

Walk-through of the Monday 8 AM scheduled job.

**Step 1.** APScheduler fires inside the backend container. It calls `run_weekly_summary(send=True)`.

**Step 2.** The function loads Sam's profile:
```
backend/app/agents/profiles/founder-ops/agent.md
```

**Step 3.** It calls `run_agent(agent_name="founder-ops", user_prompt="produce the weekly summary…", skill="weekly-summary")`.

**Step 4.** The runtime assembles the prompt:
- **System**: Sam's profile body ("Hi, I'm Sam…") + all 8 team-memory facts + any Sam-specific notebook entries tagged `topic:metrics` or `skill:weekly-summary` (probably last week's headline numbers).
- **Messages**: just the new user prompt.
- **Tools**: `read_internal_api`, `web_fetch`, `web_search` (Sam's allowed list).

**Step 5.** The runtime calls Anthropic. Claude replies: *"I need to look at this week's stats first."* and emits a `tool_use` block:
```json
{
  "id": "tu_a8f3",
  "name": "read_internal_api",
  "input": {"endpoint": "stats/weekly"}
}
```

**Step 6.** The runtime executes the tool. The handler makes an HTTP GET to `http://easm-backend:5000/api/internal/stats/weekly` with Sam's bearer key. The response comes back:
```json
{"orgs_total": 42, "users_total": 75, "signups_in_window": 5,
 "scans_in_window": 130, "plan_mix": {"Free": 30, "Starter": 8, "Pro": 4}, …}
```

**Step 7.** The runtime appends the tool result to the message history and calls Anthropic again. Claude might emit another `tool_use` (e.g. `read_internal_api` for `audit-log/recent` to find anything noteworthy this week), and the loop continues.

**Step 8.** Eventually Claude returns a final markdown response:
```markdown
**This week:** 5 signups, 130 scans, 1 critical finding on Acme.

- Signups: 5 (+25% vs last week)
- Scans: 130 across 42 orgs
- Plan mix unchanged (Free dominant)
- Notable: Acme had a critical CVE-2026-1234 finding flagged on Wed
```

**Step 9.** The runtime stores everything:
- `agent_run` row: status=success, cost_usd=$0.034, duration_ms=4521
- `agent_thread` row: new thread "weekly-summary 2026-05-12"
- `agent_message` rows: user prompt, tool calls, tool results, final assistant message
- A `pending_action` row proposing to remember `weekly:2026-05-12 → {signups: 5, scans: 130, …}` in Sam's notebook

**Step 10.** The send service emails the markdown (rendered as HTML) to `FOUNDER_EMAIL` via Resend.

**Step 11.** Monday morning, you open your inbox: the digest is there. You also see one item in `/admin/agents/approvals`: Sam's proposed memory write. You click ✓ and now next Monday's prompt will have access to "5 signups, 130 scans" as a comparison point.

Total cost: a few cents. No human needed during the run.

---

## A real example: Rob answers a code question

You're at your laptop. You open `/admin/agents/engineer` and type:

> "What was the latest update we made on the website?"

**Step 1.** Frontend sends `POST /admin/agents/engineer/run`.

**Step 2.** Backend loads Rob's profile. Rob's `allowed_tools` includes `git_read`, `github_query`, `read_repo_file` (plus the web tools).

**Step 3.** Runtime calls Anthropic with the prompt + tools list. Claude replies with a `tool_use`:
```json
{"name": "git_read", "input": {"command": "log",
                                "args": ["-5", "--oneline"]}}
```

**Step 4.** The handler runs `git -C /repo log -5 --oneline` via subprocess. `/repo` is a bind-mount to your live `~/boltedge-easm/` repo on the server, so Rob sees whatever's actually deployed. Output:
```
1d09e45 docs+test: Phase 2A smoke test extensions + CLAUDE.md update
9cb0b21 feat(agents): each agent's system prompt mentions its tools
a5bfb78 feat(agents): github_query tool + wire repo tools to Rob and Aisha
cbd2ac1 feat(agents): read_repo_file tool with denylist
3886018 feat(agents): git_read tool + repo bind-mount
```

**Step 5.** The runtime feeds that back to Claude. Claude may request more (e.g. `git_read show 1d09e45` to see what changed), or it might already be enough.

**Step 6.** Final response:
> "The most recent commit is `1d09e45` — added Phase 2A smoke test extensions + CLAUDE.md update. The last 5 commits are all part of Phase 2A: agent tool wiring, the GitHub query tool, the file-reading tool, and the git-read tool with a repo bind-mount."

This is the prompt that **failed** before Phase 2A — Rob just said "I don't have access to git." After Phase 2A, he actually checks.

---

## A real example: John drafts a support reply (with the approval gate)

A new contact-form submission lands in your `contact_request` table from "alex@example.com" — they're asking about MSP onboarding.

You open `/admin/agents/voice` and type:

> "Draft a reply to the latest contact request about MSP onboarding."

**Step 1.** John's runtime starts. John's allowed tools: `read_internal_api`, `web_fetch`, `web_search`.

**Step 2.** Claude emits a `tool_use`:
```json
{"name": "read_internal_api",
 "input": {"endpoint": "contact-requests/recent", "params": {"limit": 5}}}
```

**Step 3.** Handler returns the recent contact requests as JSON. John reads Alex's message: *"Hi, I run an MSP serving 30 customers. Curious about how Nano EASM handles multi-tenant ASM."*

**Step 4.** John drafts a reply in markdown. Claude returns:
> "Hi Alex, …" *(full draft)*

**Step 5.** You see the draft in the browser response. **Nothing has been sent.** This is the critical point: John never has sending capability. The draft is a string; the send service requires an explicit approval-queue approval before it actually fires Resend.

**Step 6.** If you like the draft, you'd click "Send" in the approval queue (this UI is on the Phase 2B roadmap). Then — and only then — the platform sends the email via Resend.

For now (Phase 2A), drafts come back as text and you copy-paste manually. The approval-queued send is Phase 2B.

---

## What runs automatically (no human needed)

Three scheduled jobs (only Monday is shipped in Phase 1; Tue + Wed are Phase 2B):

| Day/Time | Agent | Skill | Output |
|---|---|---|---|
| Monday 08:00 | Sam | `weekly-summary` | Markdown digest email to FOUNDER_EMAIL |
| Tuesday 08:00 | Ava | `competitor-pulse` (Phase 2B) | Market snapshot email |
| Wednesday 08:00 | Maya | `weekly-finding-brief` (Phase 2B) | Top findings + threat intel email |

APScheduler runs inside the backend container as a daemon thread. When the cron fires, it just calls the skill function, which runs the agent end-to-end — same path as if you'd clicked "Run" in the browser.

---

## The safety net (three layers)

### Layer 1: Capability fences (in each agent's profile)

Every agent's YAML lists exactly which tools they can use and which secrets they can access. Anything not on the list is unavailable. Sam literally cannot call `git_read` — the runtime doesn't even expose it to her.

```yaml
# Sam's profile
allowed_tools:
  - read_internal_api
  - web_fetch
  - web_search
secrets_allowed:
  - NANOEASM_API_KEY_AGENTS
external_writes: false
```

`external_writes: false` is the catch-all: no agent in Phase 2A can directly send an email, open a PR, or modify Nano EASM data. The platform refuses the action regardless of what the model emits.

### Layer 2: The approval queue

Anything externally visible doesn't execute synchronously — it lands in `pending_action`. You approve via `/admin/agents/approvals`. Approve → executes. Reject → captured as feedback for that agent.

Example approval-queue row right after Sam's weekly summary:

```
Agent:       founder-ops
Action type: memory-write
Target:      weekly:2026-05-12
Payload:     {value: {signups: 5, scans: 130, ...},
              tags: [skill:weekly-summary, topic:metrics],
              source: skill-output}
Rationale:   weekly-summary headline numbers
Proposed:    2026-05-12 08:01:23
Expires:     2026-05-19 08:01:23
```

You click ✓ and the row is "consumed" — the memory is written. You click ✕ with a reason, and the rejection is captured as feedback on Sam's notebook so she'll think differently next time.

### Layer 3: Hard gates (in code)

The platform refuses outright on:
- Production deploys
- DNS, certificate, infrastructure changes
- Secrets management (rotating keys, env var changes)
- Pricing, plan, commercial decisions
- Legal / policy / terms changes
- Granting access (impersonation, superadmin, API keys)
- Outbound spend (upgrading external services)

These are not behind the approval queue. They're **not in the toolset at all.** No agent can attempt them; the founder does them by hand.

Plus three runtime safety caps per agent:
- **Monthly cost cap** (e.g. Sam: $50/month Anthropic spend). When hit, future runs return `status=over-budget` and don't execute.
- **Per-run wall-time cap** (default 600 seconds). A stuck run aborts itself.
- **Per-run tool-call cap** (e.g. 50 calls). A loop calling tools in a circle gets killed.

---

## What changed in Phase 2A

**Before:** agents could only "think" with whatever you fed them. The prompt was the universe.

**After:** agents can **look things up**. Same job descriptions, same approval gates — they just have phones now.

The day-to-day difference:
- "What's our current scan volume?" — used to require you to paste the number; now Sam calls `read_internal_api stats/weekly` herself.
- "Brief me on the latest critical findings" — used to require you to paste finding data; now Maya calls `findings/recent` and `web_fetch` for any referenced CVE pages.
- "What did the last release change?" — Rob now calls `git_read log` and `read_repo_file` for the changelog instead of guessing.

---

## Where everything actually lives (technical reference)

### On disk in the repo

- **Agent personalities:** `backend/app/agents/profiles/<name>/agent.md` — six files, one per agent.
- **Tool implementations:** `backend/app/agents/tools/*.py` — internal_api, web, repo, github.
- **Runtime:** `backend/app/agents/runtime.py` — the multi-turn loop.
- **Skills:** `backend/app/agents/skills/*.py` — currently just `weekly_summary.py`.
- **Approval logic:** `backend/app/agents/approvals.py`.
- **Memory:** `backend/app/agents/memory.py`.
- **Internal API:** `backend/app/agents/internal_routes.py` + `internal_queries.py`.
- **Admin routes:** `backend/app/agents/routes.py` (gated by `require_root_admin`).
- **Admin UI:** `frontend/app/(admin)/admin/agents/...`.

### In the Postgres database

| Table | What's in it |
|---|---|
| `agent_memory` | Each agent's notebook (per-agent rows) |
| `team_memory` | Shared whiteboard (8 universal facts) |
| `agent_thread` | One row per conversation |
| `agent_message` | One row per message (user, assistant, or tool call/result) |
| `agent_run` | One row per agent invocation — status, cost, duration |
| `agent_task` | Sam's internal task list |
| `pending_action` | Approval queue |
| `api_key` (with `kind='agent'`) | Each agent's bearer token for `/api/internal/...` |
| `audit_log` (with `category='agent'`) | Every internal API call agents make |

### In environment variables

| Variable | What it's for |
|---|---|
| `ANTHROPIC_API_KEY_AGENTS` | Calling Claude (the LLM) |
| `RESEND_API_KEY` (or `RESEND_TOKEN_AGENTS`) | Sending digest emails |
| `GITHUB_TOKEN_AGENTS` | GitHub REST API access for Rob and Aisha |
| `NANOEASM_API_KEY_AGENTS_FOUNDER_OPS` | Sam's bearer key for `/api/internal/...` |
| `FOUNDER_EMAIL` | Who receives the weekly digest |
| `AGENTS_FROM_EMAIL` | The sender address (must be Resend-verified) |
| `INTERNAL_API_BASE` | Where the agent platform calls itself (default `http://easm-backend:5000`) |

### In docker-compose.yml

- The `easm-backend` service has `volumes: - ${HOST_REPO_PATH:-./}:/repo:ro` — that's the read-only bind-mount that makes `git_read` and `read_repo_file` work inside the container.
- The same service's `environment:` block lists every env var the container can see (the runtime can't read host env vars unless they're listed here).

### Admin access

The `/admin/agents` area is gated by `require_root_admin` — a stricter tier than the rest of `/admin/*` (which uses `require_superadmin`). Reason: the agent platform spends Anthropic credits and can produce customer-facing drafts. The 404 response for non-root-admins is opaque — they can't even tell the section exists.

Grant root admin via Flask CLI on the server:
```bash
docker compose exec easm-backend flask grant-root-admin your@email.com
```

---

## What's coming next (Phase 2B, not built yet)

- **Write tools**: agents can propose pull requests, draft emails for the send service, and write to their own memory through tools (still approval-gated)
- **Tuesday + Wednesday briefs**: Ava's `competitor-pulse` and Maya's `weekly-finding-brief`
- **Memory hygiene job**: weekly cleanup of stale/expired memory rows
- **Customer-facing send service**: actually sends John's drafts to customers after approval
- **Agent-to-agent hand-offs**: Sam can delegate to Rob, Rob's output flows back to Sam — durable queue + workflow

When you're ready, the brainstorming-then-spec-then-plan workflow we used for Phase 1 and 2A picks up the same way.
