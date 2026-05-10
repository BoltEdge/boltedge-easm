# Internal Agent Platform — Design

**Date:** 2026-05-10
**Status:** Draft (pending user review)

## Goal

Build an internal multi-agent operations platform that gives the Nano EASM solo founder leverage across engineering, QA, security analysis, market intelligence, customer-facing communications, and founder operations — without ceding control of any decision that affects production, customers, pricing, infrastructure, or legal posture.

The platform is **operational scaffolding for the founder**, not an autonomous business actor. Agents draft, research, summarise, review, and propose. The founder approves anything externally visible.

## Scope

### In scope

- A dedicated agent-ops platform on the **parent company site** (separate hosting, separate Postgres, separate secrets, separate auth from Nano EASM).
- An admin UI at `/admin/agents` on the parent site for profiles, threads, recent runs, approval queue, memory viewer.
- Six agent identities (Engineer, QA, Security Analyst, Strategy, Voice, Founder Ops) with skills underneath.
- Per-agent isolated memory + a small shared `team_memory` namespace; approval-gated writes.
- A strict approval queue covering memory writes, externally-visible outputs, code PRs, and integration writes.
- Manual invocation + scheduled (cron) runs at launch.
- A small read-only `/api/internal/...` surface on Nano EASM, served on `internal.nanoeasm.com` behind Cloudflare Access.
- Cost budgets and runtime caps per agent.

### Out of scope (deferred to later phases)

- Agent-to-agent hand-offs (queue, allowlists, chained workflows) — Phase 2.
- Event-driven webhook triggers (critical-finding alerts, support-reply drafts) — Phase 2.
- Multi-agent threads where one agent invites another mid-conversation — Phase 3+.
- Vector / semantic memory retrieval — Phase 3+ if memory grows past flat retrieval.
- Workflow editor UI — Phase 3+.
- Multi-user auth on the agent platform — when the team grows past one operator.
- Replacing the Claude Code session as the primary place the founder writes/reviews code. The agent platform complements Claude Code, it does not replace it.

### Non-goals

- The platform must never make production changes to Nano EASM, send messages to customers, or commit funds without explicit founder approval. There is no "trusted agent that bypasses approvals."
- The platform is not a Nano EASM product feature. It is internal tooling and must remain so.

## Architecture

### Hosting and isolation

The platform runs on the **parent company site** infrastructure, fully isolated from Nano EASM at the operational level:

- Separate Postgres instance (not a shared DB with a different schema).
- Separate environment / secrets store.
- Separate auth and session domain.
- Separate API keys for every external service the agents touch (Anthropic, GitHub, GitLab, Resend, etc.). **Never reuse Nano EASM's keys.**

This separation is load-bearing: a compromise of one system must not pivot into the other, and a Nano EASM schema change must not silently break agents.

### Network topology

```
┌─────────────────────────────────────────────────────────────────┐
│  Parent company site (isolated infra)                           │
│                                                                 │
│  ┌──────────────────────────┐   ┌─────────────────────────────┐ │
│  │ Admin UI (/admin/agents) │   │ Backend                     │ │
│  │  - Agent profiles        │   │  - Agent runtime            │ │
│  │  - "Run now" button      │◄──┤  - Approval queue           │ │
│  │  - Threads view          │   │  - Scheduler (cron)         │ │
│  │  - Approval queue        │   │  - Postgres (separate)      │ │
│  │  - Memory viewer         │   │  - Cost / budget enforce    │ │
│  │  - Recent runs / costs   │   │                             │ │
│  └──────────────────────────┘   └─────────────────────────────┘ │
│                                       │                         │
│                                       │ CF Access Service Token │
│                                       │  + bearer API key       │
│                                       ▼                         │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       │ HTTPS
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│  internal.nanoeasm.com  (Cloudflare Access in front)            │
│                                                                 │
│  Read-only /api/internal/... endpoints, scoped per agent:       │
│   - GET /stats/weekly                                           │
│   - GET /findings/recent                                        │
│   - GET /contact-requests/recent                                │
│   - GET /audit-log/recent                                       │
│   - GET /scans/recent                                           │
└─────────────────────────────────────────────────────────────────┘

Outputs from agents → admin UI (drafts, threads, weekly digests).
The platform's send service holds the Resend token; it sends:
  • weekly-brief digests (auto, internal-only, recipient = founder)
  • approved customer-facing drafts (only after explicit founder approval)
No agent holds a Resend token directly.
```

### Cloudflare Access setup

`internal.nanoeasm.com` is fronted by Cloudflare Access:

- One Access application covers the whole subdomain.
- Two policies on that application:
  1. **User policy** — allows the founder's email (OTP / SSO).
  2. **Service Token policy** — allows the agent platform's machine identity. Cloudflare issues `CF-Access-Client-Id` + `CF-Access-Client-Secret`; both are required headers on every agent → Nano EASM call.
- Application-layer auth (a bearer API key per agent) sits **on top of** Cloudflare Access. CF Access answers "who can reach the endpoint?", the bearer key answers "what can they do once they reach it?". Both are required.
- Each agent's bearer key is scoped (e.g. `read:findings`, `read:stats`) and audit-logged on the Nano EASM side via the existing audit log infrastructure.

### Internal API surface (Nano EASM side)

A new `/api/internal/...` blueprint on Nano EASM, mounted only on a vhost that resolves to `internal.nanoeasm.com`. Initial endpoints (read-only):

| Endpoint | Purpose | Consumed by |
|---|---|---|
| `GET /api/internal/stats/weekly` | Org count, signups, scan totals, plan mix | Founder Ops |
| `GET /api/internal/findings/recent?severity=&since=` | Recent findings (no PII) | Security Analyst |
| `GET /api/internal/contact-requests/recent` | Trial requests, sales enquiries | Voice, Founder Ops |
| `GET /api/internal/audit-log/recent?category=` | Recent audit-log entries | Founder Ops |
| `GET /api/internal/scans/recent` | Active + recent scan jobs | Security Analyst, Founder Ops |

These are scoped read endpoints. **No internal-API write endpoints in Phase 1.** Any future write surface must be added with an explicit per-agent scope and an audit-log entry on every call.

## Agent roster

Each agent's identity lives in `agents/<name>/agent.md` in the agent-platform repo, version-controlled. The file declares: name, role, system prompt, allowed tools, allowed secrets, hand-off allowlists, default cost cap, and external-write flag.

| # | Agent | Owns | Default tools | Key secrets | External writes |
|---|---|---|---|---|---|
| 1 | **Engineer** | Code, infra, migrations, debugging, dependency management | git read, web fetch, Nano EASM read API, GitHub API (read + PR-create) | `GITHUB_TOKEN_AGENTS`, `NANOEASM_API_KEY_RO` | Drafts only — opens PRs, never merges |
| 2 | **QA** | Feature/regression testing, release readiness | git read, test runner (staging only), Nano EASM read API | `NANOEASM_API_KEY_RO` | None |
| 3 | **Security Analyst** | Findings review, severity reasoning, remediation guidance, threat intel | Nano EASM read API, web fetch (NVD, MITRE ATT&CK, CISA, exploit-db) | `NANOEASM_API_KEY_RO` | None |
| 4 | **Strategy** | Market intel, competitor monitoring, positioning, sales messaging, partnership ideas | Web fetch, Anthropic web search, Nano EASM aggregate stats | `NANOEASM_API_KEY_STATS_RO` | None |
| 5 | **Voice** | All written + visual customer-facing output, support replies, marketing copy, legal-copy review | Nano EASM read API, web fetch | `NANOEASM_API_KEY_RO` | None — Voice never sends. Drafts land in the approval queue; the platform's send service sends after approval. |
| 6 | **Founder Ops** | Task tracking, weekly summaries, launch checklists, priority management | Nano EASM read API, internal `agent_task` table, web fetch | `NANOEASM_API_KEY_RO` | Writes to `agent_task` only (internal, never customer-visible) |

### Skills underneath each agent

Skills are the unit of repeatable work. Each skill is a `agents/<name>/skills/<skill>.md` file that contains a focused workflow checklist for one task type. Initial skill set:

**Engineer**
- `review-pr` — review a diff against project conventions and security checklist
- `audit-migration` — sanity-check a Flask-Migrate migration before applying
- `debug-prod-issue` — structured trace from symptom → log → suspected cause
- `dependency-audit` — review `package.json` / `requirements.txt` for stale or risky deps
- `security-aware-recommendation` — flag insecure patterns when proposing changes

**QA**
- `release-readiness-check` — run the standard pre-release checklist on a branch
- `feature-test-plan` — generate a test plan from a feature description / spec
- `bug-reproduce` — turn a vague bug report into a reproducible scenario
- `ui-ux-review` — review UI changes against the project's existing patterns

**Security Analyst**
- `explain-finding` — turn a raw finding into a customer-readable explanation
- `severity-assessment` — re-evaluate severity with current threat-intel context
- `weekly-finding-brief` — top findings from the week with themes
- `threat-intel-roundup` — recent CVE/threat news relevant to assets we scan

**Strategy**
- `competitor-pulse` — weekly snapshot of competitor moves (pricing, features, content)
- `positioning-review` — sanity-check a positioning statement against market state
- `sales-talking-points` — generate talking points for a specific prospect type
- `partnership-outreach` — draft a partnership-pitch email
- `msp-mssp-analysis` — analyse a specific MSP/MSSP segment for fit

**Voice**
- `blog-post` — draft a blog post in the brand voice
- `release-notes` — turn a code diff + feature description into release notes
- `support-reply` — draft a support reply with org context
- `social-post` — short-form post for LinkedIn / X
- `legal-copy-review` — sanity-check legal/policy copy for tone + clarity (not legal advice)
- `image-prompt` — generate prompts for product / marketing images

**Founder Ops**
- `weekly-summary` — Monday digest of last-week activity from Nano EASM stats + audit log
- `launch-checklist` — generate or update a launch checklist
- `task-triage` — categorise incoming items by urgency / owner-agent
- `priority-matrix` — re-rank current task list against stated priorities
- `agent-handoff` — draft a structured hand-off payload from one agent to another (Phase 2)

New tasks → either fit an existing skill or you write a new skill and assign it to whichever agent should own it. Skills should not be shared across agents (different voices, different memory contexts).

## Memory model

### Storage tiers

| Layer | Storage | Scope | Edited by |
|---|---|---|---|
| **Identity** | `agents/<name>/agent.md` (repo) | Per-agent | Founder, in editor |
| **`agent_memory`** (operational facts) | Postgres | Per-agent isolated | Agent (approval-gated) + founder |
| **`team_memory`** (universal facts) | Postgres | All agents read | Founder only (~10–30 facts) |
| **`agent_thread` / `agent_message`** | Postgres | Per-thread | Auto, append-only |
| **`agent_run`** (execution trace) | Postgres or Langfuse | Per-run | Auto, immutable |

### Schema sketch

```sql
-- per-agent operational memory
CREATE TABLE agent_memory (
    id            BIGSERIAL PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    key           TEXT NOT NULL,
    value         JSONB NOT NULL,
    tags          TEXT[] NOT NULL DEFAULT '{}',
    source        TEXT NOT NULL,                 -- user-told | inferred-from-thread | api-fetched
    confidence    NUMERIC(3,2) NOT NULL DEFAULT 1.00,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,                   -- default 90d for operational facts
    superseded_by BIGINT REFERENCES agent_memory(id),
    UNIQUE (agent_id, key)
);
CREATE INDEX ON agent_memory USING GIN (tags);
CREATE INDEX ON agent_memory (agent_id, expires_at);

-- universal facts visible to all agents
CREATE TABLE team_memory (
    id          BIGSERIAL PRIMARY KEY,
    key         TEXT NOT NULL UNIQUE,
    value       JSONB NOT NULL,
    tags        TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- threads + messages
CREATE TABLE agent_thread (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    title       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived_at TIMESTAMPTZ
);
CREATE TABLE agent_message (
    id           BIGSERIAL PRIMARY KEY,
    thread_id    BIGINT NOT NULL REFERENCES agent_thread(id),
    role         TEXT NOT NULL,                  -- user | assistant | tool
    content      JSONB NOT NULL,
    tokens_used  INTEGER,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- immutable run trace (or use Langfuse and skip this table)
CREATE TABLE agent_run (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    skill       TEXT,
    thread_id   BIGINT REFERENCES agent_thread(id),
    input       JSONB NOT NULL,
    output      JSONB,
    tool_calls  JSONB,
    status      TEXT NOT NULL,                   -- success | failed | timeout | over-budget
    cost_usd    NUMERIC(8,4),
    duration_ms INTEGER,
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ
);

-- approval queue
CREATE TABLE pending_action (
    id            BIGSERIAL PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    skill         TEXT,
    action_type   TEXT NOT NULL,                 -- memory-write | external-output | code-pr | integration-write | nano-easm-write
    target        TEXT,                          -- memory key, file path, recipient, etc.
    payload       JSONB NOT NULL,
    rationale     TEXT,
    proposed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,          -- default proposed_at + 7d
    decided_at    TIMESTAMPTZ,
    decision      TEXT,                          -- approved | rejected | edited-and-approved | expired
    decided_by    TEXT,
    decision_note TEXT
);
```

### Retrieval strategy

At the start of every agent run:

1. Load identity from the agent's `.md` file (system prompt, voice rules, allowed tools).
2. Load all rows from `team_memory` (small, ~10–30 facts — fits in any prompt).
3. Load this agent's pinned memories (a designated subset, e.g. `tags @> ARRAY['pinned']`).
4. Query this agent's `agent_memory` for tag-matches relevant to the current task; cap at top-N by `(updated_at DESC, confidence DESC)`. N starts at 30 and is tuned later.
5. Load recent `agent_message` history if the run is part of an existing thread.
6. Inject the assembled context into the Anthropic API call.

Never dump the full pool. Tag-based retrieval keeps prompts short and signal high.

### Memory hygiene (weekly job)

- Expire any `agent_memory` row past `expires_at`.
- Surface low-confidence (< 0.6) and old (> 60 days, never retrieved) rows in a "review" queue for the founder to confirm/delete.
- Detect duplicate keys across `agent_memory` and prompt for merge.
- Generate a one-line summary for the founder of last week's memory churn.

## Permissions and approval gates

### Action categories

**Auto-allowed** (no approval needed):
- Reading data via scoped API keys (Nano EASM internal API, GitHub/GitLab via PAT, web fetch, public CVE / threat-intel databases).
- Producing internal-only artifacts (drafts, briefs, plans, summaries, test reports).
- Running tests in non-production environments.
- Writing to a temporary scratch namespace within `agent_memory` that auto-expires in 24 h if not promoted.
- Logging and tracing the agent's own runs.

**Approval-queued (strict at launch)** — every item lands in `pending_action` and waits for the founder:
- Promoting scratch memory to permanent `agent_memory` rows.
- Any write to `team_memory` (proposals from agents only; rare, the founder writes most of these directly).
- Externally-visible outputs: customer emails, support replies, social posts, blog publishes.
- Code PR opens (Engineer can draft and push to a branch; **merge stays human**).
- Outbound writes to integrations: Slack messages, Linear tickets, Jira issues.
- Any call to a Nano EASM write endpoint (none exist in Phase 1; this rule applies if any are added later).

**Hard-gated — never agent-initiated, always founder action**:
- Production deploys.
- DNS, certificate, infrastructure changes.
- Secrets management — rotating keys, adding env vars, changing scopes.
- Pricing, plan, commercial decisions.
- Legal / policy / terms changes.
- Granting access to anyone (impersonation, superadmin, API keys).
- Any action that incurs outbound spend (upgrading external services, etc.).

### Per-agent declaration

Each `agent.md` declares (frontmatter or YAML block):

```yaml
name: voice
allowed_tools:
  - read_internal_api
  - web_fetch
  - draft_email
  - draft_blog
secrets_allowed:
  - RESEND_DRAFT_TOKEN
  - NANOEASM_API_KEY_RO
external_writes: false
hand_off_to: [founder-ops, qa]   # Phase 2; ignored in Phase 1
hand_off_from: [strategy, security-analyst, founder-ops, qa, engineer]
cost_cap_monthly_usd: 50
runtime_cap_seconds: 300
tool_call_cap_per_run: 50
```

Centrally enforced at run-start: the platform loads only the declared secrets into the runtime, only the declared tools are wired in, and `external_writes: false` blocks any externally-emitting tool call regardless of skill behaviour.

### Approval queue UI

The admin dashboard exposes a queue view. Each pending item shows:

- Agent + skill that produced it
- Action type and target
- Full content / diff
- Rationale provided by the agent
- Proposed-at timestamp + expiry
- Three buttons: **Approve**, **Reject** (with reason — captured as agent feedback memory), **Edit and approve**

Other behaviours:

- Daily 8 am email digest of pending approvals (so nothing rots in the queue).
- Items expire 7 days after proposal with `decision = 'expired'` if not acted on.
- Bulk-approve buttons per agent and per action-type, used carefully (only for low-stakes classes in practice).
- Reject reasons are added to `agent_memory` for the proposing agent under tag `feedback:reject`, so the agent can learn from them on subsequent runs.

### Cost and runtime caps

- Per-agent `cost_cap_monthly_usd` enforced on every Anthropic call. Soft cap at 80 % emails the founder; hard cap blocks new runs.
- `runtime_cap_seconds` aborts a run that exceeds wall-time.
- `tool_call_cap_per_run` aborts a run that exceeds tool-call count (prevents runaway loops).
- All three are surfaced on each agent's profile page.

## Orchestration

Phase 1 scope is deliberately tight:

### Triggers

- **Manual** — any agent, any prompt, from the admin UI's "Run now" or directly from Claude Code via a thin CLI wrapper.
- **Scheduled (cron)** — three weekly briefs (timezone configured per-deployment, defaults to the founder's timezone):
  - **Monday 08:00** — Founder Ops `weekly-summary` → email digest
  - **Tuesday 08:00** — Strategy `competitor-pulse` → email digest
  - **Wednesday 08:00** — Security Analyst `weekly-finding-brief` → email digest

### Hand-offs, multi-agent threads, event-driven workflows

**Not in Phase 1.** The hand-off queue, allowlist enforcement, and durable workflow engine are deferred to Phase 2. Event-driven webhooks (critical-finding alerts, support-reply drafts) are also Phase 2. Multi-agent threads are Phase 3+.

This is the single biggest scope reduction: with hand-offs deferred, agents at launch run solo. They produce drafts that land in either the agent's thread or the approval queue. The founder is the connective tissue between agents until the workflow infra is justified by real recurring needs.

## Phased build plan

| Phase | Scope | Realistic effort |
|---|---|---|
| **1 — MVP** | 6 agent profiles + initial skill set, manual + scheduled runs, approval queue, memory tables, admin UI v1, Cloudflare Access setup, Nano EASM `/api/internal` read endpoints, cost/runtime caps | 2–3 weeks |
| **2 — Workflows** | Hand-off queue, hand-off allowlist enforcement, durable workflow engine (Inngest or Trigger.dev only if justified), event-driven webhooks (critical-finding, support-reply), corresponding new skills | 2 weeks |
| **3 — Polish** | Multi-agent threads, vector / semantic memory if memory grows past flat retrieval, workflow editor UI, cost dashboards, multi-user auth (when team grows) | 2 weeks |

**Total to "fully scalable": 6–7 weeks of real engineering.** Phase 1 alone is daily-usable; Phases 2–3 only get built when Phase 1 has proved leverage.

### Phase 1 checklist (high level)

- [ ] Provision Postgres on the parent company site (separate instance, not shared).
- [ ] Create agent-platform repo with `agents/<name>/agent.md` for all 6 agents and the initial skills.
- [ ] Build the run-an-agent backend endpoint: loads identity + memory + thread, calls Anthropic, streams response, persists to `agent_run` and `agent_message`.
- [ ] Build the approval queue model and UI (Approve / Reject / Edit-and-approve, daily digest email).
- [ ] Build the memory model (tables, retrieval, hygiene job).
- [ ] Build the admin UI v1: agent list, agent profile, recent runs, approval queue, memory viewer, "Run now".
- [ ] Stand up Cloudflare Access on `internal.nanoeasm.com`; create Service Token; document setup.
- [ ] Add `/api/internal/...` read blueprint on Nano EASM with the five Phase-1 endpoints, mounted only on the `internal.nanoeasm.com` vhost.
- [ ] Wire scheduler for the three weekly briefs.
- [ ] Provision separate Anthropic, GitHub, Resend keys for the agent platform; never reuse Nano EASM keys.
- [ ] Enforce per-agent cost / runtime / tool-call caps before any run starts.

## Open questions / decisions deferred to implementation

- **Workflow engine choice** (Phase 2): Inngest vs. Trigger.dev vs. Temporal vs. Postgres-backed queue. Decide when implementing Phase 2 with concrete workflow shapes in hand.
- **Run-trace storage**: in-house `agent_run` table vs. Langfuse self-hosted. If observability needs grow (token-level traces, prompt-version comparison), Langfuse pays back. Start with in-house.
- **Initial `team_memory` seed**: ~10–30 facts on day one. Candidates: brand rules ("never use BoltEdge"), SOC2/ISO claim discipline, no-community-framing rule, current product status (free upgrades), AUD pricing context, Nano EASM URL, founder approval gates, current quarter priorities. Will be drafted at the start of Phase 1.
- **`agent_task` shape**: a small internal task list for Founder Ops to write to (id, title, status, priority, agent_owner, due, created_at). Visible in the admin UI. Out of scope: integrating with Linear / Notion / Asana — that's Phase 2+ if needed.
- **Voice tone calibration**: the Voice agent's system prompt needs deliberate iteration in week 1–2. Plan to A/B prompt variations against past outputs the founder considers "on-tone".
- **Whether to use Claude Code subagents (`.claude/agents/`) for any of these.** Likely no — the agent platform is a separate runtime — but the Claude Code session itself remains where the founder writes/reviews code, and might benefit from one or two `.claude/agents/*.md` for in-session helpers (e.g. a `code-reviewer` subagent inside Claude Code). Out of scope for this spec.

## Risks

1. **Build cost vs. revenue tension.** 6–7 weeks of internal tooling competes with Nano EASM revenue work. Mitigation: ship Phase 1 only; defer Phases 2–3 until Phase 1 proves leverage. Be willing to abandon the platform if the leverage isn't there.

2. **Approval queue friction.** The approval queue is the gate that keeps the founder in control. There will be daily temptation to relax it. Mitigation: relaxation must be **per action class**, never "agent X is now trusted." Every relaxation needs a written rationale committed alongside the change.

3. **Voice consistency drift.** Voice is the most consequential agent — its tone shapes brand. Mitigation: review every draft for the first month even if otherwise auto-approvable; iterate the prompt deliberately; never bypass the queue for Voice outputs.

4. **Memory pollution.** Hallucinated "facts" promoted to `agent_memory` can corrupt future runs. Mitigation: approval-gated writes, weekly hygiene job, low-confidence review surface, every memory has a `source` field for audit.

5. **Scope creep on the agent platform itself.** It's a tool, not a product. Risk of building features for it that the founder doesn't actually use. Mitigation: every new feature must answer "which workflow that I run weekly does this support?" — speculative features are rejected.

6. **Cloudflare and Anthropic dependency.** Both are vendor concentrations. Mitigation: tolerate it; the alternative (self-hosting a zero-trust proxy + LLM) is not a reasonable trade for a solo founder.

7. **Cost runaway.** A misconfigured agent or runaway loop could burn Anthropic credits fast. Mitigation: per-agent monthly cap (hard), per-run wall-time + tool-call cap (hard), 80 % soft-cap email alert.

## Success criteria

The platform is judged successful if, at the end of three months of Phase 1 use:

- The founder runs at least one agent invocation per workday on average.
- The three weekly briefs are read (and acted on) at least 80 % of weeks.
- No agent action has caused a customer-visible incident, brand-voice slip, or unauthorised production change.
- The approval queue stays under 20 pending items at any time (otherwise it's not actually being used).
- Agent-platform spend (Anthropic + hosting) is < 5 % of Nano EASM monthly revenue.

If those bars aren't being met, the platform is over-engineered for actual leverage and should be trimmed or shelved before Phase 2 starts.
