# Agent Platform — Slack Integration (Design)

**Status:** Draft, awaiting implementation plan
**Date:** 2026-05-16
**Phase:** 2B-3 (after 2B-1 approval-queued PRs and 2B-2 memory CRUD tools)

## Summary

Bring the existing internal agent platform onto Slack. Two private channels in the founder's workspace:

- **#nano-broadcast** — outbound-only. Scheduled briefs (Mon/Tue/Wed), approval-pending pings, run-completion summaries.
- **#nano-chat** — bidirectional, threaded. Founder talks to agents via `@nano <persona>` addressing; Sam can pull other agents into his threads.

Single Slack app ("Nano Agents") with one bot identity that posts under per-agent persona names + avatars using `chat:write.customize`. Founder-only — all events from non-founder Slack users are silently ignored.

Slack threads live on Slack — no DB mirror, no cost rollup into the existing `/admin/agents` dashboard. Approvals queued from Slack runs still flow through the existing `/admin/agents/approvals` queue and require a click-through to the web UI to approve.

## Goals

1. Mobile/anywhere access to the agent platform without opening the laptop.
2. "Team feel" — ambient visibility of what the agents are doing, named avatars on every message.
3. Push notifications — broadcast channel surfaces things that need attention (approvals, briefs, completions).

## Non-goals

- Slack-side approval buttons. Approvals are link-only — review and decide in the web UI.
- Per-agent Slack apps (six separate identities). Defer until "team feel" of approach A proves inadequate in practice.
- Unified thread store. Slack threads don't write to `agent_thread` rows; the web UI is unaware of Slack-initiated conversations.
- Slash commands or app-home view.
- Customer-facing Slack — this is founder-only ops tooling; the existing `app/integrations/` Slack webhook (for findings) is unrelated and untouched.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       Slack workspace                       │
│                                                             │
│   #nano-broadcast  (outbound only)                          │
│   #nano-chat       (threaded, bidirectional)                │
│                                                             │
│            └── @nano  ◄── single bot identity               │
│                            posts as Sam/Rob/… via           │
│                            chat:write.customize             │
└────────────────┬──────────────────────┬─────────────────────┘
                 │                      │
        Events API                  Web API
        (inbound POST)              (outbound POST)
                 │                      ▲
                 ▼                      │
┌────────────────────────────────────────────────────────────┐
│                      Nano EASM backend                     │
│                                                            │
│   POST /api/integrations/slack/events                      │
│        ├── verify signing-secret + replay window           │
│        ├── verify event.user == FOUNDER_SLACK_USER_ID      │
│        ├── ack within 3s (return 200)                      │
│        └── enqueue async run                               │
│                                                            │
│   backend/app/agents/slack/                                │
│        ├── router.py     — parse persona prefix            │
│        ├── client.py     — chat.postMessage helpers        │
│        ├── publisher.py  — outbound dispatchers            │
│        └── events.py     — inbound handler + ack           │
│                                                            │
│   Hooks into existing systems:                             │
│        • runtime.run_agent()    — same path as web UI      │
│        • approvals queue        — broadcast on enqueue     │
│        • scheduled briefs       — mirror email → broadcast │
└────────────────────────────────────────────────────────────┘
```

### Key choices

- **One Slack app, persona-prefix routing.** Single bot user `@nano`. Inbound: first word after `@nano` (`sam`, `rob`, `aisha`, `maya`, `ava`, `john`, case-insensitive) selects the agent; no prefix defaults to Sam. Outbound: `chat:write.customize` lets one bot post under different `username` + `icon_url` per message, so replies appear from "Sam", "Rob", etc.
- **Ack-fast, run-async.** Slack requires HTTP 200 within 3 seconds. The event handler verifies + enqueues + returns 200; a background thread runs the agent and posts the reply via Web API. Same pattern as the existing audit-webhook forwarder.
- **In-process LRU for thread ownership.** A thread's "owner agent" is cached in memory (`{slack_ts: agent_id}`, ~512 entries) so mid-thread replies without re-addressing go to the right agent. Eviction = fallback to Sam. No DB table.
- **Sam-only delegation.** Only the founder-ops profile can re-address inside a thread (`@nano rob, ...`). Other agents in their own threads respond directly to the founder; they cannot pull peers in.
- **Slack lives on Slack.** Thread history is fetched fresh from Slack via `conversations.replies` on each new message and rebuilt into runtime context. No `agent_thread` row, no dashboard rollup. Cost is still written to the standard `audit_log` / agent-run records — just not surfaced as Slack-specific.

## Components

### New files under `backend/app/agents/slack/`

| File | Purpose |
|---|---|
| `__init__.py` | Blueprint export. |
| `events.py` | Flask route `POST /api/integrations/slack/events`. Handles URL verification, signing-secret check, founder/channel checks, ack-fast, enqueue. |
| `router.py` | `parse_message(text) -> (agent_id, cleaned_text)`. Strips `<@U_NANO>`, parses persona prefix, falls back to founder-ops. |
| `client.py` | Thin wrapper around Slack Web API: `post_as_agent(channel, agent_id, text, thread_ts=None)`. Per-agent `username`/`icon_url` lookup. |
| `publisher.py` | High-level outbound dispatch: `broadcast_brief()`, `broadcast_approval_pending()`, `broadcast_run_completed()`. |
| `thread_owner.py` | In-memory LRU mapping `slack_thread_ts → agent_id` (~512 entries). Falls back to founder-ops when missing. |
| `signing.py` | `verify_signature(headers, raw_body)` — HMAC-SHA256 per Slack docs, 5-minute replay window. |

### Profile config additions

Each `backend/app/agents/profiles/<name>/agent.md` frontmatter gets two new fields:

```yaml
slack_display_name: "Sam"
slack_icon_url: "https://nanoeasm.com/agents/sam.png"
```

Six static avatars committed under `frontend/public/agents/{sam,rob,aisha,maya,ava,john}.png`. Served by the existing Next.js static handler — no new endpoint.

### Environment variables

Added under the existing `_AGENTS` namespace (CLAUDE.md rule: agent secrets are namespaced and never reuse customer-facing keys).

```
SLACK_BOT_TOKEN_AGENTS=xoxb-...      # scopes: chat:write, chat:write.customize,
                                     # app_mentions:read, channels:history,
                                     # channels:read, links:read
SLACK_SIGNING_SECRET_AGENTS=...
SLACK_BROADCAST_CHANNEL_ID=C0...     # #nano-broadcast
SLACK_CHAT_CHANNEL_ID=C0...          # #nano-chat
FOUNDER_SLACK_USER_ID=U0...          # only this user's events are processed
```

When any of these are unset, the Slack integration is a no-op — inbound endpoint 404s, outbound publishers log + skip. Local dev works without a Slack workspace.

### Edits to existing code

Minimal — the Slack module mostly bolts on at the seams.

| File | Edit |
|---|---|
| `app/agents/approvals.py` | After `pending_action` insert, fire `publisher.broadcast_approval_pending(action)`. |
| `app/agents/routes.py` (manual-run completion) | After run completes, fire `publisher.broadcast_run_completed(run)`. |
| `app/agents/skills/weekly_summary.py`, `…/competitor_pulse.py`, `…/weekly_finding_brief.py` | After email send (each `run_*(send=True)` function), fire `publisher.broadcast_brief(...)`. Email path unchanged — Slack is additive. Scheduler at `app/scheduler.py` is untouched. |
| `app/__init__.py` | Register the new `agents.slack` blueprint. |

Out of scope: no DB tables, no `pending_action` for outbound posts, no Slack-side approval UI.

## Data flow

### Flow 1 — Inbound message in #nano-chat

```
1. Founder types in Slack:
     "@nano rob, can you look at the agent-platform module and propose a refactor?"

2. Slack POSTs to https://nanoeasm.com/api/integrations/slack/events
   { type: "event_callback",
     event: { type: "app_mention", text: "<@U_NANO> rob, can you ...",
              user: "U_FOUNDER", channel: "C_CHAT", ts: "1715890000.123",
              thread_ts: null } }

3. events.py:
   a. verify X-Slack-Signature (HMAC-SHA256, 5-min replay window)
   b. handle url_verification challenge if present
   c. dedupe by event_id (in-memory LRU, ~1000 entries)
   d. if event.user != FOUNDER_SLACK_USER_ID → return 200 silently
   e. if event.channel != SLACK_CHAT_CHANNEL_ID → return 200 silently
   f. enqueue background job, return 200 within 50ms

4. Background thread:
   a. router.parse_message("<@U_NANO> rob, can you ...")
        → strip <@U_NANO>, parse "rob," prefix
        → (agent_id="engineer", cleaned="can you look at ...")
   b. thread_owner.set(ts="1715890000.123", agent_id="engineer")
   c. Optional ack: client.post_as_agent(channel=C_CHAT, agent_id="engineer",
                                         text="On it.", thread_ts="1715890000.123")
   d. Run agent: runtime.run_agent(
        agent_id="engineer",
        prompt="can you look at the agent-platform module and propose a refactor?",
        context={"source": "slack", "thread_ts": "1715890000.123"})
   e. Stream final assistant text → client.post_as_agent(..., text=reply, thread_ts=...)
   f. If tool calls queued for approval, the run continues and the approval-pending
      publisher fires into #nano-broadcast separately (Flow 3).

5. Founder replies in the SAME thread (no @nano):
   - event_callback again, type "message" with thread_ts set
   - router checks: thread_ts present → look up thread_owner[thread_ts] → "engineer"
   - runtime continues conversation using rebuilt context from conversations.replies
```

**Sam-only re-addressing.** If the thread owner is `founder-ops` and the cleaned message contains a re-address (`@nano rob, ...`), the next turn runs as Rob but the thread record still points to Sam. Other agents never re-address.

### Flow 2 — Outbound scheduled brief

```
app/agents/skills/weekly_summary.run_weekly_summary(send=True)
   ├── email via Resend (existing, unchanged)
   └── publisher.broadcast_brief(
          agent_id="founder-ops",
          subject="Weekly summary — week of ...",
          body=brief_text)
       └── client.post_as_agent(
              channel=SLACK_BROADCAST_CHANNEL_ID,
              agent_id="founder-ops",
              text=formatted_brief)

(Same pattern for competitor_pulse.py → strategy / Ava, and
 weekly_finding_brief.py → security-analyst / Maya.)
```

**Format.** Slack-friendly summary: title + first ~6 lines + a "Full brief in email" footer. If the full body is under 3000 characters it goes in one message; longer briefs are chunked across messages in the same thread (initial post, then `thread_ts`-linked follow-ups).

### Flow 3 — Approval-pending ping

```
approvals.queue_action(action_type, payload)
   ├── INSERT pending_action row (existing)
   └── publisher.broadcast_approval_pending(action)
       └── client.post_as_agent(
              channel=SLACK_BROADCAST_CHANNEL_ID,
              agent_id=action.agent_id,
              text="Proposed: <title>. Review: https://nanoeasm.com/admin/agents/approvals/<id>")
```

One-line message with the proposing agent's avatar + link. No buttons.

### Two non-obvious details

1. **Thread continuation is stateless.** Each new Slack message fetches the full thread via `conversations.replies` and rebuilds context for the runtime. Costs one Slack API call per reply but avoids a thread-state DB column. Acceptable at expected volume (human-paced, founder-only).

2. **Optional ack message ("On it.").** The 3-second Slack window is for the HTTP ack only, but tool-using agent runs take 30–90s. Posting a quick "On it." after enqueue makes the UX feel responsive. Per-profile toggle: `slack_send_ack: true` (default) in agent.md frontmatter.

## Error handling

### Layer 1 — Slack-side errors (network, 4xx, 5xx)

- `client.post_as_agent()` wraps every `chat.postMessage` in try/except. On failure: log channel + agent_id + truncated text, do not retry, do not raise. Slack posting must never break an agent run.
- No retries in v1. Volume is low enough that drop-on-failure is acceptable; retries would add dedupe complexity.
- Slack rate limits: ~1 message/sec/channel. Briefs are 3/week, approvals are a few/day, chat is human-paced — well under the limit. If a 429 ever happens, log and drop; the email path still delivers briefs.

### Layer 2 — Inbound signature / auth failures

| Failure | Response |
|---|---|
| Bad/missing `X-Slack-Signature` | `403` + log |
| Timestamp outside 5-min window | `403` + log |
| `event.user != FOUNDER_SLACK_USER_ID` | `200` silent (don't reveal we're listening) |
| `event.channel` not in allowlist | `200` silent (bot may be in other channels for visibility) |
| Duplicate `event_id` | `200` silent (Slack retries on slow ack; dedupe protects double-runs) |

Silent 200 on auth-failure is deliberate — a probe shouldn't learn this endpoint exists.

### Layer 3 — Agent runtime errors

- Runtime exceptions propagate as-is and are caught at the Slack background-thread boundary. Slack posts a one-line failure: *"Hit a problem mid-run. Check /admin/agents for details."* with the persona avatar.
- The full error goes to `audit_log` + agent_run record. Slack just signals "look elsewhere".
- Budget cap reached: same one-line message, no auto-retry.

### Edge case — lost thread context

If `conversations.replies` fails when rebuilding a continuation's context, post: *"Lost the thread context. Start a fresh message?"* and skip the run. Rare but worth failing loudly rather than running with no context.

## Testing

### Unit tests (`backend/tests/agents/slack/`)

- `test_router.py` — persona prefix parsing: `@nano rob, hi` → engineer; `@nano hi` → founder-ops; case-insensitive; multiple-persona prefix rejected.
- `test_signing.py` — valid signature passes; tampered body fails; old timestamp fails; missing header fails.
- `test_events.py` — wrong user → 200 silent; wrong channel → 200 silent; duplicate event_id → 200 no enqueue; valid event → enqueues + 200.
- `test_thread_owner.py` — set/get; LRU eviction at cap; missing key → default agent.
- `test_publisher.py` — formatting of brief/approval/completion payloads. Mocks `client.post_as_agent`, asserts call shape.

### Integration smoke test

`tests/integration/test_slack_smoke.py`, gated by `RUN_SLACK_SMOKE=1`. Posts a real test message into a private throwaway channel and verifies it lands with the right username + icon. Skipped in CI; run manually after Slack-app config changes.

### Manual smoke checklist (run after deploy)

1. Install Slack app in workspace, invite to both channels.
2. Send `@nano sam, hi` in #nano-chat → Sam avatar replies in-thread.
3. Reply in the same thread without `@nano` → Sam continues.
4. Send `@nano rob, propose a tiny no-op PR (e.g., add a comment to README)` → Rob avatar replies; approval ping lands in #nano-broadcast with link.
5. Trigger the Monday weekly summary manually → brief lands in #nano-broadcast with Sam avatar.
6. Send a message from a non-founder Slack user in the same channel → silent no-op.

### Not tested

- Slack's own behaviour (delivery, rendering).
- Rate-limit handling (volume too low to hit it).
- Long-thread context bloat — that's a runtime concern, not Slack-specific.

## Open questions / future work

- **Per-agent Slack identities (approach B).** If "team feel" of approach A proves thin, swap one app for six. Runtime stays the same; only Slack-app config changes.
- **Cost rollup for Slack runs.** Currently Slack runs incur cost but don't surface in the dashboard's per-agent spend chart. Could be added by writing `agent_thread` rows for Slack threads — defer until usage warrants it.
- **Approval buttons in Slack.** Deferred — link-only is safer for v1.
- **Memory hygiene job, send_email_draft tool, agent hand-off queue.** Tracked separately under Phase 2B-2+ (per CLAUDE.md), not part of this spec.

## Security and operational notes

- Inbound endpoint always validates signing secret. Reject (403) on bad sig, silent-200 on auth-mismatch.
- All Slack interactions are founder-only (`FOUNDER_SLACK_USER_ID` allowlist of one).
- All inbound runs write to `audit_log` with `category='agent'` (same as web-initiated runs).
- Outbound posts never include secrets, PII, or customer data unless the agent explicitly fetched it via existing read tools.
- Bot token rotation: rotate `SLACK_BOT_TOKEN_AGENTS` in the Slack admin panel + env var. No code change needed.
- When env vars are unset, the integration is fully no-op — local dev and existing deploys keep working unchanged.

## Hooks into existing constraints (CLAUDE.md)

- Agent secrets namespaced with `_AGENTS` suffix.
- Internal API seam preserved — Slack runs use the same `runtime.run_agent()` path, which goes through `/api/internal/...` to reach Nano EASM data.
- No agent can `git push` to master directly — approval-gated PRs still go through `/admin/agents/approvals` and the existing GitHub writer. Slack just announces.
- Don't propose net-new features unprompted during the agent platform observation phase — Slack is responsive to a direct request.
