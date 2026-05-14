# Agent Memory CRUD Tools — Design

**Status:** approved 2026-05-14
**Predecessors:** Phase 2B-1 (approval-queued PRs), Phase 1 (memory schema + approval queue)

## Goal

Let each agent propose memory writes/deletes through the approval queue, and read its own memory mid-run, via three new tools: `update_agent_memory`, `delete_agent_memory`, `read_agent_memory`. Reuses the existing memory tables, approval queue, and approval UI patterns established in Phase 1 and Phase 2B-1.

## Scope

- **In:** Three tools targeting each agent's OWN `agent_memory` only. Read is inline. Write and delete queue for the founder's approval. All 6 agents (Sam, Rob, Aisha, Maya, Ava, John) get the tools.
- **Out:** `team_memory` writes (still CLI-only — too high blast radius for v1). Cross-agent writes (agent X cannot write to agent Y's memory). Memory hygiene weekly job (separate scope). UI for managing memory outside the approval queue.

## Architecture

### Three tools, three approval semantics

The runtime decides `requires_approval` per tool, not per call. We therefore split CRUD across three tools rather than collapse into one.

| Tool | requires_approval | action_type | Effect |
|---|---|---|---|
| `update_agent_memory` | True | `memory-write` | Upsert into caller's agent_memory |
| `delete_agent_memory` | True | `memory-delete` (new) | Delete row by (agent_id, key) |
| `read_agent_memory` | False | — | Returns matching rows inline |

### Scope binding — calling agent only

The agent_id used for the write/delete/read is **always** the caller's own ID, taken from `profile.name` in the runtime when it queues the proposal. Tool inputs **do not** include an `agent_id` field — there's no way for the model to write to a different agent's memory by accident or design. Server-side enforcement.

### Approval-queued execution (write + delete)

Same Pattern A as `github_pr_create`:

1. Agent emits `tool_use` for `update_agent_memory` or `delete_agent_memory`
2. Runtime intercepts on `requires_approval=True`, creates `pending_action` row with the appropriate `action_type` and `agent_id=profile.name`
3. Returns `[queued for approval as pending_action #N]` to the agent as the tool result
4. Founder approves in `/admin/agents/approvals`
5. `_apply_action()` dispatches by `action_type`:
   - `memory-write` → existing executor (calls `write_memory(...)`) — already wired in Phase 1
   - `memory-delete` → new executor (deletes the row) — to be added
6. Result captured into `pending_action.applied_result`

### Read tool — inline, no approval

`read_agent_memory` is a normal read tool like `read_repo_file`. It executes synchronously in the runtime's tool-call loop, returns a JSON string to the agent, no `pending_action` row, no executor.

The handler implements:
- Calls `retrieve_for_agent(agent_id=profile.name, ...)` from the existing `memory.py`
- Result-capped to `result_cap_bytes` like other read tools
- Filter inputs: optional `key` (exact match), optional `tags` (list), optional `limit` (default 30, max 100)

## Components to build

### Backend

- **`backend/app/agents/tools/memory_tools.py`** (new) — three `ToolDef` registrations:
  - `update_agent_memory` — sentinel handler (write-class, runtime intercepts before handler), strict input schema for `key`/`value`/`tags`/optional fields
  - `delete_agent_memory` — sentinel handler, schema requires only `key`
  - `read_agent_memory` — real handler that calls `retrieve_for_agent` and serializes results to JSON
- **`backend/app/agents/approvals.py`** — extend `_apply_action()`:
  - Add `elif action_type == "memory-delete":` branch that deletes the row matching `(agent_id, target)`. Returns `{"deleted": True, "key": target}` for applied_result; `{"deleted": False, "reason": "not found"}` if no row matched (don't raise).
- **`backend/app/agents/tools/__init__.py`** — import the new module (so registrations fire).
- **`backend/app/agents/runtime.py`** — runtime needs to pass `profile.name` as agent_id when intercepting these tools. Already does this for `code-pr` via the same `propose_action(agent_id=profile.name, ...)` call; reusable.

### Profiles

Add `update_agent_memory`, `delete_agent_memory`, `read_agent_memory` to `allowed_tools` in all 6 profile files:
- `engineer/agent.md` (Rob)
- `qa/agent.md` (Aisha)
- `founder-ops/agent.md` (Sam)
- `security-analyst/agent.md` (Maya)
- `strategy/agent.md` (Ava)
- `voice/agent.md` (John)

Add a short paragraph to each profile body describing when to use them (varies slightly per persona — e.g., John remembers customer preferences, Maya remembers threat patterns).

### Frontend

- **`frontend/app/(admin)/admin/agents/approvals/ApprovalCard_MemoryWrite.tsx`** — extend to recognize both `memory-write` and `memory-delete`. The card layout is fine as-is; just changes the heading ("Memory write proposal" vs "Memory delete proposal") and the action button label.
- **`frontend/app/(admin)/admin/agents/approvals/page.tsx`** — dispatch already handles non-`code-pr` to `ApprovalCard_MemoryWrite`. After the card update both action types route through it.

### Tests

- `tests/test_agents_tools_memory_tools.py` (new) — 6 tests:
  - All three tools registered in `TOOL_REGISTRY`
  - `update_agent_memory` has `requires_approval=True`, `action_type='memory-write'`
  - `delete_agent_memory` has `requires_approval=True`, `action_type='memory-delete'`
  - `read_agent_memory` has `requires_approval=False`, idempotent
  - `read_agent_memory` handler returns matching rows for the caller's agent
  - `read_agent_memory` handler returns `[]` for an agent with no memory
- `tests/test_agents_approvals.py` (extend) — 2 tests:
  - Approving `memory-delete` action removes the row, applied_result contains `{deleted: True}`
  - Approving `memory-delete` for a non-existent key returns `{deleted: False, reason: "not found"}` (no exception)

## Tool input schemas

### update_agent_memory

```json
{
  "type": "object",
  "required": ["key", "value", "tags"],
  "properties": {
    "key": {"type": "string", "minLength": 1, "maxLength": 200,
            "description": "Stable identifier for this fact. Reuse the same key to update; choose new keys for new facts."},
    "value": {"type": "object",
              "description": "Free-form JSON object holding the fact. Use {rule: '...'} for rule-style facts; {n: 123, ...} for numeric facts."},
    "tags": {"type": "array", "items": {"type": "string"}, "minItems": 1,
             "description": "Filter tags. Used at retrieval time to scope what gets loaded. Common: topic:..., customer:..., source:meeting."},
    "source": {"type": "string", "default": "agent-observation",
               "description": "Where the fact came from. e.g., 'user-told', 'agent-observation', 'web-fetch'."},
    "confidence": {"type": "number", "minimum": 0, "maximum": 1, "default": 1.0},
    "expires_at": {"type": "string", "description": "ISO 8601 timestamp; null = never expires."}
  }
}
```

### delete_agent_memory

```json
{
  "type": "object",
  "required": ["key"],
  "properties": {
    "key": {"type": "string", "minLength": 1, "maxLength": 200}
  }
}
```

### read_agent_memory

```json
{
  "type": "object",
  "properties": {
    "key": {"type": "string", "description": "Exact key to fetch. Mutually exclusive with tags."},
    "tags": {"type": "array", "items": {"type": "string"},
             "description": "Filter by any-of these tags."},
    "limit": {"type": "integer", "default": 30, "minimum": 1, "maximum": 100}
  }
}
```

## Error handling

- Tool handlers for write/delete return the sentinel string (the runtime intercepts before reaching them).
- Read tool catches DB errors and returns `[read_agent_memory error: <type>: <message>]` — same pattern as other read tools.
- Approval executor for `memory-delete`: don't raise on missing key; record `{deleted: False, reason: "not found"}` in `applied_result` so the UI can surface it. Match the spirit of `approve()` already catching exceptions for code-pr.

## Migrations

**None required.** No schema changes. The `agent_memory` table already exists from Phase 1. The new `memory-delete` action_type is just a new string value in the existing `pending_action.action_type` text column.

## Build order

| Stage | Outcome |
|---|---|
| A | New tool file with 3 ToolDef registrations; tests for registration + read handler |
| B | Approvals executor extension for `memory-delete`; tests |
| C | Profile updates for all 6 agents |
| D | Frontend card extension for delete-action heading/button |
| E | Smoke test against prod: agent proposes a memory write, founder approves, retrieval surfaces the new fact |

## Out of scope (explicit)

- Renaming the existing `agent_memory` table or schema migration
- Team memory writes via tool (CLI-only for now)
- Bulk operations (write many keys at once)
- Audit log entries beyond what `_apply_action`'s logging already does
- UI for browsing/searching memory outside the approval queue
- Memory hygiene weekly job (deferred Phase 2B+)
- Renaming `github_pr_create` to a less alarming name (separate concern noted in 2B-1 post-ship memory)

## Success criteria

1. An agent (any of the 6) can call `update_agent_memory` with a small payload and the runtime queues a `pending_action`
2. The founder approves; the row appears in `agent_memory`
3. Subsequent runs of that agent show the fact in the system prompt (via existing `retrieve_for_agent` injection)
4. `delete_agent_memory` removes the row after approval; subsequent runs no longer show the fact
5. `read_agent_memory` returns the agent's memory rows inline, scoped to caller, no approval gate
6. CI green; no migration drift; all existing tests pass
