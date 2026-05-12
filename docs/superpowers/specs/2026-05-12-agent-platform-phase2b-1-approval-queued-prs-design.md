# Internal Agent Platform — Phase 2B-1: Approval-Queued PRs — Design

**Date:** 2026-05-12
**Status:** Draft (pending user review)
**Builds on:** `2026-05-10-internal-agent-platform-design.md` (Phase 1) and `2026-05-12-agent-platform-phase2a-tool-use-design.md` (Phase 2A).
**Decomposition note:** Phase 2B was originally specced as six independent features (write tools, approval-queued execution, hand-offs, memory hygiene, customer-facing send, CI). This spec covers the first sub-spec — CI + approval-queued runtime + `github_pr_create`. The remaining Phase 2B features (`send_email_draft`, hand-offs, memory hygiene, `update_agent_memory` tool) get their own sub-specs later.

## Goal

Enable Rob (Engineer) and Aisha (QA) to propose pull requests that are gated behind the existing approval queue, plus the CI hygiene work that must be in place before any agent PR is trustworthy. The founder reviews the proposed file content in the approval queue, clicks ✓, and a real PR opens on GitHub against `master` — ready for the founder to pull locally, test, and merge. The agent never touches production directly; the agent never even causes a PR to exist on GitHub until the founder has explicitly approved.

Success criterion: Rob can be asked *"fix the audit-log timeout, write tests first"*, produce a proposed PR that lands in `/admin/agents/approvals`, the founder can preview each file's full content inline, click ✓, and find a real PR open on GitHub against `master` within ~2 seconds, ready for `git pull` + local test + merge.

## Scope

### In scope

- **Task 0 — CI + branch protection.** GitHub Actions workflow that runs `pytest backend/tests/` on every PR and on pushes to `master`. Branch protection on `master` requiring the CI green check (founder configures via GitHub UI; this spec ships the workflow file).
- **Task 1 — Tool classification.** Extend `ToolDef` with `requires_approval: bool` (default `False`) and `action_type: str | None`. The existing six read-class tools stay `False` and continue executing inline.
- **Task 2 — Runtime capture-and-queue.** Modify `runtime.py`'s multi-turn loop: when an agent emits a `tool_use` for a `requires_approval=True` tool, the runtime does NOT call the handler. Instead it creates a `pending_action(action_type=<tool.action_type>, payload=<tool_use.input>)` row and returns a synthesized `[queued for approval as pending_action #<id>]` string as the tool result. The agent's run continues with that text — typically the model says *"I've proposed X, awaiting your approval"* and emits `end_turn`.
- **Task 3 — `github_pr_create` write tool.** Tool registered with `requires_approval=True`, `action_type='code-pr'`. Available to Rob and Aisha. Input is a structured payload: branch_name, base (default `master`), commit_message, files (list of `{path, content}` with **full new file content**), pr_title, pr_body.
- **Task 4 — Approval executor for `code-pr`.** Extend `approvals._apply_action()` to handle `code-pr`. On founder ✓, calls a new `github_writer.create_pr(payload)` function that creates the branch + commits files + opens a PR via the GitHub REST API. Result (PR URL or error) stored on the `pending_action` row in a new `applied_result` JSON column.
- **Task 5 — Approval queue UI v2 (L2 — click-to-expand file content).** Per-action-type rendering on the approvals page. Memory-write cards unchanged. Code-PR cards show pr_title, pr_body (rendered markdown), branch_name → base badge, and an accordion of files: each `{path, content}` collapsed by default with a line count; click expands to a full code block of the proposed content. Approve / Reject buttons; Edit-and-approve disabled for code-pr (too easy to break a multi-file proposal).
- **Task 6 — Profile updates.** Rob and Aisha get `github_pr_create` in their `allowed_tools`. System prompts updated to include the TDD-in-PR rule and the "proposal-then-wait" flow expectation.
- **Task 7 — End-to-end smoke + docs.** Manual test against a real repo. Update `CLAUDE.md` and `docs/agents.md` with the new tool, the new flow, and the new UI.

### Out of scope (deferred to later Phase 2B sub-specs)

- **Pattern B (suspend-and-resume runtime).** Single-step tool-use is enough for Rob's PR proposals. Multi-step agentic chains (e.g. open PR → wait → add a comment to the PR → wait → label it) need suspend-and-resume; that's a separate spec when we have a concrete workflow that needs it.
- **`send_email_draft` + customer-facing send service.** Separate sub-spec. John's customer-reply drafts continue to land as text-in-response in Phase 2B-1; the founder copy-pastes for now.
- **`update_agent_memory` write tool.** Memory writes today go through `propose_action` from skill code, not from inside an agent's own tool call. Adding agent-initiated memory writes is a small follow-up sub-spec.
- **Agent-to-agent hand-offs.** A separate sub-spec. Sam delegating to Rob mid-flight is not in this scope.
- **Memory hygiene weekly job.** Independent, ships any time as a tiny patch.
- **Inline diff rendering (L3 in the approval UI).** Defer to a polish iteration after L2 has been used for a while.
- **Replacing the founder's manual local-test step.** Rob proposes, the founder still pulls + tests + merges by hand. No automated post-CI merge.

### Non-goals

- The platform must never cause a code change to land on `master` without the founder's explicit click. CI is the safety net; founder merge is the gate. Branch protection enforces both.
- The platform must never `git push` to `master` from inside the container. Only the GitHub REST API on PR branches.
- No write capability for tools that aren't on the per-agent allowlist. Today only Rob and Aisha get `github_pr_create`; Sam, Maya, Ava, John do not. If a tool call from an agent without the capability hits the runtime, it's rejected at the existing allowlist check.

## Architecture

### Component overview

```
                          ┌────────────────────────────┐
                          │  Agent runtime              │
                          │  (run_agent loop)           │
                          └──────────┬──────────────────┘
                                     │
            Read-class tool          │     Write-class tool
            (web_fetch, git_read…)   │     (github_pr_create)
                                     │
                       ┌─────────────┴─────────────┐
                       │                           │
                       ▼                           ▼
              ┌─────────────────┐       ┌─────────────────────────┐
              │ Execute inline  │       │ Capture as pending_action│
              │ (Phase 2A)      │       │ Return [queued] to agent│
              └─────────────────┘       │ Agent finishes its run  │
                                        └────────────┬─────────────┘
                                                     │
                                       Founder reviews + clicks ✓
                                                     │
                                                     ▼
                                        ┌─────────────────────────┐
                                        │ Approval handler        │
                                        │ - Loads action payload  │
                                        │ - Calls write-tool      │
                                        │   executor inline       │
                                        │ - Records result on row │
                                        └────────────┬─────────────┘
                                                     │
                                                     ▼
                                           ┌───────────────────┐
                                           │ GitHub API        │
                                           │ (create branch +  │
                                           │  commit + PR)     │
                                           └───────────────────┘
```

### New components

1. **Tool classification** in `backend/app/agents/tools/__init__.py`. `ToolDef` gains two fields:

```python
@dataclasses.dataclass
class ToolDef:
    name: str
    description: str
    input_schema: dict
    handler: Callable
    idempotent: bool
    result_cap_bytes: int
    server_side_type: str | None = None
    requires_approval: bool = False            # NEW
    action_type: str | None = None             # NEW — only set when requires_approval=True
```

2. **Capture-and-queue branch** in `backend/app/agents/runtime.py`. Inside the existing multi-turn loop's tool-use handling:

```python
for tu in result.tool_uses:
    if tu["name"] not in TOOL_REGISTRY:
        # ...existing unknown-tool handling
        continue
    tool = TOOL_REGISTRY[tu["name"]]

    if tool.requires_approval:
        from .approvals import propose_action
        pending = propose_action(
            agent_id=profile.name,
            action_type=tool.action_type,
            target=tu["input"].get("pr_title") or tu["name"],
            payload=tu["input"],
            rationale=f"Tool call from run #{run.id}",
            skill=skill,
            run_id=run.id,
        )
        tool_output = (
            f"[queued for approval as pending_action #{pending.id}; "
            f"agent should wrap up its response without expecting "
            f"this to fire during the current run]"
        )
        is_error = False
    else:
        tool_output, is_error = _execute_tool(tu["name"], tu["input"])

    # ...rest of the tool-result append logic, unchanged
```

3. **Approval executor extension** in `backend/app/agents/approvals.py`. The existing `_apply_action()` function:

```python
def _apply_action(action_type: str, agent_id: str, target: str, payload: dict):
    if action_type == "memory-write":
        # ...existing path
    elif action_type == "code-pr":
        from .tools.github_writer import create_pr
        return create_pr(payload)
    else:
        raise NotImplementedError(...)
```

The `approve()` function captures the executor's return value into the `pending_action.applied_result` JSON column (new column).

4. **GitHub writer** at `backend/app/agents/tools/github_writer.py`:

```python
def create_pr(payload: dict) -> dict:
    """Called by approvals._apply_action when a code-pr is approved.

    Steps:
      1. Read GITHUB_TOKEN_AGENTS.
      2. Resolve repo slug from team_memory `github:repo_slug`.
      3. GET /repos/{slug}/git/ref/heads/{base} → get base SHA.
      4. POST /repos/{slug}/git/refs with {ref: 'refs/heads/<branch>',
         sha: <base SHA>} → create the new branch.
      5. For each file: PUT /repos/{slug}/contents/{path} with
         {message, content (base64), branch} → commits the file to the
         new branch.
      6. POST /repos/{slug}/pulls with {title, body, head, base} →
         opens the PR.
      7. Return {pr_url, pr_number, branch}.

    On any HTTP error, raise — the caller (approvals.approve) records
    the error in pending_action.applied_result and surfaces in the UI.
    """
```

5. **DB schema** — add `applied_result` JSON column to `pending_action`. Alembic migration chained off `q5g6h7i8j9k0`. Nullable; populated on approval execution.

### `github_pr_create` tool definition

| Field | Value |
|---|---|
| `name` | `github_pr_create` |
| `description` | Multi-line; emphasises: "queues for approval; nothing fires until founder ✓; ALWAYS include tests in the same PR as implementation; PR body must mention which tests cover the change." |
| `input_schema` | See below |
| `handler` | A sentinel that should never run (the runtime intercepts on `requires_approval=True`). If it does run for any reason, returns `[error: github_pr_create reached handler path; this should never happen]`. |
| `idempotent` | `False` |
| `result_cap_bytes` | `0` (agent only ever sees the synthesized `[queued]` string) |
| `requires_approval` | `True` |
| `action_type` | `'code-pr'` |

Input schema:

```json
{
  "type": "object",
  "required": ["branch_name", "commit_message", "files", "pr_title", "pr_body"],
  "properties": {
    "branch_name": {
      "type": "string",
      "pattern": "^[a-z][a-z0-9-/_]{1,80}$",
      "description": "Branch to create from base. Use kebab-case with an agent prefix, e.g. 'rob/fix-audit-log-timeout'."
    },
    "base": {
      "type": "string",
      "default": "master",
      "description": "Branch to fork from. Default 'master'."
    },
    "commit_message": {
      "type": "string",
      "minLength": 10,
      "maxLength": 500,
      "description": "Conventional commit format preferred (feat:, fix:, refactor:, etc.)."
    },
    "files": {
      "type": "array",
      "minItems": 1,
      "maxItems": 20,
      "items": {
        "type": "object",
        "required": ["path", "content"],
        "properties": {
          "path": {"type": "string"},
          "content": {"type": "string", "description": "Full new file content. For modifications, include the entire file."}
        }
      }
    },
    "pr_title": {"type": "string", "minLength": 10, "maxLength": 200},
    "pr_body": {
      "type": "string",
      "minLength": 50,
      "description": "Markdown. Must explicitly mention which tests cover the change."
    }
  }
}
```

Per-file content cap: 200 KB. Total payload cap: 1 MB. Validated at the runtime layer before persisting the pending_action.

## Approval queue UI changes (L2)

Backend: the existing `GET /admin/agents/approvals` endpoint adds an `action_type` field per row (already present in the DB; just surface it). Otherwise unchanged.

Frontend: per-action-type rendering at `frontend/app/(admin)/admin/agents/approvals/page.tsx`. Dispatches to one of two components:

- `<ApprovalCard_MemoryWrite>` — unchanged from Phase 1.
- `<ApprovalCard_CodePR>` — new. Renders:
  - `pr_title` as a heading
  - `pr_body` rendered as markdown
  - Small badge: `<branch_name> → <base>`
  - Files header with count
  - Accordion of files; collapsed by default. Each row shows path + line count (`53 lines`). Click → expands to a `<pre><code>` block of the full proposed content. Syntax highlighting if a markdown / code library is already in `package.json`; plain monospace otherwise.
  - Approve / Reject buttons; Edit-and-approve omitted.

After approval, the row updates to show the `applied_result`:
- Success: link to `pr_url` ("PR opened: github.com/.../pull/42")
- Failure: error string in red

`applied_result` is fetched on the same list endpoint. No additional API calls needed.

## CI + branch protection

### `.github/workflows/test.yml`

```yaml
name: tests
on:
  pull_request:
    branches: [master]
  push:
    branches: [master]
jobs:
  pytest:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_USER: easm_user
          POSTGRES_PASSWORD: testpass
          POSTGRES_DB: easm
        ports: ["5432:5432"]
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - run: pip install -r backend/requirements.txt
      - run: cd backend && pytest tests/ -v
        env:
          SQLALCHEMY_DATABASE_URI: postgresql://easm_user:testpass@localhost:5432/easm
          SECRET_KEY: test-secret
          CORS_ORIGINS: http://localhost:3000
```

Pre-existing budget-test failures (2 tests in `test_agents_budget.py` due to data pollution from prior smoke runs) must be either fixed or skipped before this lands, otherwise CI will be red from day one. Fix: scope the budget tests to the test's own agent_id (e.g. `f"budget-test-{uuid.uuid4()}"`) so they don't sum unrelated rows.

### Branch protection (founder configures manually)

Settings → Branches → Add rule for `master`:
- Require status checks to pass before merging
- Required: the `pytest` job from `tests` workflow
- (Optional) require pull request reviews — skip for solo founder

Once branch protection is on, **the agent platform's approval click cannot bypass CI**. Even an approved code-pr that opens a PR still needs CI green + founder merge click before reaching `master`.

## Profile updates

Both Rob and Aisha gain `github_pr_create` in `allowed_tools`:

`backend/app/agents/profiles/engineer/agent.md`:
```yaml
allowed_tools:
  - read_internal_api
  - web_fetch
  - web_search
  - git_read
  - github_query
  - read_repo_file
  - github_pr_create   # NEW
```

`backend/app/agents/profiles/qa/agent.md`:
```yaml
allowed_tools:
  - read_internal_api
  - web_fetch
  - git_read
  - github_query
  - read_repo_file
  - github_pr_create   # NEW
```

System prompt additions for both (appended to the existing "My tools:" section):

```
- `github_pr_create(branch_name, commit_message, files, pr_title, pr_body)` — propose a pull request. The proposal queues for the director's approval; nothing happens on GitHub until they ✓. ALWAYS include tests with implementation in the same PR — the PR body must explicitly name the test files and what they cover. If I can't think of a test, I say so in the PR body and let the director decide.
```

Hard rule (added to Rob's profile body):

```
- When I propose code changes, I follow TDD discipline in the PR itself:
  the failing test and the implementation that makes it pass go into the
  same proposal. PRs without tests get rejected; that's by design.
```

## Phased build order

| Stage | Outcome | Realistic effort |
|---|---|---|
| **0 — CI + branch-protection workflow** | `.github/workflows/test.yml` lands; budget test pollution fixed so CI is green from day one. Founder enables branch protection in GitHub UI. | ~half day |
| **1 — Tool classification** | `ToolDef` gains `requires_approval` + `action_type`. Existing tests still pass; no behavior change. | ~1-2 hours |
| **2 — Runtime capture-and-queue** | Multi-turn loop captures write-class tool calls as pending_action rows; returns `[queued]` to the agent. Test with a fake tool registered as `requires_approval=True`. | ~3-5 hours |
| **3 — `github_pr_create` tool registration** | Tool registered with the schema above. Rob/Aisha can now technically call it (proposals land in approval queue) — but the executor doesn't fire yet, so approvals will fail. | ~2 hours |
| **4 — Approval executor + `github_writer.create_pr()`** | Approving a code-pr row actually opens a real PR on GitHub. Includes the new `applied_result` column + Alembic migration. Smoke-tested against a real repo. | ~1-2 days |
| **5 — Approval queue UI v2 (L2)** | Per-action-type rendering; `ApprovalCard_CodePR` component with click-to-expand files; success/failure rendering on approved rows. | ~1-2 days |
| **6 — Profile updates + docs** | Rob and Aisha get the tool. System prompts updated. CLAUDE.md + docs/agents.md updated. | ~half day |
| **7 — End-to-end smoke** | Ask Rob to fix something small ("audit-log timeout" already done, pick something else); walk the full loop. Verify CI runs on the resulting PR. | ~half day |

**Total: ~2 weeks** of focused work.

## Open questions / decisions deferred to implementation

- **Test scope-fix for pre-existing budget tests.** Required before CI is meaningfully green. Approach: change the test agent_id to a per-test unique value so unrelated rows don't sum into the assertion. Decide exact pattern when writing the plan.
- **Syntax highlighting in approval queue file expansion.** If a code-block / markdown renderer is already in `package.json` (e.g., `react-syntax-highlighter`), use it. If not, plain monospace + line numbers is acceptable for v1 — don't add a dep just for this.
- **Branch naming policy.** Today's pattern in CLAUDE.md is `feat/...`, `fix/...`. The agent prefix (`rob/...`, `aisha/...`) is what the spec proposes for clarity. Discuss at implementation if this conflicts with any existing convention.
- **Commit author identity.** GitHub's contents API attributes commits to the bot account behind `GITHUB_TOKEN_AGENTS`. Acceptable for v1. If founder wants commits attributed to a specific name, switch to creating commits via the lower-level git data API (more code).
- **PR labels.** Auto-applying labels like `agent-proposed` / `from-rob` could help GitHub-side filtering. Decide at implementation; tiny add.
- **GitHub Actions caching.** The workflow above caches pip. May also want to cache `~/.cache/pip` for the postgres-services step. Polish for the implementation plan.

## Risks

1. **Stale proposals.** Rob drafts a PR based on file Y; founder commits a change to Y manually before approving. **Mitigation:** apply blindly — GitHub returns 422 on conflict, which is captured in `applied_result` as a failure. Founder re-runs Rob.

2. **Bad PR drafts that pass approval anyway.** Founder can approve a flawed PR if they don't read carefully. **Mitigation:** branch protection + CI catches anything that breaks tests; the PR sits unmerged until the founder actively merges on GitHub. The agent platform's approval is "open the PR," not "merge it."

3. **GitHub API rate limits.** 5000/hr authenticated for the personal-access-token tier. Multiple agents producing PRs could hit this. **Mitigation:** rare in practice for solo use; if it becomes routine we add backoff. Failed attempts are recorded; founder can re-approve.

4. **Agent producing files that violate brand rules.** The hard rules in team_memory should prevent it, but model errors happen. **Mitigation:** approval queue is the gate; reject and the rejection feeds back to Rob's memory.

5. **Cost.** Multi-turn tool use for code generation is more expensive than current Phase 2A usage. A real code-change run might be $0.20–$1.00. **Mitigation:** per-agent monthly caps already enforce a ceiling; observe spend in the first week and tune Rob's cap if needed.

6. **Test-in-PR discipline isn't actually enforced.** Rob's system prompt says he should include tests; we don't lint it. **Mitigation:** v1 prompt-only. If Rob opens PRs without tests, reject in the queue with reason "no test" — feedback memory will train the behavior. If still problematic, a small lint step at approval time (refuse to fire if no `test_*.py` in the files list) is a small follow-up.

7. **Branch name collisions.** Rob proposes `rob/fix-X` twice without the first being merged or deleted. Second proposal's executor call will 422 because the branch already exists. **Mitigation:** approval executor catches the error and surfaces "branch already exists." Rob picks a different branch name on retry.

8. **GITHUB_TOKEN_AGENTS scope.** The token needs `repo` scope (write access to the repo). Granting that to an agent's token is meaningfully sensitive. **Mitigation:** use a dedicated bot account, never the founder's PAT; rotate periodically; document in `docs/agents.md`. If the org has GitHub Apps available, a GitHub App installation token is preferable to a PAT — defer to implementation if the user wants it.

## Success criteria

This sub-spec is judged successful if, two weeks after shipping:

- The founder has approved at least 3 Rob-proposed PRs that landed cleanly on `master` after local test + merge.
- No agent-proposed PR has caused a customer incident, brand-voice slip, or unintended production change.
- CI catches at least one real test failure on an agent-proposed PR (proving the gate works under live conditions).
- Founder spend on Rob's runs (Anthropic + GitHub API) is < 5% of Nano EASM monthly revenue.
- The approval queue UI lets the founder review files in under 60 seconds for typical PRs (3–5 files).

If those bars aren't met, the runtime + tool pattern needs trimming before we layer the rest of Phase 2B on top.
