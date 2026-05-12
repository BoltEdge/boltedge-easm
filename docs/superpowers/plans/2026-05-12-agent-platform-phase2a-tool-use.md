# Agent Platform Phase 2A — Tool Use Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a multi-turn tool-use runtime + 6 read-only tools + 4 new `/api/internal/*` endpoints + a read-only repo bind-mount, so the 6 existing agents can autonomously look up data instead of relying on context the founder pastes in.

**Architecture:** Anthropic's native `tool_use` API drives a multi-turn loop in `runtime.py`. A central `TOOL_REGISTRY` maps tool name → handler. Per-agent allowlist enforcement uses each profile's `allowed_tools` YAML field. The 4 new internal endpoints follow the existing `stats/weekly` pattern. The repo is bind-mounted read-only into `easm-backend` at `/repo`.

**Tech Stack:**
- **Backend**: Flask + SQLAlchemy (existing), Anthropic Python SDK (already installed)
- **Runtime additions**: `requests` (existing) for `web_fetch` + `github_query`, `subprocess` (stdlib) for `git_read`, `beautifulsoup4` + `html2text` (new) for HTML→text
- **Tests**: pytest (existing), `responses` library (new) for mocking outbound HTTP
- **Compose**: docker-compose bind-mount

**Out of scope for this plan** (deferred to Phase 2B or later):
- Write tools (`github_pr_create`, `send_email`)
- Approval-gated tool execution
- Tuesday + Wednesday weekly briefs (Ava `competitor-pulse`, Maya `weekly-finding-brief`)
- Memory hygiene weekly job
- Customer-facing send service
- Hand-off between agents
- Tavily / Brave fallback for `web_search`

**Milestones** (each is a viable stopping point):

| Stage | Outcome | Tasks |
|---|---|---|
| A | Foundation: tool registry + multi-turn loop + first tool (`read_internal_api`) end-to-end | 1–3 |
| B | Web tools + 4 new internal endpoints wired across all 6 agents | 4–7 |
| C | Repo tools + bind-mount, Rob and Aisha can answer code questions | 8–10 |
| D | Polish: profile prompts updated, smoke test, CLAUDE.md updated | 11–12 |

---

## Stage A — Foundation

### Task 1: Tool registry + Anthropic client tool support

**Files:**
- Create: `backend/app/agents/tools/__init__.py`
- Modify: `backend/app/agents/anthropic_client.py`
- Test: `backend/tests/test_agents_tools_registry.py`
- Test: `backend/tests/test_agents_anthropic_tools.py`

- [ ] **Step 1: Write the failing test for the tool registry**

Create `backend/tests/test_agents_tools_registry.py`:

```python
from app.agents.tools import (
    TOOL_REGISTRY, ToolDef, register_tool, expose_tools_for,
    anthropic_tool_spec,
)


def test_tool_def_fields():
    def _fake_handler(**kwargs):
        return "ok"

    t = ToolDef(
        name="x_test",
        description="A test tool.",
        input_schema={"type": "object", "properties": {}, "required": []},
        handler=_fake_handler,
        idempotent=True,
        result_cap_bytes=1000,
    )
    assert t.name == "x_test"
    assert t.idempotent is True
    assert t.handler() == "ok"


def test_register_tool_adds_to_registry():
    def _fake(**kwargs):
        return "result"

    register_tool(ToolDef(
        name="x_register_test",
        description="d",
        input_schema={"type": "object", "properties": {}, "required": []},
        handler=_fake,
        idempotent=False,
        result_cap_bytes=100,
    ))
    assert "x_register_test" in TOOL_REGISTRY


def test_expose_tools_for_filters_by_allowlist():
    def _fake(**kwargs):
        return ""
    register_tool(ToolDef(
        name="x_one", description="", handler=_fake,
        input_schema={"type": "object", "properties": {}, "required": []},
        idempotent=True, result_cap_bytes=10,
    ))
    register_tool(ToolDef(
        name="x_two", description="", handler=_fake,
        input_schema={"type": "object", "properties": {}, "required": []},
        idempotent=True, result_cap_bytes=10,
    ))
    exposed = expose_tools_for(["x_one"])
    names = [t["name"] for t in exposed]
    assert names == ["x_one"]


def test_anthropic_tool_spec_shape():
    def _fake(**kwargs):
        return ""
    register_tool(ToolDef(
        name="x_spec_test",
        description="A spec test tool.",
        handler=_fake,
        input_schema={"type": "object",
                       "properties": {"q": {"type": "string"}},
                       "required": ["q"]},
        idempotent=True, result_cap_bytes=10,
    ))
    spec = anthropic_tool_spec(TOOL_REGISTRY["x_spec_test"])
    assert spec["name"] == "x_spec_test"
    assert spec["description"] == "A spec test tool."
    assert spec["input_schema"]["properties"]["q"]["type"] == "string"
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_tools_registry.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Implement the registry**

Create `backend/app/agents/tools/__init__.py`:

```python
"""Agent tool registry.

A central dict of tool name -> ToolDef. Each ToolDef carries the
Anthropic-facing description and schema plus the Python handler.
Per-agent allowlist filtering is done with expose_tools_for().
"""
from __future__ import annotations
import dataclasses
from typing import Callable


@dataclasses.dataclass
class ToolDef:
    name: str
    description: str
    input_schema: dict
    handler: Callable
    idempotent: bool
    result_cap_bytes: int


TOOL_REGISTRY: dict[str, ToolDef] = {}


def register_tool(tool: ToolDef) -> None:
    """Add a tool to the global registry. Overwrites by name."""
    TOOL_REGISTRY[tool.name] = tool


def anthropic_tool_spec(tool: ToolDef) -> dict:
    """Build the per-tool dict that Anthropic's messages.create()
    accepts under the `tools` parameter."""
    return {
        "name": tool.name,
        "description": tool.description,
        "input_schema": tool.input_schema,
    }


def expose_tools_for(allowed_tools: list[str]) -> list[dict]:
    """Filter the registry to the names in allowed_tools and return the
    Anthropic-shaped tool specs. Unknown names are silently skipped."""
    out = []
    for name in allowed_tools:
        if name in TOOL_REGISTRY:
            out.append(anthropic_tool_spec(TOOL_REGISTRY[name]))
    return out
```

- [ ] **Step 4: Run the test — verify it passes**

Run: `cd backend && pytest tests/test_agents_tools_registry.py -v`
Expected: PASS for all four tests.

- [ ] **Step 5: Write the failing test for Anthropic client tool support**

Create `backend/tests/test_agents_anthropic_tools.py`:

```python
from app.agents.anthropic_client import LlmCall, FakeAnthropicClient


def test_llmcall_accepts_tools_field():
    call = LlmCall(
        model="claude-opus-4-7",
        system="be helpful",
        messages=[{"role": "user", "content": "hi"}],
        max_tokens=100,
        tools=[{"name": "x_t", "description": "d", "input_schema": {}}],
    )
    assert call.tools[0]["name"] == "x_t"


def test_fake_client_default_returns_end_turn():
    fc = FakeAnthropicClient(canned_text="hello")
    call = LlmCall(
        model="claude-opus-4-7", system="s",
        messages=[{"role": "user", "content": "hi"}],
        max_tokens=100,
    )
    result = fc.call(call)
    assert result.stop_reason == "end_turn"
    assert result.text == "hello"
    assert result.tool_uses == []


def test_fake_client_scripted_tool_use_then_end_turn():
    fc = FakeAnthropicClient(scripted_responses=[
        {"stop_reason": "tool_use",
         "tool_uses": [{"id": "t1", "name": "x_t",
                         "input": {"q": "hello"}}]},
        {"stop_reason": "end_turn",
         "text": "done"},
    ])
    call = LlmCall(model="claude-opus-4-7", system="s",
                    messages=[{"role": "user", "content": "go"}],
                    max_tokens=100,
                    tools=[{"name": "x_t", "description": "d",
                             "input_schema": {}}])
    # First turn -> tool_use
    r1 = fc.call(call)
    assert r1.stop_reason == "tool_use"
    assert r1.tool_uses[0]["name"] == "x_t"
    # Second turn -> end_turn
    r2 = fc.call(call)
    assert r2.stop_reason == "end_turn"
    assert r2.text == "done"
```

- [ ] **Step 6: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_anthropic_tools.py -v`
Expected: FAIL — `LlmCall.tools` doesn't exist; `FakeAnthropicClient.scripted_responses` doesn't exist; `LlmResult.tool_uses` doesn't exist.

- [ ] **Step 7: Modify `anthropic_client.py`**

In `backend/app/agents/anthropic_client.py`:

a) Add `tools` field to `LlmCall`:

```python
@dataclasses.dataclass(frozen=True)
class LlmCall:
    model: str
    system: str
    messages: list[dict]
    max_tokens: int = 4096
    tools: list[dict] = dataclasses.field(default_factory=list)
```

b) Add `tool_uses` field to `LlmResult`:

```python
@dataclasses.dataclass(frozen=True)
class LlmResult:
    text: str
    input_tokens: int
    output_tokens: int
    cost_usd: float | None
    stop_reason: str
    duration_ms: int
    tool_uses: list[dict] = dataclasses.field(default_factory=list)
```

c) Update `RealAnthropicClient.call()` to pass `tools` if present and parse `tool_use` content blocks:

```python
    def call(self, call: LlmCall) -> LlmResult:
        import time
        start = time.monotonic()
        kwargs = dict(
            model=call.model,
            system=call.system,
            messages=call.messages,
            max_tokens=call.max_tokens,
        )
        if call.tools:
            kwargs["tools"] = call.tools
        msg = self._client.messages.create(**kwargs)
        dur = int((time.monotonic() - start) * 1000)
        text_parts: list[str] = []
        tool_uses: list[dict] = []
        for block in msg.content:
            btype = getattr(block, "type", "")
            if btype == "text":
                text_parts.append(block.text)
            elif btype == "tool_use":
                tool_uses.append({
                    "id": block.id,
                    "name": block.name,
                    "input": dict(block.input),
                })
        cost = compute_cost_usd(
            call.model, msg.usage.input_tokens, msg.usage.output_tokens,
        )
        return LlmResult(
            text="".join(text_parts),
            input_tokens=msg.usage.input_tokens,
            output_tokens=msg.usage.output_tokens,
            cost_usd=cost,
            stop_reason=msg.stop_reason or "unknown",
            duration_ms=dur,
            tool_uses=tool_uses,
        )
```

d) Update `FakeAnthropicClient` to support a list of scripted responses:

```python
class FakeAnthropicClient:
    """Deterministic stub for tests.

    Two modes:
    - `canned_text="..."` — every call() returns a single end_turn with that text.
    - `scripted_responses=[...]` — each call() returns the next entry from the list.
      Each entry is a dict with keys: stop_reason, text (optional), tool_uses (optional).
    """

    def __init__(self, canned_text: str = "ok",
                  scripted_responses: list[dict] | None = None):
        self._text = canned_text
        self._scripted = list(scripted_responses) if scripted_responses else None
        self._idx = 0

    def call(self, call: LlmCall) -> LlmResult:
        if self._scripted is not None:
            if self._idx >= len(self._scripted):
                raise RuntimeError("FakeAnthropicClient: ran out of scripted responses")
            entry = self._scripted[self._idx]
            self._idx += 1
            text = entry.get("text", "")
            tool_uses = list(entry.get("tool_uses", []))
            in_tok = max(1, sum(len(m.get("content", "")) if isinstance(m.get("content"), str) else 32
                                  for m in call.messages) // 4 + len(call.system) // 4)
            out_tok = max(1, (len(text) + sum(len(str(tu)) for tu in tool_uses)) // 4)
            cost = compute_cost_usd(call.model, in_tok, out_tok)
            return LlmResult(
                text=text,
                input_tokens=in_tok, output_tokens=out_tok,
                cost_usd=cost,
                stop_reason=entry["stop_reason"],
                duration_ms=1,
                tool_uses=tool_uses,
            )

        # canned_text mode
        in_tok = max(1, sum(len(m.get("content", "")) if isinstance(m.get("content"), str) else 32
                              for m in call.messages) // 4 + len(call.system) // 4)
        out_tok = max(1, len(self._text) // 4)
        cost = compute_cost_usd(call.model, in_tok, out_tok)
        return LlmResult(
            text=self._text,
            input_tokens=in_tok, output_tokens=out_tok,
            cost_usd=cost,
            stop_reason="end_turn", duration_ms=1, tool_uses=[],
        )
```

- [ ] **Step 8: Run all anthropic-client tests — verify everything passes**

Run: `cd backend && pytest tests/test_agents_anthropic.py tests/test_agents_anthropic_tools.py tests/test_agents_runtime.py -v`
Expected: all tests PASS (the pre-existing tests in `test_agents_runtime.py` exercise the no-tools path, which must still work).

- [ ] **Step 9: Commit**

```bash
git add backend/app/agents/tools/__init__.py backend/app/agents/anthropic_client.py backend/tests/test_agents_tools_registry.py backend/tests/test_agents_anthropic_tools.py
git commit -m "feat(agents): tool registry + Anthropic client tool support"
```

---

### Task 2: Multi-turn loop in runtime

**Files:**
- Modify: `backend/app/agents/runtime.py`
- Test: `backend/tests/test_agents_runtime_tools.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_runtime_tools.py`:

```python
from app.agents.runtime import run_agent
from app.agents.anthropic_client import FakeAnthropicClient
from app.agents.tools import ToolDef, register_tool


def test_run_agent_executes_tool_then_continues(db_session, monkeypatch):
    """Agent emits tool_use -> runtime executes handler -> appends tool_result ->
    second turn returns end_turn."""

    calls_made = []

    def _fake_handler(**kwargs):
        calls_made.append(kwargs)
        return "tool result here"

    register_tool(ToolDef(
        name="x_runtime_tool",
        description="A test tool for runtime tests.",
        input_schema={"type": "object",
                       "properties": {"q": {"type": "string"}},
                       "required": ["q"]},
        handler=_fake_handler,
        idempotent=True,
        result_cap_bytes=10_000,
    ))

    # Patch the profile's allowed_tools so the test tool is exposed
    from app.agents.profile_loader import AgentProfile
    real_load = AgentProfile.__init__
    monkeypatch.setattr(
        "app.agents.runtime.load_profile_by_name",
        lambda n: _profile_with_tools(n, ["x_runtime_tool"]),
    )

    fake = FakeAnthropicClient(scripted_responses=[
        {"stop_reason": "tool_use",
         "tool_uses": [{"id": "tu_1", "name": "x_runtime_tool",
                         "input": {"q": "hello"}}]},
        {"stop_reason": "end_turn", "text": "final answer based on tool result"},
    ])
    result = run_agent(
        agent_name="founder-ops",
        user_prompt="please use the tool",
        skill=None, memory_tags=[], client=fake,
    )

    assert result.run.status == "success"
    assert result.text == "final answer based on tool result"
    assert len(calls_made) == 1
    assert calls_made[0] == {"q": "hello"}

    # Thread should have: user msg, tool call, tool result, assistant msg
    roles = [m.role for m in result.thread.messages]
    assert roles == ["user", "tool", "assistant"]
    # tool message records what was called
    tool_msg = result.thread.messages[1]
    assert tool_msg.content["tool_name"] == "x_runtime_tool"
    assert tool_msg.content["input"] == {"q": "hello"}
    assert "tool result here" in tool_msg.content["output"]


def _profile_with_tools(name, tools):
    """Helper: load the real profile but with allowed_tools replaced."""
    from app.agents.profile_loader import load_profile_by_name
    p = load_profile_by_name(name)
    # AgentProfile is frozen; use dataclasses.replace
    import dataclasses
    return dataclasses.replace(p, allowed_tools=tools)


def test_run_agent_no_tools_still_works(db_session):
    """Backward compat: an agent with no allowed_tools follows the
    Phase 1 single-shot path."""
    fake = FakeAnthropicClient(canned_text="just text")
    result = run_agent(
        agent_name="founder-ops",
        user_prompt="say something",
        skill=None, memory_tags=[], client=fake,
    )
    assert result.run.status == "success"
    assert result.text == "just text"
    roles = [m.role for m in result.thread.messages]
    assert roles == ["user", "assistant"]


def test_run_agent_respects_tool_call_cap(db_session, monkeypatch):
    """A runaway loop must be hard-capped at profile.tool_call_cap_per_run."""

    def _always_loop(**kwargs):
        return "still going"

    register_tool(ToolDef(
        name="x_loop_tool",
        description="Always invoke again.",
        input_schema={"type": "object", "properties": {}, "required": []},
        handler=_always_loop,
        idempotent=False,
        result_cap_bytes=100,
    ))

    monkeypatch.setattr(
        "app.agents.runtime.load_profile_by_name",
        lambda n: _profile_with_tools_and_cap(n, ["x_loop_tool"], cap=3),
    )

    # Script 100 tool_use responses (more than any sane cap)
    fake = FakeAnthropicClient(scripted_responses=[
        {"stop_reason": "tool_use",
         "tool_uses": [{"id": f"t{i}", "name": "x_loop_tool", "input": {}}]}
        for i in range(100)
    ])
    result = run_agent(
        agent_name="founder-ops", user_prompt="loop please",
        skill=None, memory_tags=[], client=fake,
    )

    # Capped at 3 tool calls
    tool_count = sum(1 for m in result.thread.messages if m.role == "tool")
    assert tool_count <= 3
    assert result.run.status in ("failed", "tool-cap-exceeded")


def _profile_with_tools_and_cap(name, tools, cap):
    import dataclasses
    from app.agents.profile_loader import load_profile_by_name
    p = load_profile_by_name(name)
    return dataclasses.replace(p, allowed_tools=tools, tool_call_cap_per_run=cap)
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_runtime_tools.py -v`
Expected: FAIL. Errors will include `AttributeError: dataclasses.replace cannot replace allowed_tools` because the field may not be on `AgentProfile` yet, OR the multi-turn loop isn't implemented.

If `allowed_tools` is not on `AgentProfile`, check: `grep "allowed_tools" backend/app/agents/profile_loader.py`. It is part of the profile already (Phase 1 added it). Move on.

- [ ] **Step 3: Modify `runtime.py` to support the multi-turn tool-use loop**

Replace the body of `backend/app/agents/runtime.py` with this (preserves the no-tools path):

```python
"""Run-an-agent — the central runtime.

Single-shot mode (no tools in profile.allowed_tools): Phase 1 behaviour.
Multi-turn tool-use mode (allowed_tools non-empty): the runtime calls
Anthropic, executes any tool_use blocks the model emits, appends results
to the message history, and loops until end_turn or the per-run cap fires.
"""
from __future__ import annotations
import dataclasses
from typing import Iterable

from app.extensions import db
from app.models import AgentRun, AgentThread, AgentMessage, now_utc

from .profile_loader import load_profile_by_name, AgentProfile
from .anthropic_client import LlmCall, RealAnthropicClient, LlmResult
from .prompt_builder import build_messages_and_system
from .budget import check_within_cap
from .tools import TOOL_REGISTRY, expose_tools_for


@dataclasses.dataclass
class RunResult:
    run: AgentRun
    thread: AgentThread
    text: str | None


def _get_or_create_thread(agent_id: str, thread_id: int | None,
                           user_prompt: str) -> AgentThread:
    if thread_id is not None:
        t = AgentThread.query.get(thread_id)
        if not t:
            raise ValueError(f"thread {thread_id} not found")
        return t
    title = (user_prompt[:80] + "…") if len(user_prompt) > 80 else user_prompt
    t = AgentThread(agent_id=agent_id, title=title)
    db.session.add(t)
    db.session.flush()
    return t


def _truncate(s: str, cap_bytes: int) -> str:
    b = s.encode("utf-8")
    if len(b) <= cap_bytes:
        return s
    return b[:cap_bytes].decode("utf-8", errors="ignore") + (
        f"\n\n…[truncated at {cap_bytes} bytes]"
    )


def _execute_tool(name: str, args: dict) -> tuple[str, bool]:
    """Look up the tool, run its handler, truncate to cap.
    Returns (output_string, is_error)."""
    if name not in TOOL_REGISTRY:
        return (f"[tool '{name}' is not available to this agent]", True)
    tool = TOOL_REGISTRY[name]
    try:
        result = tool.handler(**args)
        if not isinstance(result, str):
            result = str(result)
        return (_truncate(result, tool.result_cap_bytes), False)
    except Exception as e:
        # Surface the error to the agent so it can recover
        return (f"[tool '{name}' error: {type(e).__name__}: {e}]", True)


def run_agent(
    agent_name: str,
    user_prompt: str,
    skill: str | None,
    memory_tags: Iterable[str],
    client=None,
    thread_id: int | None = None,
) -> RunResult:
    profile = load_profile_by_name(agent_name)
    thread = _get_or_create_thread(profile.name, thread_id, user_prompt)
    started = now_utc()

    run = AgentRun(
        agent_id=profile.name, skill=skill,
        thread_id=thread.id,
        input={"prompt": user_prompt, "memory_tags": list(memory_tags)},
        status="running",
        started_at=started,
    )
    db.session.add(run)
    db.session.flush()

    try:
        check_within_cap(profile.name, profile.cost_cap_monthly_usd)
    except RuntimeError as e:
        run.status = "over-budget"
        run.error = str(e)
        run.finished_at = now_utc()
        db.session.flush()
        return RunResult(run=run, thread=thread, text=None)

    # Build initial prompt context BEFORE persisting the user message
    system, messages = build_messages_and_system(
        profile=profile, user_prompt=user_prompt,
        thread=thread, memory_tags=memory_tags,
    )

    tools_spec = expose_tools_for(profile.allowed_tools)
    c = client or RealAnthropicClient()

    tool_calls_made = 0
    final_text: str | None = None
    last_result: LlmResult | None = None

    # --- multi-turn loop ---
    try:
        while True:
            result = c.call(LlmCall(
                model=profile.default_model,
                system=system,
                messages=messages,
                max_tokens=4096,
                tools=tools_spec,
            ))
            last_result = result

            if result.stop_reason == "tool_use" and result.tool_uses:
                # Append the assistant tool_use turn to messages
                assistant_blocks = []
                if result.text:
                    assistant_blocks.append({"type": "text",
                                              "text": result.text})
                for tu in result.tool_uses:
                    assistant_blocks.append({
                        "type": "tool_use",
                        "id": tu["id"],
                        "name": tu["name"],
                        "input": tu["input"],
                    })
                messages.append({"role": "assistant",
                                  "content": assistant_blocks})

                # Execute each tool
                tool_result_blocks = []
                for tu in result.tool_uses:
                    if tool_calls_made >= profile.tool_call_cap_per_run:
                        tool_result_blocks.append({
                            "type": "tool_result",
                            "tool_use_id": tu["id"],
                            "content": "[tool_call_cap_per_run reached; "
                                       "no further tool calls allowed this run]",
                            "is_error": True,
                        })
                        continue

                    output, is_error = _execute_tool(tu["name"], tu["input"])
                    tool_result_blocks.append({
                        "type": "tool_result",
                        "tool_use_id": tu["id"],
                        "content": output,
                        "is_error": is_error,
                    })

                    # Persist a 'tool' role message
                    db.session.add(AgentMessage(
                        thread_id=thread.id, role="tool",
                        content={
                            "tool_use_id": tu["id"],
                            "tool_name": tu["name"],
                            "input": tu["input"],
                            "output": output,
                            "is_error": is_error,
                        },
                    ))
                    tool_calls_made += 1

                messages.append({"role": "user",
                                  "content": tool_result_blocks})
                db.session.flush()

                if tool_calls_made >= profile.tool_call_cap_per_run:
                    # The next loop iteration would just return more tool_uses
                    # we'd refuse; abort instead.
                    run.status = "tool-cap-exceeded"
                    run.error = (f"tool_call_cap_per_run "
                                  f"({profile.tool_call_cap_per_run}) reached")
                    run.finished_at = now_utc()
                    db.session.flush()
                    return RunResult(run=run, thread=thread, text=None)

                continue  # next turn

            # end_turn / max_tokens / stop_sequence
            final_text = result.text or ""
            break
    except Exception as e:
        run.status = "failed"
        run.error = repr(e)[:1000]
        run.finished_at = now_utc()
        db.session.flush()
        return RunResult(run=run, thread=thread, text=None)

    # Persist the user prompt + the final assistant response
    # (we do this at the end so build_messages_and_system saw the thread
    #  state before any of this run's messages were added)
    db.session.add(AgentMessage(
        thread_id=thread.id, role="user",
        content={"text": user_prompt},
    ))
    db.session.add(AgentMessage(
        thread_id=thread.id, role="assistant",
        content={"text": final_text},
        tokens_used=(last_result.input_tokens + last_result.output_tokens)
                     if last_result else None,
    ))

    run.status = "success"
    run.output = {"text": final_text}
    if last_result:
        run.cost_usd = last_result.cost_usd
        run.duration_ms = last_result.duration_ms
    run.finished_at = now_utc()
    db.session.flush()

    return RunResult(run=run, thread=thread, text=final_text)
```

NOTE: this changes the order of message persistence — user + assistant are persisted at the END now, with tool messages persisted DURING the loop. Existing Phase 1 tests in `test_agents_runtime.py` expect `roles == ["user", "assistant"]` which still holds (no tool messages in between when allowed_tools is empty).

- [ ] **Step 4: Run all runtime tests**

Run: `cd backend && pytest tests/test_agents_runtime.py tests/test_agents_runtime_tools.py -v`
Expected: all PASS. Pre-existing single-shot tests continue to work; new tool-use tests pass.

- [ ] **Step 5: Run the full suite to catch regressions**

Run: `cd backend && pytest tests/ 2>&1 | tail -5`
Expected: all PASS (we should be at ~50 tests now, up from 46 after Phase 1).

- [ ] **Step 6: Commit**

```bash
git add backend/app/agents/runtime.py backend/tests/test_agents_runtime_tools.py
git commit -m "feat(agents): multi-turn tool-use loop in runtime"
```

---

### Task 3: First tool — `read_internal_api`

**Files:**
- Create: `backend/app/agents/tools/internal_api.py`
- Modify: `backend/app/agents/tools/__init__.py` (auto-import on package import)
- Test: `backend/tests/test_agents_tools_internal_api.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_tools_internal_api.py`:

```python
from unittest.mock import patch, MagicMock
from app.agents.tools.internal_api import read_internal_api_handler


def test_read_internal_api_rejects_unknown_endpoint():
    result = read_internal_api_handler(endpoint="some/random/path")
    assert "unknown endpoint" in result.lower() or "not allowed" in result.lower()


def test_read_internal_api_returns_json_string_on_success():
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.text = '{"orgs_total": 42, "users_total": 75}'
    fake_response.raise_for_status = MagicMock()

    with patch("app.agents.tools.internal_api.requests.get",
                return_value=fake_response) as mock_get:
        result = read_internal_api_handler(endpoint="stats/weekly")
        assert "orgs_total" in result
        # Verify the URL it called
        called_url = mock_get.call_args[0][0]
        assert called_url.endswith("/api/internal/stats/weekly")


def test_read_internal_api_passes_params():
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.text = "[]"
    fake_response.raise_for_status = MagicMock()

    with patch("app.agents.tools.internal_api.requests.get",
                return_value=fake_response) as mock_get:
        read_internal_api_handler(endpoint="findings/recent",
                                    params={"severity": "high", "limit": 10})
        kwargs = mock_get.call_args[1]
        assert kwargs.get("params") == {"severity": "high", "limit": 10}


def test_read_internal_api_returns_error_string_on_4xx():
    fake_response = MagicMock()
    fake_response.status_code = 403
    fake_response.text = '{"error":"scope_denied"}'

    def _raise(*a, **kw):
        from requests.exceptions import HTTPError
        raise HTTPError(response=fake_response)
    fake_response.raise_for_status = _raise

    with patch("app.agents.tools.internal_api.requests.get",
                return_value=fake_response):
        result = read_internal_api_handler(endpoint="stats/weekly")
        assert "403" in result or "scope_denied" in result
```

- [ ] **Step 2: Run the test — verify it fails (ImportError)**

Run: `cd backend && pytest tests/test_agents_tools_internal_api.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Implement the tool**

Create `backend/app/agents/tools/internal_api.py`:

```python
"""read_internal_api tool — agents call /api/internal/* endpoints via HTTPS.

Calls go through the network layer (not direct DB access) so they appear
in audit_log with the agent's identity, matching the seam the Phase 1
spec established.
"""
from __future__ import annotations
import os

import requests

from . import ToolDef, register_tool


ALLOWED_ENDPOINTS = {
    "stats/weekly",
    "findings/recent",
    "contact-requests/recent",
    "audit-log/recent",
    "scans/recent",
}

TIMEOUT_SECONDS = 10


def read_internal_api_handler(endpoint: str, params: dict | None = None) -> str:
    """Issues a GET against /api/internal/<endpoint>. Uses the founder-ops
    bearer key (NANOEASM_API_KEY_AGENTS_FOUNDER_OPS) by default — Phase 2A
    has one shared key per agent platform. Phase 2B will route per-agent
    keys."""
    if endpoint not in ALLOWED_ENDPOINTS:
        return (f"[unknown endpoint '{endpoint}'. Allowed: "
                f"{', '.join(sorted(ALLOWED_ENDPOINTS))}]")

    base = os.environ.get("INTERNAL_API_BASE", "http://easm-backend:5000")
    key = os.environ.get("NANOEASM_API_KEY_AGENTS_FOUNDER_OPS", "")
    if not key:
        return "[NANOEASM_API_KEY_AGENTS_FOUNDER_OPS env var is not set]"

    url = f"{base.rstrip('/')}/api/internal/{endpoint}"
    try:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {key}"},
            params=params or {},
            timeout=TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        return resp.text
    except requests.exceptions.HTTPError as e:
        status = getattr(e.response, "status_code", "?")
        body = (e.response.text or "")[:500] if e.response is not None else ""
        return f"[HTTP {status} from /api/internal/{endpoint}: {body}]"
    except requests.exceptions.RequestException as e:
        return f"[request failed: {type(e).__name__}: {e}]"


register_tool(ToolDef(
    name="read_internal_api",
    description=(
        "Call Nano EASM's read-only internal API. Allowed endpoints: "
        "'stats/weekly' (org count, signups, scans, plan mix for last 7d), "
        "'findings/recent' (recent vulnerability findings — accepts severity, "
        "since, limit params), 'contact-requests/recent' (trial requests, "
        "sales enquiries), 'audit-log/recent' (recent platform audit events — "
        "accepts category, since, limit), 'scans/recent' (recent scan jobs). "
        "Returns a JSON string."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "endpoint": {
                "type": "string",
                "enum": sorted(ALLOWED_ENDPOINTS),
                "description": "Which internal endpoint to call.",
            },
            "params": {
                "type": "object",
                "description": "Optional query string parameters.",
                "additionalProperties": True,
            },
        },
        "required": ["endpoint"],
    },
    handler=read_internal_api_handler,
    idempotent=True,
    result_cap_bytes=50_000,
))
```

- [ ] **Step 4: Modify `backend/app/agents/tools/__init__.py` to auto-import handlers on package import**

Append to `backend/app/agents/tools/__init__.py`:

```python
# Importing the handler modules triggers their register_tool() calls.
# Keep this at the bottom to avoid circular imports.
from . import internal_api  # noqa: F401,E402
```

- [ ] **Step 5: Run the tool tests**

Run: `cd backend && pytest tests/test_agents_tools_internal_api.py tests/test_agents_tools_registry.py -v`
Expected: all PASS.

- [ ] **Step 6: Update Sam's profile to allow the new tool**

Edit `backend/app/agents/profiles/founder-ops/agent.md` — change the `allowed_tools` block:

```yaml
allowed_tools:
  - read_internal_api
```

(Replacing the old aspirational list of `read_internal_api`, `web_fetch`, `write_agent_task`. We'll add the web tools in Task 6, and Sam doesn't need a `write_agent_task` tool in Phase 2A — agent_task writes still happen via the direct internal flow.)

- [ ] **Step 7: Run the full suite**

Run: `cd backend && pytest tests/ 2>&1 | tail -5`
Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add backend/app/agents/tools/__init__.py backend/app/agents/tools/internal_api.py backend/app/agents/profiles/founder-ops/agent.md backend/tests/test_agents_tools_internal_api.py
git commit -m "feat(agents): read_internal_api tool + Sam tool exposure"
```

---

## Stage B — Web tools + 4 new internal endpoints

### Task 4: Four new `/api/internal/*` read endpoints

**Files:**
- Modify: `backend/app/agents/internal_routes.py` (4 new routes)
- Create: `backend/app/agents/internal_stats.py` extension (or new module `internal_data.py`)
- Test: `backend/tests/test_agents_internal_endpoints_phase2a.py`

- [ ] **Step 1: Decide on module placement**

For Phase 1, `internal_stats.py` held `weekly_stats()`. With 4 more endpoints we should rename the module to `internal_queries.py` to reflect its broader role.

Run: `git mv backend/app/agents/internal_stats.py backend/app/agents/internal_queries.py`
Then update the import in `internal_routes.py` line ~10 from `internal_stats` to `internal_queries`.

Verify with: `cd backend && pytest tests/test_agents_internal_stats.py -v`
Expected: still PASS (rename didn't break anything).

- [ ] **Step 2: Write failing tests for the 4 new endpoints**

Create `backend/tests/test_agents_internal_endpoints_phase2a.py`:

```python
import hashlib
from uuid import uuid4
from app.models import ApiKey


def _sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _make_agent_key(db_session, test_org, test_user, scopes):
    raw = "nk_agent_" + uuid4().hex + uuid4().hex[:8]
    db_session.add(ApiKey(
        organization_id=test_org.id, user_id=test_user.id, name="phase2a",
        key_prefix="nk_agent_", key_hash=_sha256(raw),
        kind="agent", scopes=scopes,
    ))
    db_session.flush()
    return raw


def test_findings_recent_requires_scope(client, db_session, test_org, test_user):
    raw = _make_agent_key(db_session, test_org, test_user, ["read:stats"])
    resp = client.get("/api/internal/findings/recent",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 403


def test_findings_recent_returns_list(client, db_session, test_org, test_user):
    raw = _make_agent_key(db_session, test_org, test_user, ["read:findings"])
    resp = client.get("/api/internal/findings/recent",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "findings" in data
    assert isinstance(data["findings"], list)


def test_contact_requests_recent(client, db_session, test_org, test_user):
    raw = _make_agent_key(db_session, test_org, test_user,
                           ["read:contact_requests"])
    resp = client.get("/api/internal/contact-requests/recent",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "contact_requests" in data
    assert isinstance(data["contact_requests"], list)


def test_audit_log_recent(client, db_session, test_org, test_user):
    raw = _make_agent_key(db_session, test_org, test_user, ["read:audit_log"])
    resp = client.get("/api/internal/audit-log/recent",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "entries" in data
    assert isinstance(data["entries"], list)


def test_scans_recent(client, db_session, test_org, test_user):
    raw = _make_agent_key(db_session, test_org, test_user, ["read:scans"])
    resp = client.get("/api/internal/scans/recent",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "scans" in data
    assert isinstance(data["scans"], list)


def test_findings_recent_limit_capped(client, db_session, test_org, test_user):
    raw = _make_agent_key(db_session, test_org, test_user, ["read:findings"])
    resp = client.get("/api/internal/findings/recent?limit=9999",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    data = resp.get_json()
    # Hard cap at 200 in the implementation
    assert len(data["findings"]) <= 200
```

- [ ] **Step 3: Run the test — verify it fails (404)**

Run: `cd backend && pytest tests/test_agents_internal_endpoints_phase2a.py -v`
Expected: all FAIL with 404.

- [ ] **Step 4: Add the four query functions to `internal_queries.py`**

Append to `backend/app/agents/internal_queries.py`:

```python
from datetime import timedelta
from sqlalchemy import desc

from app.models import (
    Finding, ContactRequest, AuditLog, ScanJob, Organization, Asset,
    now_utc,
)


def _parse_since(since_iso: str | None, default_days: int = 7):
    if not since_iso:
        return now_utc() - timedelta(days=default_days)
    try:
        from datetime import datetime
        return datetime.fromisoformat(since_iso.replace("Z", ""))
    except (ValueError, TypeError):
        return now_utc() - timedelta(days=default_days)


def recent_findings(severity: str | None = None,
                     since: str | None = None,
                     limit: int = 50) -> dict:
    limit = max(1, min(limit, 200))
    start = _parse_since(since, default_days=30)

    q = (
        db.session.query(Finding, Organization.name, Asset.name)
        .join(Asset, Finding.asset_id == Asset.id)
        .join(Organization, Asset.organization_id == Organization.id)
        .filter(Finding.created_at >= start)
    )
    if severity:
        q = q.filter(Finding.severity == severity)
    q = q.order_by(desc(Finding.created_at)).limit(limit)

    rows = q.all()
    return {
        "findings": [
            {
                "id": f.id,
                "org_name": org_name,
                "asset": asset_name,
                "severity": f.severity,
                "title": f.title,
                "status": f.status,
                "created_at": f.created_at.isoformat() + "Z",
            }
            for f, org_name, asset_name in rows
        ],
        "count": len(rows),
        "since": start.isoformat() + "Z",
    }


def recent_contact_requests(since: str | None = None,
                              limit: int = 50) -> dict:
    limit = max(1, min(limit, 200))
    start = _parse_since(since, default_days=30)

    rows = (
        ContactRequest.query
        .filter(ContactRequest.created_at >= start)
        .order_by(desc(ContactRequest.created_at))
        .limit(limit)
        .all()
    )
    return {
        "contact_requests": [
            {
                "id": c.id,
                "kind": getattr(c, "kind", None) or getattr(c, "category", None),
                "email": c.email,
                "message_excerpt": (c.message or "")[:300],
                "created_at": c.created_at.isoformat() + "Z",
                "status": getattr(c, "status", None),
            }
            for c in rows
        ],
        "count": len(rows),
        "since": start.isoformat() + "Z",
    }


def recent_audit_log(category: str | None = None,
                      since: str | None = None,
                      limit: int = 50) -> dict:
    limit = max(1, min(limit, 200))
    start = _parse_since(since, default_days=7)

    q = AuditLog.query.filter(AuditLog.created_at >= start)
    if category:
        q = q.filter(AuditLog.category == category)
    rows = q.order_by(desc(AuditLog.created_at)).limit(limit).all()

    return {
        "entries": [
            {
                "id": e.id,
                "actor": getattr(e, "user_email", None) or getattr(e, "actor", None),
                "action": e.action,
                "category": e.category,
                "target": getattr(e, "target", None),
                "description": getattr(e, "description", None),
                "created_at": e.created_at.isoformat() + "Z",
            }
            for e in rows
        ],
        "count": len(rows),
        "since": start.isoformat() + "Z",
    }


def recent_scans(status: str | None = None,
                  since: str | None = None,
                  limit: int = 50) -> dict:
    limit = max(1, min(limit, 200))
    start = _parse_since(since, default_days=7)

    q = (
        db.session.query(ScanJob, Organization.name, Asset.name)
        .join(Asset, ScanJob.asset_id == Asset.id, isouter=True)
        .join(Organization, ScanJob.organization_id == Organization.id, isouter=True)
        .filter(ScanJob.created_at >= start)
    )
    if status:
        q = q.filter(ScanJob.status == status)
    rows = q.order_by(desc(ScanJob.created_at)).limit(limit).all()

    return {
        "scans": [
            {
                "id": s.id,
                "org_name": org_name,
                "asset": asset_name,
                "status": s.status,
                "started_at": s.started_at.isoformat() + "Z"
                                if getattr(s, "started_at", None) else None,
                "finished_at": s.finished_at.isoformat() + "Z"
                                 if getattr(s, "finished_at", None) else None,
            }
            for s, org_name, asset_name in rows
        ],
        "count": len(rows),
        "since": start.isoformat() + "Z",
    }
```

If the field names in `Finding`, `ContactRequest`, `AuditLog`, or `ScanJob` differ from what the code expects (column may be `category` vs `kind`, `actor` vs `user_email`, etc.), adjust the field accessors. Use `getattr(..., None)` defensively where you're uncertain.

- [ ] **Step 5: Add the four routes to `internal_routes.py`**

In `backend/app/agents/internal_routes.py`, after the existing `stats/weekly` route, append:

```python
from .internal_queries import (
    recent_findings, recent_contact_requests,
    recent_audit_log, recent_scans,
)


@bp.route("/findings/recent", methods=["GET"])
@require_agent_key(scope="read:findings")
def findings_recent():
    severity = request.args.get("severity")
    since = request.args.get("since")
    limit = request.args.get("limit", default=50, type=int)
    return jsonify(recent_findings(severity=severity, since=since, limit=limit))


@bp.route("/contact-requests/recent", methods=["GET"])
@require_agent_key(scope="read:contact_requests")
def contact_requests_recent():
    since = request.args.get("since")
    limit = request.args.get("limit", default=50, type=int)
    return jsonify(recent_contact_requests(since=since, limit=limit))


@bp.route("/audit-log/recent", methods=["GET"])
@require_agent_key(scope="read:audit_log")
def audit_log_recent():
    category = request.args.get("category")
    since = request.args.get("since")
    limit = request.args.get("limit", default=50, type=int)
    return jsonify(recent_audit_log(category=category, since=since, limit=limit))


@bp.route("/scans/recent", methods=["GET"])
@require_agent_key(scope="read:scans")
def scans_recent():
    status = request.args.get("status")
    since = request.args.get("since")
    limit = request.args.get("limit", default=50, type=int)
    return jsonify(recent_scans(status=status, since=since, limit=limit))
```

- [ ] **Step 6: Run the new tests**

Run: `cd backend && pytest tests/test_agents_internal_endpoints_phase2a.py -v`
Expected: all PASS.

- [ ] **Step 7: Run the full suite**

Run: `cd backend && pytest tests/ 2>&1 | tail -5`
Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add backend/app/agents/internal_routes.py backend/app/agents/internal_queries.py backend/tests/test_agents_internal_endpoints_phase2a.py
git rm backend/app/agents/internal_stats.py 2>/dev/null || true
git commit -m "feat(agents): 4 new /api/internal read endpoints (findings, contact-requests, audit-log, scans)"
```

---

### Task 5: `web_fetch` tool with SSRF defence

**Files:**
- Create: `backend/app/agents/tools/web.py`
- Create: `backend/app/agents/tools/_html_to_text.py`
- Modify: `backend/app/agents/tools/__init__.py` (add `from . import web` at bottom)
- Modify: `backend/requirements.txt` (add `beautifulsoup4`, `html2text`)
- Test: `backend/tests/test_agents_tools_web_fetch.py`

- [ ] **Step 1: Install dependencies**

```bash
cd backend && pip install beautifulsoup4 html2text
pip freeze | grep -E "^(beautifulsoup4|html2text)==" >> requirements.txt
```

Deduplicate `requirements.txt` after appending (the lines you just added may already exist):

```bash
sort -u requirements.txt -o requirements.txt
```

- [ ] **Step 2: Write the failing test**

Create `backend/tests/test_agents_tools_web_fetch.py`:

```python
from unittest.mock import patch, MagicMock
from app.agents.tools.web import web_fetch_handler


def test_web_fetch_rejects_non_http_urls():
    assert "rejected" in web_fetch_handler(url="file:///etc/passwd").lower()
    assert "rejected" in web_fetch_handler(url="ftp://example.com/").lower()
    assert "rejected" in web_fetch_handler(url="javascript:alert(1)").lower()


def test_web_fetch_rejects_private_ips():
    # SSRF defence: refuse to fetch RFC1918, loopback, link-local
    for url in [
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    ]:
        result = web_fetch_handler(url=url)
        assert "rejected" in result.lower() or "private" in result.lower()


def test_web_fetch_strips_html_to_text():
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.text = (
        "<html><body><h1>Hello</h1>"
        "<p>This is a <strong>test</strong>.</p>"
        "<script>alert('xss')</script>"
        "</body></html>"
    )
    fake_response.headers = {"content-type": "text/html; charset=utf-8"}
    fake_response.raise_for_status = MagicMock()

    with patch("app.agents.tools.web.requests.get",
                return_value=fake_response):
        result = web_fetch_handler(url="https://example.com/article")
        assert "Hello" in result
        assert "test" in result
        # Script tags should not appear in the output text
        assert "alert" not in result
        # HTML tags should be stripped
        assert "<h1>" not in result
        assert "<script>" not in result


def test_web_fetch_truncates_large_responses():
    huge = "x" * 200_000  # 200 KB of x's
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.text = f"<html><body>{huge}</body></html>"
    fake_response.headers = {"content-type": "text/html"}
    fake_response.raise_for_status = MagicMock()

    with patch("app.agents.tools.web.requests.get",
                return_value=fake_response):
        result = web_fetch_handler(url="https://example.com/")
        assert len(result.encode("utf-8")) <= 50_000 + 200  # cap + truncation notice
        assert "truncated" in result.lower()
```

- [ ] **Step 3: Run the test — verify it fails (ImportError)**

Run: `cd backend && pytest tests/test_agents_tools_web_fetch.py -v`
Expected: FAIL with ImportError.

- [ ] **Step 4: Implement HTML-to-text utility**

Create `backend/app/agents/tools/_html_to_text.py`:

```python
"""HTML to plain-text conversion for tool results.

Uses BeautifulSoup to strip script/style/nav and html2text for the
content -> markdown step. Errors silently fall back to a basic regex
strip.
"""
from __future__ import annotations
import re


_SCRIPT_STYLE_RE = re.compile(
    r"<(script|style|noscript|nav|footer|header)[^>]*>.*?</\1>",
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")


def html_to_text(html: str) -> str:
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript", "nav",
                          "footer", "header", "aside"]):
            tag.decompose()
        text = soup.get_text(separator="\n")
        # Collapse runs of blank lines
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()
    except Exception:
        # Fallback: regex-based strip
        out = _SCRIPT_STYLE_RE.sub("", html)
        out = _TAG_RE.sub(" ", out)
        out = re.sub(r"\s+", " ", out)
        return out.strip()
```

- [ ] **Step 5: Implement `web_fetch` handler**

Create `backend/app/agents/tools/web.py`:

```python
"""web_fetch tool — agents fetch a public URL and get plain text back.

SSRF defence: rejects private/loopback/link-local IPs and non-http(s)
schemes. 50 KB result cap after HTML extraction.
"""
from __future__ import annotations
import ipaddress
import socket
from urllib.parse import urlparse

import requests

from . import ToolDef, register_tool
from ._html_to_text import html_to_text


WEB_FETCH_TIMEOUT_SECONDS = 10
WEB_FETCH_RESULT_CAP_BYTES = 50_000


def _is_private_host(host: str) -> bool:
    """Resolve host to IP and check if it's in a private/reserved range."""
    try:
        addr = socket.gethostbyname(host)
        ip = ipaddress.ip_address(addr)
        return (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast
        )
    except (socket.gaierror, ValueError):
        # If we can't resolve, refuse to be safe.
        return True


def web_fetch_handler(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return f"[rejected: only http/https URLs allowed; got '{parsed.scheme}']"
    if not parsed.hostname:
        return "[rejected: no hostname in URL]"
    if _is_private_host(parsed.hostname):
        return f"[rejected: '{parsed.hostname}' resolves to a private IP]"

    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "Nano-EASM-Agent/1.0"},
            timeout=WEB_FETCH_TIMEOUT_SECONDS,
            allow_redirects=True,
        )
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        return f"[fetch failed: {type(e).__name__}: {e}]"

    ctype = resp.headers.get("content-type", "").lower()
    body = resp.text or ""

    if "html" in ctype:
        body = html_to_text(body)

    encoded = body.encode("utf-8")
    if len(encoded) > WEB_FETCH_RESULT_CAP_BYTES:
        body = encoded[:WEB_FETCH_RESULT_CAP_BYTES].decode("utf-8", errors="ignore")
        body += f"\n\n…[truncated at {WEB_FETCH_RESULT_CAP_BYTES} bytes]"

    return body


register_tool(ToolDef(
    name="web_fetch",
    description=(
        "Fetch a public URL and return its main text content (HTML pages "
        "are stripped to readable text). Use for: CVE pages, documentation, "
        "competitor product pages, blog articles, RFCs. Private/internal "
        "URLs are rejected. Result capped at 50 KB."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "An http:// or https:// URL to fetch.",
            },
        },
        "required": ["url"],
    },
    handler=web_fetch_handler,
    idempotent=True,
    result_cap_bytes=WEB_FETCH_RESULT_CAP_BYTES,
))
```

- [ ] **Step 6: Wire the module import**

Append to `backend/app/agents/tools/__init__.py`:

```python
from . import web  # noqa: F401,E402
```

- [ ] **Step 7: Run the tests**

Run: `cd backend && pytest tests/test_agents_tools_web_fetch.py -v`
Expected: all PASS.

- [ ] **Step 8: Run the full suite**

Run: `cd backend && pytest tests/ 2>&1 | tail -5`
Expected: all PASS.

- [ ] **Step 9: Commit**

```bash
git add backend/app/agents/tools/web.py backend/app/agents/tools/_html_to_text.py backend/app/agents/tools/__init__.py backend/requirements.txt backend/tests/test_agents_tools_web_fetch.py
git commit -m "feat(agents): web_fetch tool with SSRF defence + HTML->text"
```

---

### Task 6: `web_search` tool (Anthropic native)

**Files:**
- Modify: `backend/app/agents/tools/web.py` (append `web_search` handler + registration)
- Modify: `backend/app/agents/anthropic_client.py` (extend tools list to include server-side tools)
- Test: `backend/tests/test_agents_tools_web_search.py`

NOTE: Anthropic's `web_search_20250305` is a **server-side** tool. The Anthropic API executes it; our handler is mostly a no-op that signals to the model the tool is available. The implementation strategy: register a `ToolDef` with a sentinel handler that should never run (server-side execution means tool_use blocks come back already-resolved as search results). If the handler IS invoked (model emitted tool_use anyway), return a clear "[handled server-side]" message.

- [ ] **Step 1: Write the test**

Create `backend/tests/test_agents_tools_web_search.py`:

```python
from app.agents.tools import TOOL_REGISTRY, anthropic_tool_spec
from app.agents.tools.web import WEB_SEARCH_TOOL_TYPE


def test_web_search_registered():
    assert "web_search" in TOOL_REGISTRY


def test_web_search_tool_spec_uses_server_side_type():
    """For server-side tools, Anthropic wants the dict to include
    'type' = 'web_search_20250305' instead of a regular tool definition.
    The expose_tools_for() function should produce that shape for web_search."""
    from app.agents.tools import expose_tools_for
    specs = expose_tools_for(["web_search"])
    assert len(specs) == 1
    assert specs[0].get("type") == WEB_SEARCH_TOOL_TYPE
    assert specs[0].get("name") == "web_search"


def test_web_search_handler_returns_passthrough_note():
    """If the local handler ever runs, it should return a clear no-op
    string explaining that web_search is server-side."""
    from app.agents.tools.web import web_search_handler
    result = web_search_handler(query="anything")
    assert "server-side" in result.lower() or "handled by anthropic" in result.lower()
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_tools_web_search.py -v`
Expected: FAIL.

- [ ] **Step 3: Modify `expose_tools_for` to support server-side tools**

In `backend/app/agents/tools/__init__.py`, modify `anthropic_tool_spec` and add server-side tool support:

```python
def anthropic_tool_spec(tool: ToolDef) -> dict:
    """Build the per-tool dict that Anthropic's messages.create() accepts.
    Server-side tools (web_search etc.) use a 'type' discriminator instead
    of the input_schema shape.
    """
    if getattr(tool, "server_side_type", None):
        return {
            "type": tool.server_side_type,
            "name": tool.name,
        }
    return {
        "name": tool.name,
        "description": tool.description,
        "input_schema": tool.input_schema,
    }
```

Update `ToolDef`:

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
```

- [ ] **Step 4: Append `web_search` to `web.py`**

Append to `backend/app/agents/tools/web.py`:

```python
WEB_SEARCH_TOOL_TYPE = "web_search_20250305"


def web_search_handler(query: str) -> str:
    """Server-side tool — Anthropic executes the search and returns results
    directly in the message thread. Our local handler should not actually
    run; if it does (e.g. fake client emitting a regular tool_use block),
    return a clear note so the agent doesn't get confused."""
    return ("[web_search is handled server-side by Anthropic; results are "
            "returned in the next message turn automatically]")


register_tool(ToolDef(
    name="web_search",
    description=(
        "Search the public web for recent news, threat intel, competitor "
        "announcements, technical articles. Returns titles + snippets + "
        "URLs — use web_fetch to get a specific page's full text."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string"},
        },
        "required": ["query"],
    },
    handler=web_search_handler,
    idempotent=False,
    result_cap_bytes=0,
    server_side_type=WEB_SEARCH_TOOL_TYPE,
))
```

- [ ] **Step 5: Update the existing tool registry test**

Step 1 of Task 1 introduced `test_anthropic_tool_spec_shape` which assumed all tools use the input_schema shape. Add a new test asserting the server-side shape (which we just covered in `test_web_search_tool_spec_uses_server_side_type`).

The existing test for input_schema-shaped tools is still valid for non-server-side tools. No changes needed.

- [ ] **Step 6: Run the tests**

Run: `cd backend && pytest tests/test_agents_tools_web_search.py tests/test_agents_tools_registry.py -v`
Expected: all PASS.

- [ ] **Step 7: Run the full suite**

Run: `cd backend && pytest tests/ 2>&1 | tail -5`
Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add backend/app/agents/tools/web.py backend/app/agents/tools/__init__.py backend/tests/test_agents_tools_web_search.py
git commit -m "feat(agents): web_search tool (Anthropic native)"
```

---

### Task 7: Wire web tools + new endpoints across all 6 agents

**Files:**
- Modify: all 6 `backend/app/agents/profiles/<name>/agent.md`

- [ ] **Step 1: Update `allowed_tools` in each profile to match Phase 2A roster**

Edit each profile's frontmatter `allowed_tools` block:

`backend/app/agents/profiles/founder-ops/agent.md`:
```yaml
allowed_tools:
  - read_internal_api
  - web_fetch
  - web_search
```

`backend/app/agents/profiles/engineer/agent.md`:
```yaml
allowed_tools:
  - read_internal_api
  - web_fetch
  - web_search
```
(Stage C will add `git_read`, `github_query`, `read_repo_file`.)

`backend/app/agents/profiles/qa/agent.md`:
```yaml
allowed_tools:
  - read_internal_api
  - web_fetch
```
(Stage C will add `git_read`, `github_query`, `read_repo_file`.)

`backend/app/agents/profiles/security-analyst/agent.md`:
```yaml
allowed_tools:
  - read_internal_api
  - web_fetch
  - web_search
```

`backend/app/agents/profiles/strategy/agent.md`:
```yaml
allowed_tools:
  - read_internal_api
  - web_fetch
  - web_search
```

`backend/app/agents/profiles/voice/agent.md`:
```yaml
allowed_tools:
  - read_internal_api
  - web_fetch
  - web_search
```

- [ ] **Step 2: Verify all 6 profiles still load**

```bash
cd backend && python -c "
from app.agents.profile_loader import load_profile_by_name
for n in ['founder-ops','engineer','qa','security-analyst','strategy','voice']:
    p = load_profile_by_name(n)
    print(f'  {p.name:18} -> {p.display_name:6} | tools: {p.allowed_tools}')
"
```

Expected: 6 lines, each showing display name and the new allowed_tools list.

- [ ] **Step 3: Run the full suite**

Run: `cd backend && pytest tests/ 2>&1 | tail -5`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add backend/app/agents/profiles/
git commit -m "feat(agents): wire Stage B tools across all 6 agents"
```

---

## Stage C — Repo tools + bind-mount

### Task 8: docker-compose bind-mount + `git_read` tool

**Files:**
- Modify: `docker-compose.yml` (volume mount on `easm-backend`)
- Create: `backend/app/agents/tools/repo.py` (initially just `git_read`)
- Modify: `backend/app/agents/tools/__init__.py` (add `from . import repo`)
- Test: `backend/tests/test_agents_tools_git_read.py`

- [ ] **Step 1: Add the bind-mount to `docker-compose.yml`**

In `docker-compose.yml`, locate the `easm-backend:` service block. After the `environment:` mapping (right before `expose:`), add:

```yaml
    volumes:
      - ${HOST_REPO_PATH:-./}:/repo:ro
```

NOTE: if `easm-backend` already has a `volumes:` key, append to it instead of adding a new one.

- [ ] **Step 2: Write the failing test**

Create `backend/tests/test_agents_tools_git_read.py`:

```python
import subprocess
from unittest.mock import patch, MagicMock
from app.agents.tools.repo import git_read_handler


def test_git_read_rejects_unknown_subcommand():
    result = git_read_handler(command="push")
    assert "rejected" in result.lower() or "not allowed" in result.lower()
    result = git_read_handler(command="commit")
    assert "rejected" in result.lower() or "not allowed" in result.lower()


def test_git_read_accepts_allowed_subcommands():
    fake = MagicMock()
    fake.stdout = "fake stdout"
    fake.stderr = ""
    fake.returncode = 0

    with patch("app.agents.tools.repo.subprocess.run",
                return_value=fake) as mock_run:
        for cmd in ["log", "show", "diff", "blame", "status", "ls-tree", "branch"]:
            result = git_read_handler(command=cmd)
            assert "fake stdout" in result
            args_called = mock_run.call_args[0][0]
            assert args_called[0] == "git"
            assert "-C" in args_called
            assert "/repo" in args_called
            assert cmd in args_called


def test_git_read_passes_args_safely():
    fake = MagicMock()
    fake.stdout = "log output here"
    fake.stderr = ""
    fake.returncode = 0
    with patch("app.agents.tools.repo.subprocess.run",
                return_value=fake) as mock_run:
        git_read_handler(command="log", args=["-5", "--oneline"])
        args_called = mock_run.call_args[0][0]
        assert "-5" in args_called
        assert "--oneline" in args_called
        # Should be passed as list, NOT joined into shell string
        assert isinstance(args_called, list)


def test_git_read_truncates_large_output():
    huge = "x" * 100_000
    fake = MagicMock()
    fake.stdout = huge
    fake.stderr = ""
    fake.returncode = 0
    with patch("app.agents.tools.repo.subprocess.run", return_value=fake):
        result = git_read_handler(command="log")
        assert len(result.encode("utf-8")) <= 50_000 + 200


def test_git_read_returns_stderr_on_nonzero_exit():
    fake = MagicMock()
    fake.stdout = ""
    fake.stderr = "fatal: not a git repository"
    fake.returncode = 128
    with patch("app.agents.tools.repo.subprocess.run", return_value=fake):
        result = git_read_handler(command="log")
        assert "not a git repository" in result
        assert "exit 128" in result or "128" in result
```

- [ ] **Step 3: Run the test — verify it fails (ImportError)**

Run: `cd backend && pytest tests/test_agents_tools_git_read.py -v`
Expected: FAIL.

- [ ] **Step 4: Implement `git_read`**

Create `backend/app/agents/tools/repo.py`:

```python
"""Repo access tools: git_read, read_repo_file.

git_read runs read-only git subcommands against the bind-mounted repo
at /repo. Subcommand allowlist enforced; args passed as a list (no
shell). Stderr surfaced on non-zero exit so the agent can recover.
"""
from __future__ import annotations
import subprocess

from . import ToolDef, register_tool


REPO_PATH = "/repo"
GIT_READ_TIMEOUT_SECONDS = 10
GIT_READ_RESULT_CAP_BYTES = 50_000

ALLOWED_GIT_SUBCOMMANDS = {
    "log", "show", "diff", "blame", "status", "ls-tree", "branch",
}


def _truncate(s: str, cap_bytes: int) -> str:
    b = s.encode("utf-8")
    if len(b) <= cap_bytes:
        return s
    return b[:cap_bytes].decode("utf-8", errors="ignore") + (
        f"\n\n…[truncated at {cap_bytes} bytes]"
    )


def git_read_handler(command: str, args: list[str] | None = None) -> str:
    if command not in ALLOWED_GIT_SUBCOMMANDS:
        return (f"[rejected: subcommand '{command}' not allowed. "
                f"Allowed: {', '.join(sorted(ALLOWED_GIT_SUBCOMMANDS))}]")

    args = args or []
    # Defence: refuse shell metachars (just in case args is a string-y type)
    for a in args:
        if not isinstance(a, str):
            return f"[rejected: non-string arg {a!r}]"
        if any(ch in a for ch in (";", "&&", "||", "|", "`", "\n")):
            return f"[rejected: arg contains shell metacharacter: {a!r}]"

    cmd = ["git", "-C", REPO_PATH, command, *args]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=GIT_READ_TIMEOUT_SECONDS,
            check=False,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return f"[git_read timeout after {GIT_READ_TIMEOUT_SECONDS}s]"
    except FileNotFoundError:
        return "[rejected: git is not installed in this container]"

    if proc.returncode != 0:
        return f"[git exit {proc.returncode}]\nstderr: {proc.stderr}"

    return _truncate(proc.stdout, GIT_READ_RESULT_CAP_BYTES)


register_tool(ToolDef(
    name="git_read",
    description=(
        "Run a read-only git command against the Nano EASM repo. "
        "Allowed subcommands: log, show, diff, blame, status, ls-tree, "
        "branch. Pass args as a list (e.g. command='log', args=['-5', "
        "'--oneline']). Output truncated to 50 KB."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "enum": sorted(ALLOWED_GIT_SUBCOMMANDS),
            },
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional arguments to pass to the subcommand.",
            },
        },
        "required": ["command"],
    },
    handler=git_read_handler,
    idempotent=True,
    result_cap_bytes=GIT_READ_RESULT_CAP_BYTES,
))
```

- [ ] **Step 5: Register the module**

Append to `backend/app/agents/tools/__init__.py`:

```python
from . import repo  # noqa: F401,E402
```

- [ ] **Step 6: Run the tests**

Run: `cd backend && pytest tests/test_agents_tools_git_read.py -v`
Expected: all PASS.

- [ ] **Step 7: Run the full suite**

Run: `cd backend && pytest tests/ 2>&1 | tail -5`
Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add docker-compose.yml backend/app/agents/tools/repo.py backend/app/agents/tools/__init__.py backend/tests/test_agents_tools_git_read.py
git commit -m "feat(agents): git_read tool + repo bind-mount"
```

---

### Task 9: `read_repo_file` tool with denylist

**Files:**
- Modify: `backend/app/agents/tools/repo.py` (append handler + registration)
- Test: `backend/tests/test_agents_tools_read_repo_file.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_tools_read_repo_file.py`:

```python
import os
import tempfile
from unittest.mock import patch
from app.agents.tools.repo import read_repo_file_handler


def test_read_repo_file_returns_contents(tmp_path):
    """Point REPO_PATH at a temp dir for the test, then verify reads."""
    f = tmp_path / "hello.txt"
    f.write_text("Hello, world!\n")

    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        result = read_repo_file_handler(path="hello.txt")
        assert "Hello, world!" in result


def test_read_repo_file_blocks_dotgit(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n")

    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        result = read_repo_file_handler(path=".git/config")
        assert "rejected" in result.lower() or "denied" in result.lower()


def test_read_repo_file_blocks_env_files(tmp_path):
    (tmp_path / ".env").write_text("SECRET=foo\n")
    (tmp_path / ".env.local").write_text("KEY=bar\n")
    (tmp_path / ".env.production").write_text("DB=baz\n")

    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        for path in [".env", ".env.local", ".env.production"]:
            result = read_repo_file_handler(path=path)
            assert ("rejected" in result.lower()
                    or "denied" in result.lower())


def test_read_repo_file_blocks_key_files(tmp_path):
    (tmp_path / "server.key").write_text("-----BEGIN PRIVATE KEY-----\n")
    (tmp_path / "cert.pem").write_text("-----BEGIN CERTIFICATE-----\n")
    (tmp_path / "bundle.p12").write_bytes(b"\x30\x82")

    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        for path in ["server.key", "cert.pem", "bundle.p12"]:
            result = read_repo_file_handler(path=path)
            assert ("rejected" in result.lower()
                    or "denied" in result.lower())


def test_read_repo_file_blocks_path_traversal(tmp_path):
    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        for bad in ["../etc/passwd", "../../home", "subdir/../../../etc/passwd"]:
            result = read_repo_file_handler(path=bad)
            assert ("rejected" in result.lower()
                    or "outside" in result.lower())


def test_read_repo_file_blocks_absolute_paths(tmp_path):
    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        result = read_repo_file_handler(path="/etc/passwd")
        assert ("rejected" in result.lower()
                or "absolute" in result.lower())


def test_read_repo_file_truncates_huge_files(tmp_path):
    huge = "x" * 200_000  # 200 KB
    f = tmp_path / "big.txt"
    f.write_text(huge)

    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        result = read_repo_file_handler(path="big.txt")
        assert len(result.encode("utf-8")) <= 100_000 + 200
        assert "truncated" in result.lower() or "too large" in result.lower()


def test_read_repo_file_handles_missing_file(tmp_path):
    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        result = read_repo_file_handler(path="nonexistent.txt")
        assert "not found" in result.lower() or "no such file" in result.lower()


def test_read_repo_file_rejects_symlinks(tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("contents")
    link = tmp_path / "link.txt"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        # Symlinks not supported on this OS (Windows in some configs)
        return

    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        result = read_repo_file_handler(path="link.txt")
        assert "rejected" in result.lower() or "symlink" in result.lower()
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_tools_read_repo_file.py -v`
Expected: FAIL with ImportError.

- [ ] **Step 3: Append `read_repo_file_handler` to `repo.py`**

Append to `backend/app/agents/tools/repo.py`:

```python
import fnmatch
import os
from pathlib import Path


READ_REPO_FILE_RESULT_CAP_BYTES = 100_000

DENYLIST_PATTERNS = (
    ".git/*",
    ".env",
    ".env.*",
    "*.key",
    "*.pem",
    "*.p12",
)


def _matches_denylist(rel_path: str) -> bool:
    """Check the relative path against the denylist patterns. Each segment
    of the path is also checked against the patterns so '.env' anywhere
    in the path matches."""
    rel = rel_path.replace("\\", "/")
    for pattern in DENYLIST_PATTERNS:
        if fnmatch.fnmatch(rel, pattern):
            return True
        # Also match each path segment (catches subdir/.env)
        for seg in rel.split("/"):
            if fnmatch.fnmatch(seg, pattern):
                return True
    return False


def read_repo_file_handler(path: str) -> str:
    if os.path.isabs(path):
        return f"[rejected: absolute paths not allowed; got '{path}']"
    if ".." in Path(path).parts:
        return f"[rejected: path traversal not allowed; got '{path}']"
    if _matches_denylist(path):
        return f"[rejected: '{path}' matches denylist (.git/, .env*, *.key, *.pem, *.p12)]"

    full = (Path(REPO_PATH) / path).resolve()
    # Final sanity check: resolved path must still be under REPO_PATH
    try:
        full.relative_to(Path(REPO_PATH).resolve())
    except ValueError:
        return f"[rejected: resolved path is outside repo root]"

    if not full.exists():
        return f"[file not found: '{path}']"
    if full.is_symlink():
        return f"[rejected: symlinks not allowed; '{path}' is a symlink]"
    if not full.is_file():
        return f"[rejected: '{path}' is not a regular file]"

    try:
        data = full.read_bytes()
    except OSError as e:
        return f"[read error: {e}]"

    if len(data) > READ_REPO_FILE_RESULT_CAP_BYTES:
        excerpt = data[:READ_REPO_FILE_RESULT_CAP_BYTES].decode("utf-8", errors="replace")
        return (excerpt + f"\n\n…[file too large; truncated at "
                f"{READ_REPO_FILE_RESULT_CAP_BYTES} bytes. "
                f"Use git_read 'show HEAD:{path}' for a specific revision "
                f"or ask for a smaller range.]")

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace") + (
            "\n\n…[file is not valid UTF-8; rendered with replacement chars]"
        )


register_tool(ToolDef(
    name="read_repo_file",
    description=(
        "Read a file from the Nano EASM repo by its path relative to repo "
        "root. Example: 'backend/app/agents/runtime.py'. Returns file text. "
        "Denylist blocks .git/, .env*, *.key, *.pem, *.p12. Symlinks "
        "rejected. 100 KB cap; larger files return a truncation notice."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path relative to the repo root.",
            },
        },
        "required": ["path"],
    },
    handler=read_repo_file_handler,
    idempotent=True,
    result_cap_bytes=READ_REPO_FILE_RESULT_CAP_BYTES,
))
```

- [ ] **Step 4: Run the tests**

Run: `cd backend && pytest tests/test_agents_tools_read_repo_file.py -v`
Expected: all PASS (one may skip if running on Windows without symlink support).

- [ ] **Step 5: Run the full suite**

Run: `cd backend && pytest tests/ 2>&1 | tail -5`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/app/agents/tools/repo.py backend/tests/test_agents_tools_read_repo_file.py
git commit -m "feat(agents): read_repo_file tool with denylist + path-traversal defence"
```

---

### Task 10: `github_query` tool

**Files:**
- Create: `backend/app/agents/tools/github.py`
- Modify: `backend/app/agents/tools/__init__.py` (add `from . import github`)
- Test: `backend/tests/test_agents_tools_github_query.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_tools_github_query.py`:

```python
from unittest.mock import patch, MagicMock
from app.agents.tools.github import github_query_handler


def test_github_query_calls_api(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN_AGENTS", "ghp_fake_token")

    fake = MagicMock()
    fake.status_code = 200
    fake.text = '[{"sha":"abc123","commit":{"message":"hello"}}]'
    fake.raise_for_status = MagicMock()

    with patch("app.agents.tools.github.requests.get", return_value=fake) as m:
        result = github_query_handler(endpoint="repos/foo/bar/commits")
        assert "abc123" in result
        called_url = m.call_args[0][0]
        assert called_url == "https://api.github.com/repos/foo/bar/commits"
        # Auth header present
        headers = m.call_args[1]["headers"]
        assert "token" in headers["Authorization"]


def test_github_query_passes_params(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN_AGENTS", "ghp_fake_token")

    fake = MagicMock()
    fake.status_code = 200
    fake.text = "[]"
    fake.raise_for_status = MagicMock()
    with patch("app.agents.tools.github.requests.get", return_value=fake) as m:
        github_query_handler(endpoint="repos/foo/bar/pulls",
                              params={"state": "merged", "per_page": 5})
        kw = m.call_args[1]
        assert kw["params"] == {"state": "merged", "per_page": 5}


def test_github_query_rejects_full_urls(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN_AGENTS", "ghp_fake_token")
    result = github_query_handler(endpoint="https://api.github.com/repos/foo/bar")
    assert "rejected" in result.lower() or "relative path" in result.lower()


def test_github_query_surfaces_rate_limit(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN_AGENTS", "ghp_fake_token")
    fake = MagicMock()
    fake.status_code = 403
    fake.headers = {
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": "1735689600",
    }
    fake.text = '{"message":"API rate limit exceeded"}'

    def _raise(*a, **kw):
        from requests.exceptions import HTTPError
        raise HTTPError(response=fake)
    fake.raise_for_status = _raise

    with patch("app.agents.tools.github.requests.get", return_value=fake):
        result = github_query_handler(endpoint="repos/foo/bar")
        assert "rate limit" in result.lower()
        assert "remaining" in result.lower() or "reset" in result.lower()


def test_github_query_missing_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN_AGENTS", raising=False)
    result = github_query_handler(endpoint="repos/foo/bar")
    assert "GITHUB_TOKEN_AGENTS" in result
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_tools_github_query.py -v`
Expected: FAIL with ImportError.

- [ ] **Step 3: Implement `github_query`**

Create `backend/app/agents/tools/github.py`:

```python
"""github_query tool — read-only GitHub REST API access."""
from __future__ import annotations
import os

import requests

from . import ToolDef, register_tool


GITHUB_API_BASE = "https://api.github.com"
GITHUB_QUERY_TIMEOUT_SECONDS = 10
GITHUB_QUERY_RESULT_CAP_BYTES = 50_000


def _truncate(s: str, cap_bytes: int) -> str:
    b = s.encode("utf-8")
    if len(b) <= cap_bytes:
        return s
    return b[:cap_bytes].decode("utf-8", errors="ignore") + (
        f"\n\n…[truncated at {cap_bytes} bytes]"
    )


def github_query_handler(endpoint: str, params: dict | None = None) -> str:
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        return ("[rejected: pass a relative path like "
                "'repos/OWNER/REPO/commits', not a full URL]")

    token = os.environ.get("GITHUB_TOKEN_AGENTS")
    if not token:
        return ("[GITHUB_TOKEN_AGENTS env var is not set; "
                "github_query is unavailable]")

    url = f"{GITHUB_API_BASE}/{endpoint.lstrip('/')}"
    try:
        resp = requests.get(
            url,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            params=params or {},
            timeout=GITHUB_QUERY_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        return _truncate(resp.text, GITHUB_QUERY_RESULT_CAP_BYTES)
    except requests.exceptions.HTTPError as e:
        resp = e.response
        status = resp.status_code if resp is not None else "?"
        if status == 403 and resp is not None and resp.headers.get(
            "X-RateLimit-Remaining", "1"
        ) == "0":
            reset = resp.headers.get("X-RateLimit-Reset", "?")
            return (f"[GitHub rate limit hit. Remaining: 0. "
                    f"Reset (epoch): {reset}. "
                    f"Try git_read instead, or wait until reset.]")
        body = (resp.text or "")[:500] if resp is not None else ""
        return f"[GitHub HTTP {status}: {body}]"
    except requests.exceptions.RequestException as e:
        return f"[github_query error: {type(e).__name__}: {e}]"


register_tool(ToolDef(
    name="github_query",
    description=(
        "Read-only GitHub REST API. Pass a relative endpoint path: "
        "e.g. 'repos/OWNER/REPO/commits', 'repos/OWNER/REPO/pulls?state=merged', "
        "'repos/OWNER/REPO/contents/path/to/file'. Returns the JSON response as "
        "a string. Only GET; no POST/PUT/PATCH/DELETE."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "endpoint": {
                "type": "string",
                "description": "Relative endpoint path (no leading https://).",
            },
            "params": {
                "type": "object",
                "description": "Optional query string parameters.",
                "additionalProperties": True,
            },
        },
        "required": ["endpoint"],
    },
    handler=github_query_handler,
    idempotent=False,
    result_cap_bytes=GITHUB_QUERY_RESULT_CAP_BYTES,
))
```

- [ ] **Step 4: Register the module**

Append to `backend/app/agents/tools/__init__.py`:

```python
from . import github  # noqa: F401,E402
```

- [ ] **Step 5: Wire `github_query`, `git_read`, `read_repo_file` to Rob + Aisha**

Edit `backend/app/agents/profiles/engineer/agent.md`:

```yaml
allowed_tools:
  - read_internal_api
  - web_fetch
  - web_search
  - git_read
  - github_query
  - read_repo_file
```

Edit `backend/app/agents/profiles/qa/agent.md`:

```yaml
allowed_tools:
  - read_internal_api
  - web_fetch
  - git_read
  - github_query
  - read_repo_file
```

- [ ] **Step 6: Verify profiles load**

```bash
cd backend && python -c "
from app.agents.profile_loader import load_profile_by_name
p = load_profile_by_name('engineer')
print('Rob:', p.allowed_tools)
p = load_profile_by_name('qa')
print('Aisha:', p.allowed_tools)
"
```

Expected: Rob and Aisha show their full tool lists.

- [ ] **Step 7: Run the full suite**

Run: `cd backend && pytest tests/ 2>&1 | tail -5`
Expected: all PASS.

- [ ] **Step 8: Add `GITHUB_TOKEN_AGENTS` to docker-compose env list**

In `docker-compose.yml`, in the `easm-backend` `environment:` block (the agent-platform sub-section we added in Phase 1), add:

```yaml
      GITHUB_TOKEN_AGENTS: ${GITHUB_TOKEN_AGENTS:-${GITHUB_TOKEN:-}}
```

This reuses the existing `GITHUB_TOKEN` env var as a fallback so the user doesn't need to set a new one for initial testing.

- [ ] **Step 9: Commit**

```bash
git add backend/app/agents/tools/github.py backend/app/agents/tools/__init__.py backend/app/agents/profiles/engineer/agent.md backend/app/agents/profiles/qa/agent.md backend/tests/test_agents_tools_github_query.py docker-compose.yml
git commit -m "feat(agents): github_query tool + wire repo tools to Rob and Aisha"
```

---

## Stage D — Polish

### Task 11: Update agent system prompts to mention tools

**Files:**
- Modify: all 6 `backend/app/agents/profiles/<name>/agent.md` (system-prompt body)

- [ ] **Step 1: Add a "My tools" section to each agent's system prompt**

For each agent, insert a new section before the closing "My voice / personality" section. The exact text per agent:

**Sam (`founder-ops/agent.md`):**

After the "Hard rules" block, before "My voice", add:

```markdown
My tools:
- `read_internal_api(endpoint, params)` — I can pull fresh stats, recent findings, recent contact requests, recent audit-log entries, and recent scans from Nano EASM.
- `web_fetch(url)` — I can read public web pages (docs, articles, status pages).
- `web_search(query)` — I can search the web for current information.

I use these freely; the director doesn't need to feed me data I can look up myself.
```

**Rob (`engineer/agent.md`):**

```markdown
My tools:
- `read_internal_api(endpoint, params)` — I can read Nano EASM's runtime state.
- `web_fetch(url)` — I can read library docs, RFCs, GitHub issue threads.
- `web_search(query)` — I can search for solutions to specific errors.
- `git_read(command, args)` — I can run `log`, `show`, `diff`, `blame`, `status`, `ls-tree`, `branch` against the Nano EASM repo.
- `github_query(endpoint, params)` — I can query the GitHub REST API for PRs, commits, issues, file contents.
- `read_repo_file(path)` — I can read any file in the repo by path. The .git/, .env*, *.key, *.pem, *.p12 patterns are blocked.

When the director asks me a code question, I look at the actual code instead of guessing.
```

**Aisha (`qa/agent.md`):**

```markdown
My tools:
- `read_internal_api(endpoint, params)` — I can read recent scans, recent findings, and audit-log entries from Nano EASM.
- `web_fetch(url)` — I can read documentation, RFCs, library test docs.
- `git_read(command, args)` — I can inspect the repo state, recent commits, and diffs.
- `github_query(endpoint, params)` — I can query GitHub for PRs and CI status.
- `read_repo_file(path)` — I can read any test file or implementation file by path.

I look at the real code and the real data before reporting on a feature's testability.
```

**Maya (`security-analyst/agent.md`):**

```markdown
My tools:
- `read_internal_api(endpoint, params)` — I can pull recent findings, scan history, and audit log.
- `web_fetch(url)` — I can read NVD entries, MITRE ATT&CK pages, vendor advisories, CVE writeups.
- `web_search(query)` — I can search for recent threat intel, exploit availability, and CVE updates.

When I cite a CVE or severity, I've actually looked at the source.
```

**Ava (`strategy/agent.md`):**

```markdown
My tools:
- `read_internal_api(endpoint, params)` — I can pull aggregate stats and recent contact requests.
- `web_fetch(url)` — I can read competitor product pages, pricing pages, blog posts.
- `web_search(query)` — I can search for recent competitor announcements and market news.

When I make a market claim, I cite a source I actually fetched or searched.
```

**John (`voice/agent.md`):**

```markdown
My tools:
- `read_internal_api(endpoint, params)` — I can pull recent contact requests (for support replies), recent findings (for context in release notes), and recent scans.
- `web_fetch(url)` — I can read style guides, examples, and reference content.
- `web_search(query)` — I can search for context, examples, or competitor copy.

I never invent quotes or stats. If I cite something, I can point at the source.
```

- [ ] **Step 2: Verify all profiles still parse**

```bash
cd backend && python -c "
from app.agents.profile_loader import load_profile_by_name
for n in ['founder-ops','engineer','qa','security-analyst','strategy','voice']:
    p = load_profile_by_name(n)
    print(f'  {p.display_name:6} | prompt {len(p.system_prompt)} chars | tools {len(p.allowed_tools)}')
"
```

Expected: 6 lines, each agent's prompt length up by 100-300 chars from the addition.

- [ ] **Step 3: Run the full suite**

Run: `cd backend && pytest tests/ 2>&1 | tail -5`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add backend/app/agents/profiles/
git commit -m "feat(agents): each agent's system prompt mentions its tools"
```

---

### Task 12: End-to-end smoke test + CLAUDE.md update

**Files:**
- Modify: `backend/scripts/smoke_test.py` (extend with tool-use checks)
- Modify: `CLAUDE.md` (Phase 2A section)

- [ ] **Step 1: Extend `smoke_test.py` with a tool-use check**

In `backend/scripts/smoke_test.py`, add a new stage before the existing cleanup block:

```python
        # ------------------------------------------------------------
        # Stage 8 (Phase 2A): tool use end-to-end with FakeAnthropicClient
        # ------------------------------------------------------------
        print("\n[8] Tool-use loop end-to-end (fake LLM)")
        from app.agents.runtime import run_agent
        from app.agents.anthropic_client import FakeAnthropicClient
        from app.agents.tools import TOOL_REGISTRY

        check("read_internal_api tool registered",
              "read_internal_api" in TOOL_REGISTRY)
        check("web_fetch tool registered", "web_fetch" in TOOL_REGISTRY)
        check("web_search tool registered", "web_search" in TOOL_REGISTRY)
        check("git_read tool registered", "git_read" in TOOL_REGISTRY)
        check("github_query tool registered", "github_query" in TOOL_REGISTRY)
        check("read_repo_file tool registered",
              "read_repo_file" in TOOL_REGISTRY)

        # Run founder-ops with a scripted tool_use that calls read_internal_api
        fake = FakeAnthropicClient(scripted_responses=[
            {"stop_reason": "tool_use",
             "tool_uses": [{"id": "smoke_t1", "name": "read_internal_api",
                             "input": {"endpoint": "stats/weekly"}}]},
            {"stop_reason": "end_turn",
             "text": "stats look OK based on the tool result"},
        ])
        try:
            tool_run = run_agent(
                agent_name="founder-ops",
                user_prompt="check the weekly stats for me",
                skill="smoke-test-tools",
                memory_tags=[],
                client=fake,
            )
            check("tool-use run completes with success",
                  tool_run.run.status == "success",
                  f"got status={tool_run.run.status} error={tool_run.run.error}")
            tool_msgs = [m for m in tool_run.thread.messages if m.role == "tool"]
            check("at least one tool message persisted",
                  len(tool_msgs) >= 1)
            if tool_msgs:
                check("tool message has tool_name and output",
                      "tool_name" in tool_msgs[0].content
                      and "output" in tool_msgs[0].content)
        except Exception as e:
            check("tool-use run completes without exception", False, str(e))
```

Then verify it still cleans up — the existing cleanup block at the end of `main()` should already cover the new test row via the `ApiKey.query.filter_by(name="smoke-test-founder-ops").delete()` pattern.

- [ ] **Step 2: Run the extended smoke test locally**

```bash
cd backend && python -m scripts.smoke_test
```

Expected: all previous 28 checks plus the 6 new tool-registry checks + 3 new run checks pass. Total ~37 passed, 0 failed.

If any of the registry checks fail (e.g. `web_search tool registered` is FAIL), it means the module's `from . import X` line wasn't appended in the corresponding task. Fix and re-run.

- [ ] **Step 3: Update CLAUDE.md**

In `CLAUDE.md`, find the existing "## Internal Agent Platform (Phase 1)" section. Just before the "### Phase 2 (to be planned next)" sub-heading, add:

```markdown
### Phase 2A (tool use, shipped)

Agents now have tool use. The 6 read-only tools available are:

| Tool | Used by |
|---|---|
| `read_internal_api(endpoint, params)` | All agents (read 5 internal endpoints) |
| `web_fetch(url)` | All agents (HTML→text, 50 KB cap, SSRF defence) |
| `web_search(query)` | Sam, Rob, Maya, Ava, John (Anthropic native) |
| `git_read(command, args)` | Rob, Aisha (read-only subcommands: log/show/diff/blame/status/ls-tree/branch) |
| `github_query(endpoint, params)` | Rob, Aisha (GitHub REST, read-only) |
| `read_repo_file(path)` | Rob, Aisha (denylist: .git/, .env*, *.key, *.pem, *.p12) |

Internal API expanded with 4 new endpoints: `/api/internal/findings/recent`, `/contact-requests/recent`, `/audit-log/recent`, `/scans/recent`. All gated on agent-key scope.

Repo is bind-mounted into `easm-backend` at `/repo:ro` via `${HOST_REPO_PATH:-./}` in docker-compose.

The runtime is now a multi-turn loop: agent emits `tool_use` → handler runs → tool_result appended → next turn → continues until `end_turn` or `tool_call_cap_per_run` is reached.
```

And replace the existing "### Phase 2 (to be planned next)" block with:

```markdown
### Phase 2B (still to plan)

- Write tools: `github_pr_create`, `send_email_draft`, `update_agent_memory`
- Approval-queued tool execution pattern (handler creates pending_action; agent gets `[queued for approval]` as tool result; founder approves; background worker retries)
- Tuesday + Wednesday weekly briefs (Ava `competitor-pulse`, Maya `weekly-finding-brief`)
- Memory hygiene weekly job
- Customer-facing send service for approved drafts
- Hand-off queue between agents
```

- [ ] **Step 4: Run the full suite one more time**

Run: `cd backend && pytest tests/ 2>&1 | tail -5`
Expected: all PASS. Phase 2A's added tests put us at ~70+ tests total.

- [ ] **Step 5: Commit**

```bash
git add backend/scripts/smoke_test.py CLAUDE.md
git commit -m "docs+test: Phase 2A smoke test extensions + CLAUDE.md update"
```

---

## Self-review

**Spec coverage:**

- ✅ Multi-turn tool-use loop in `runtime.py` — Task 2
- ✅ Six tools (`read_internal_api`, `web_fetch`, `web_search`, `git_read`, `github_query`, `read_repo_file`) — Tasks 3, 5, 6, 8, 9, 10
- ✅ Four new `/api/internal/*` endpoints — Task 4
- ✅ Read-only bind-mount of host repo — Task 8
- ✅ Per-agent tool allowlist enforcement (via `expose_tools_for` + profile `allowed_tools`) — Task 1 + Tasks 7 & 10
- ✅ Per-thread cache — DEFERRED (left out of the plan as a non-blocking optimisation; flagged for follow-up)
- ✅ Tool result truncation caps — Tasks 5, 8, 9, 10 (`_truncate` helper)
- ✅ Anthropic native web_search support — Task 6
- ✅ Profile updates (tools + system prompts) — Tasks 3, 7, 10, 11
- ✅ Smoke test extension — Task 12

Gap: per-thread tool cache wasn't included as a task. It's a pure latency/cost optimisation; not blocking for shipping. Adding a follow-up "Task 13: per-thread tool cache" if you want it before merging — for now, intentionally left as a known follow-up.

**Placeholder scan:** No "TBD", "TODO", "implement later", "similar to Task N". Every step contains the actual content.

**Type consistency:** `ToolDef` has the same fields throughout (Tasks 1, 6 add `server_side_type` consistently). `LlmCall`/`LlmResult` shapes match between Task 1 and Task 2 usage. `RunResult` unchanged from Phase 1.

**Known caveat:** Task 4's `internal_queries.py` uses field accessors like `Finding.severity`, `ContactRequest.kind`, `AuditLog.user_email` that may need adjustment to match the actual model schema. The plan flags this with `getattr(..., None)` defensiveness, but the implementer should grep the actual model definitions and adjust if names differ. Each model is in `backend/app/models.py`.
