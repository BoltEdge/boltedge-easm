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
