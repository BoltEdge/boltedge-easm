"""Phase 2B-1: write-class tools queue for approval instead of executing inline."""
import dataclasses

from app.agents.runtime import run_agent
from app.agents.anthropic_client import FakeAnthropicClient
from app.agents.tools import ToolDef, register_tool
from app.models import PendingAction


def _profile_with_tools(name, tools):
    """Helper: load real profile, override its allowed_tools."""
    from app.agents.profile_loader import load_profile_by_name
    p = load_profile_by_name(name)
    return dataclasses.replace(p, allowed_tools=tools)


def test_write_tool_call_queues_instead_of_executing(db_session, monkeypatch):
    """A tool with requires_approval=True must NOT call its handler.
    Instead the runtime must create a pending_action row and return
    [queued] as the tool result string."""

    handler_was_called = []

    def _should_not_be_called(**kwargs):
        handler_was_called.append(kwargs)
        return "this should not appear"

    register_tool(ToolDef(
        name="x_write_test",
        description="A write tool for tests.",
        input_schema={"type": "object",
                       "properties": {"label": {"type": "string"}},
                       "required": ["label"]},
        handler=_should_not_be_called,
        idempotent=False,
        result_cap_bytes=0,
        requires_approval=True,
        action_type="x-test-action",
    ))

    monkeypatch.setattr(
        "app.agents.runtime.load_profile_by_name",
        lambda n: _profile_with_tools(n, ["x_write_test"]),
    )

    fake = FakeAnthropicClient(scripted_responses=[
        {"stop_reason": "tool_use",
         "tool_uses": [{"id": "tu_1", "name": "x_write_test",
                         "input": {"label": "hello"}}]},
        {"stop_reason": "end_turn",
         "text": "I've proposed the action; awaiting your approval."},
    ])
    result = run_agent(
        agent_name="founder-ops",
        user_prompt="please propose the test action",
        skill=None, memory_tags=[], client=fake,
    )

    assert handler_was_called == []
    assert result.run.status == "success"
    assert "awaiting your approval" in (result.text or "").lower()

    pending = (
        PendingAction.query
        .filter_by(action_type="x-test-action", agent_id="founder-ops")
        .order_by(PendingAction.id.desc())
        .first()
    )
    assert pending is not None
    assert pending.payload == {"label": "hello"}
    assert pending.run_id == result.run.id
    assert pending.decision is None

    tool_msgs = [m for m in result.thread.messages if m.role == "tool"]
    assert len(tool_msgs) == 1
    assert "queued for approval" in tool_msgs[0].content["output"]


def test_read_tool_still_executes_inline(db_session, monkeypatch):
    """Regression: a tool with requires_approval=False must still call
    its handler (existing Phase 2A behavior)."""

    handler_called = []

    def _real_handler(**kwargs):
        handler_called.append(kwargs)
        return "real result"

    register_tool(ToolDef(
        name="x_read_test",
        description="A read tool for tests.",
        input_schema={"type": "object",
                       "properties": {"q": {"type": "string"}},
                       "required": ["q"]},
        handler=_real_handler,
        idempotent=True,
        result_cap_bytes=1000,
        requires_approval=False,
    ))

    monkeypatch.setattr(
        "app.agents.runtime.load_profile_by_name",
        lambda n: _profile_with_tools(n, ["x_read_test"]),
    )

    fake = FakeAnthropicClient(scripted_responses=[
        {"stop_reason": "tool_use",
         "tool_uses": [{"id": "tu_1", "name": "x_read_test",
                         "input": {"q": "hello"}}]},
        {"stop_reason": "end_turn", "text": "done"},
    ])
    result = run_agent(
        agent_name="founder-ops",
        user_prompt="use the read tool", skill=None,
        memory_tags=[], client=fake,
    )

    assert handler_called == [{"q": "hello"}]
    assert result.run.status == "success"
    new_pending = PendingAction.query.filter_by(
        action_type="x-test-action").count()
    assert new_pending == 0
