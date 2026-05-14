"""Integration test: runtime injects caller's agent_id into
read_agent_memory tool calls so the handler can scope to the
calling agent's own memory without the model having to specify it."""
from __future__ import annotations
import dataclasses

from app.agents.runtime import run_agent
from app.agents.anthropic_client import FakeAnthropicClient
from app.agents.memory import write_memory


def _profile_with_tools(name, tools):
    from app.agents.profile_loader import load_profile_by_name
    p = load_profile_by_name(name)
    return dataclasses.replace(p, allowed_tools=tools)


def test_read_agent_memory_call_is_scoped_to_caller(db_session, monkeypatch):
    write_memory(
        agent_id="founder-ops",
        key="fact:scoped_test",
        value={"rule": "founder-ops fact"},
        tags=["topic:test"],
        source="test",
    )
    write_memory(
        agent_id="engineer",
        key="fact:scoped_test",
        value={"rule": "engineer fact"},
        tags=["topic:test"],
        source="test",
    )

    monkeypatch.setattr(
        "app.agents.runtime.load_profile_by_name",
        lambda n: _profile_with_tools(n, ["read_agent_memory"]),
    )

    fake = FakeAnthropicClient(scripted_responses=[
        {"stop_reason": "tool_use",
         "tool_uses": [{"id": "tu_1", "name": "read_agent_memory",
                         "input": {"key": "fact:scoped_test"}}]},
        {"stop_reason": "end_turn", "text": "looked it up"},
    ])
    result = run_agent(
        agent_name="founder-ops",
        user_prompt="read your memory for fact:scoped_test",
        skill=None, memory_tags=[], client=fake,
    )

    tool_msgs = [m for m in result.thread.messages if m.role == "tool"]
    assert len(tool_msgs) == 1
    output = tool_msgs[0].content["output"]
    assert "founder-ops fact" in output
    assert "engineer fact" not in output
