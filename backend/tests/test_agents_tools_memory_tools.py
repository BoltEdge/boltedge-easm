"""Tests for agent memory CRUD tools (Phase 2B-2)."""
import json

from app.agents.tools import TOOL_REGISTRY
from app.agents.memory import write_memory


def test_read_agent_memory_is_registered():
    assert "read_agent_memory" in TOOL_REGISTRY


def test_read_agent_memory_is_not_approval_gated():
    t = TOOL_REGISTRY["read_agent_memory"]
    assert t.requires_approval is False
    assert t.idempotent is True


def test_read_agent_memory_handler_returns_caller_rows(db_session):
    """Handler scopes to the calling agent_id passed by the runtime."""
    write_memory(
        agent_id="founder-ops",
        key="fact:test_a",
        value={"rule": "value A"},
        tags=["topic:test"],
        source="test",
    )
    write_memory(
        agent_id="engineer",
        key="fact:test_b",
        value={"rule": "value B"},
        tags=["topic:test"],
        source="test",
    )

    t = TOOL_REGISTRY["read_agent_memory"]
    out = t.handler(agent_id="founder-ops")
    parsed = json.loads(out)
    keys = [row["key"] for row in parsed]
    assert "fact:test_a" in keys
    assert "fact:test_b" not in keys  # other agent's row not visible


def test_read_agent_memory_handler_filters_by_tags(db_session):
    write_memory(
        agent_id="founder-ops",
        key="fact:t1",
        value={"n": 1},
        tags=["topic:metrics"],
        source="test",
    )
    write_memory(
        agent_id="founder-ops",
        key="fact:t2",
        value={"n": 2},
        tags=["topic:other"],
        source="test",
    )

    t = TOOL_REGISTRY["read_agent_memory"]
    out = t.handler(agent_id="founder-ops", tags=["topic:metrics"])
    parsed = json.loads(out)
    keys = [row["key"] for row in parsed]
    assert keys == ["fact:t1"]


def test_read_agent_memory_handler_empty_for_unknown_agent(db_session):
    t = TOOL_REGISTRY["read_agent_memory"]
    out = t.handler(agent_id="nonexistent-agent")
    assert json.loads(out) == []
