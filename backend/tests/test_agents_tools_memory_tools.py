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


def test_update_agent_memory_is_registered_and_requires_approval():
    t = TOOL_REGISTRY["update_agent_memory"]
    assert t.requires_approval is True
    assert t.action_type == "memory-write"
    assert t.idempotent is False


def test_update_agent_memory_schema_requires_key_value_tags():
    t = TOOL_REGISTRY["update_agent_memory"]
    required = set(t.input_schema.get("required", []))
    assert {"key", "value", "tags"} <= required
    # agent_id MUST NOT be in the schema — scope is server-side.
    assert "agent_id" not in t.input_schema["properties"]


def test_update_agent_memory_handler_is_sentinel():
    t = TOOL_REGISTRY["update_agent_memory"]
    out = t.handler(key="x", value={"y": 1}, tags=["z"])
    assert "should never" in out.lower() or "approval" in out.lower()


def test_delete_agent_memory_is_registered_and_requires_approval():
    t = TOOL_REGISTRY["delete_agent_memory"]
    assert t.requires_approval is True
    assert t.action_type == "memory-delete"
    assert t.idempotent is False


def test_delete_agent_memory_schema_requires_key_only():
    t = TOOL_REGISTRY["delete_agent_memory"]
    required = set(t.input_schema.get("required", []))
    assert required == {"key"}
    assert "agent_id" not in t.input_schema["properties"]


def test_delete_agent_memory_handler_is_sentinel():
    t = TOOL_REGISTRY["delete_agent_memory"]
    out = t.handler(key="x")
    assert "should never" in out.lower() or "approval" in out.lower()
