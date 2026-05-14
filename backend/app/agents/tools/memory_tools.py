"""Agent memory CRUD tools (Phase 2B-2).

read_agent_memory runs inline (no approval needed). Each call is
implicitly scoped to the caller's own agent_id, which the runtime
passes in as a kwarg; the tool input itself never accepts an
agent_id — there is no way for one agent to read another agent's
memory through this tool.

update_agent_memory and delete_agent_memory are write tools that
queue for the founder's approval (see runtime.py's requires_approval
branch). Their handlers are sentinels — the runtime intercepts before
the handler runs.
"""
from __future__ import annotations
import json

from . import ToolDef, register_tool
from app.agents.memory import retrieve_for_agent


def _read_agent_memory_handler(
    agent_id: str,
    key: str | None = None,
    tags: list[str] | None = None,
    limit: int = 30,
) -> str:
    """Return the caller's own agent_memory rows as a JSON string.

    agent_id is passed in by the runtime (NOT the model) — see
    runtime._execute_tool for how scoped kwargs are added before the
    handler is called. The tool's input schema does not expose
    agent_id to the model.
    """
    try:
        rows = retrieve_for_agent(
            agent_id=agent_id,
            tags=tags or None,
            top_n=max(1, min(limit, 100)),
        )
        if key is not None:
            rows = [r for r in rows if r.key == key]
        payload = [
            {
                "key": r.key,
                "value": r.value,
                "tags": r.tags,
                "source": r.source,
                "confidence": float(r.confidence) if r.confidence is not None else None,
            }
            for r in rows
        ]
        return json.dumps(payload)
    except Exception as e:
        return f"[read_agent_memory error: {type(e).__name__}: {e}]"


register_tool(ToolDef(
    name="read_agent_memory",
    description=(
        "Return rows from your own agent_memory. Scoped automatically "
        "to you — there is no way to read another agent's memory. "
        "Pass optional key (exact match) or tags (any-of filter) or "
        "neither (returns up to `limit` most-recent rows). Results "
        "come back as a JSON array of {key, value, tags, source, "
        "confidence} objects."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "key": {
                "type": "string",
                "description": "Exact key to look up. Optional.",
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Filter by any-of these tags. Optional; omit to "
                    "return all rows up to `limit`."
                ),
            },
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100,
                "default": 30,
            },
        },
    },
    handler=_read_agent_memory_handler,
    idempotent=True,
    result_cap_bytes=20000,
))


def _memory_write_sentinel(**kwargs) -> str:
    """Sentinel for update_agent_memory and delete_agent_memory. The
    runtime must intercept on requires_approval=True before this is
    called. If it runs, return a clear error so we notice."""
    return (
        "[error: memory write sentinel handler reached the synchronous "
        "path; this should never happen — the runtime should have "
        "queued this for approval instead. Check runtime's "
        "requires_approval branch.]"
    )


register_tool(ToolDef(
    name="update_agent_memory",
    description=(
        "Propose adding or updating a row in your own agent_memory. "
        "The proposal queues for the director's approval; nothing is "
        "written until they ✓. Use this when you've learned a fact "
        "worth remembering across runs (a customer preference, a "
        "recurring pattern, a domain rule). Reusing the same `key` "
        "updates the existing row in place. Scoped automatically to "
        "you — no way to write to another agent's memory."
    ),
    input_schema={
        "type": "object",
        "required": ["key", "value", "tags"],
        "properties": {
            "key": {
                "type": "string",
                "minLength": 1,
                "maxLength": 200,
                "description": (
                    "Stable identifier for this fact. Reuse the same "
                    "key to update; choose new keys for new facts. "
                    "Common shapes: 'fact:topic:detail', "
                    "'customer:acme:tier'."
                ),
            },
            "value": {
                "type": "object",
                "description": (
                    "Free-form JSON object holding the fact. Common "
                    "shape: {rule: '...'} for rule-style facts; "
                    "{n: 123, ...} for numeric facts."
                ),
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
                "description": (
                    "Filter tags used at retrieval time. Common: "
                    "topic:..., customer:..., source:meeting."
                ),
            },
            "source": {
                "type": "string",
                "description": (
                    "Where the fact came from. e.g. 'user-told', "
                    "'agent-observation', 'web-fetch'. Defaults to "
                    "'agent-observation' if omitted."
                ),
            },
            "confidence": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
                "description": "0..1; defaults to 1.0.",
            },
            "expires_at": {
                "type": "string",
                "description": (
                    "ISO 8601 timestamp; omit for facts that never "
                    "expire."
                ),
            },
        },
    },
    handler=_memory_write_sentinel,
    idempotent=False,
    result_cap_bytes=0,
    requires_approval=True,
    action_type="memory-write",
))


register_tool(ToolDef(
    name="delete_agent_memory",
    description=(
        "Propose deleting a row from your own agent_memory. The "
        "proposal queues for the director's approval. Use this when a "
        "previously-remembered fact is no longer true or relevant. "
        "Scoped automatically to you. If the key does not exist, the "
        "approval will still apply cleanly and the applied_result "
        "will say so."
    ),
    input_schema={
        "type": "object",
        "required": ["key"],
        "properties": {
            "key": {
                "type": "string",
                "minLength": 1,
                "maxLength": 200,
                "description": "Exact key of the row to delete.",
            },
        },
    },
    handler=_memory_write_sentinel,
    idempotent=False,
    result_cap_bytes=0,
    requires_approval=True,
    action_type="memory-delete",
))
