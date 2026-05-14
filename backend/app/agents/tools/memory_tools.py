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
