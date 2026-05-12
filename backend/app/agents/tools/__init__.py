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
    server_side_type: str | None = None


TOOL_REGISTRY: dict[str, ToolDef] = {}


def register_tool(tool: ToolDef) -> None:
    """Add a tool to the global registry. Overwrites by name."""
    TOOL_REGISTRY[tool.name] = tool


def anthropic_tool_spec(tool: ToolDef) -> dict:
    """Build the per-tool dict Anthropic's messages.create() accepts.
    Server-side tools (web_search etc.) use a 'type' discriminator
    instead of the input_schema shape.
    """
    if tool.server_side_type:
        return {
            "type": tool.server_side_type,
            "name": tool.name,
        }
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


# Importing the handler modules triggers their register_tool() calls.
# Keep this at the bottom to avoid circular imports.
from . import internal_api  # noqa: F401,E402
from . import web  # noqa: F401,E402
from . import repo  # noqa: F401,E402
