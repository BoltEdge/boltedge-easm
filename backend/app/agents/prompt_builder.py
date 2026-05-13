"""Builds the system prompt + message list for one agent run.

System prompt = profile.system_prompt + team_memory + relevant agent_memory.
Messages = thread history (if any) + current user prompt.
"""
from __future__ import annotations
from typing import Iterable

from .profile_loader import AgentProfile
from .memory import retrieve_for_agent, retrieve_team_memory
from app.models import AgentThread


def _format_team_memory_block() -> str:
    rows = retrieve_team_memory()
    if not rows:
        return ""
    bullets = "\n".join(
        f"- {r.key}: {r.value.get('rule', r.value)}" for r in rows
    )
    return f"\n\n## TEAM MEMORY (universal facts every agent must respect)\n{bullets}"


def _format_agent_memory_block(agent_id: str, tags: Iterable[str]) -> str:
    rows = retrieve_for_agent(agent_id, tags=tags or None, top_n=30)
    if not rows:
        return ""
    bullets = "\n".join(
        f"- {r.key}: {r.value}" for r in rows
    )
    return f"\n\n## YOUR MEMORY (relevant facts you've recorded)\n{bullets}"


def build_messages_and_system(
    profile: AgentProfile,
    user_prompt: str,
    thread: AgentThread | None,
    memory_tags: Iterable[str],
) -> tuple[str, list[dict]]:
    system = profile.system_prompt
    system += _format_team_memory_block()
    system += _format_agent_memory_block(profile.name, memory_tags)

    messages: list[dict] = []
    if thread is not None:
        messages.extend(_rebuild_anthropic_messages(thread.messages))
    messages.append({"role": "user", "content": user_prompt})

    return system, messages


def _rebuild_anthropic_messages(thread_messages) -> list[dict]:
    """Convert persisted AgentMessage rows into Anthropic-shaped messages.

    The DB stores three role kinds: 'user', 'assistant' (final text), and
    'tool' (one row per tool call, with tool_use_id/tool_name/input/output/
    is_error). Anthropic's API only accepts 'user' and 'assistant', and
    tool results must arrive as a user-role message with `tool_result`
    content blocks immediately AFTER an assistant-role message whose
    content includes the matching `tool_use` block.

    The runtime never persists the assistant tool_use turn (it lives only
    in the per-run in-memory messages list), so we synthesize it from the
    fields stored on each tool row. Consecutive tool rows are grouped:
    one assistant message holds all their tool_use blocks, one user
    message holds all their tool_result blocks.

    Without this, continuing a thread that contains tool calls raises a
    400 from Anthropic: 'Unexpected role "tool"'.
    """
    out: list[dict] = []
    msgs = list(thread_messages)
    i = 0
    while i < len(msgs):
        m = msgs[i]
        if m.role == "tool":
            tool_uses, tool_results = [], []
            while i < len(msgs) and msgs[i].role == "tool":
                c = msgs[i].content if isinstance(msgs[i].content, dict) else {}
                tool_uses.append({
                    "type": "tool_use",
                    "id": c.get("tool_use_id", ""),
                    "name": c.get("tool_name", ""),
                    "input": c.get("input", {}),
                })
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": c.get("tool_use_id", ""),
                    "content": c.get("output", ""),
                    "is_error": bool(c.get("is_error", False)),
                })
                i += 1
            out.append({"role": "assistant", "content": tool_uses})
            out.append({"role": "user", "content": tool_results})
        else:
            c = m.content
            text = c.get("text", "") if isinstance(c, dict) else str(c)
            # Skip empty final-assistant messages (the runtime sometimes
            # persists content={"text": ""} when a turn ended on tool_use
            # with no accompanying text). Anthropic rejects empty content.
            if m.role == "assistant" and not text:
                i += 1
                continue
            out.append({"role": m.role, "content": text})
            i += 1
    return out
