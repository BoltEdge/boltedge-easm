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
        for m in thread.messages:
            content = m.content.get("text", "") if isinstance(m.content, dict) else str(m.content)
            messages.append({"role": m.role, "content": content})
    messages.append({"role": "user", "content": user_prompt})

    return system, messages
