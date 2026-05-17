"""Persona-prefix message routing.

Maps Slack message text to one of the six agent IDs:
    sam   -> founder-ops      (also the default fallback)
    rob   -> engineer
    aisha -> qa
    maya  -> security-analyst
    ava   -> strategy
    john  -> voice
"""
from __future__ import annotations

import re


PERSONA_TO_AGENT: dict[str, str] = {
    "sam": "founder-ops",
    "rob": "engineer",
    "aisha": "qa",
    "maya": "security-analyst",
    "ava": "strategy",
    "john": "voice",
}

DEFAULT_AGENT_ID = "founder-ops"


def parse_message(text: str, bot_user_id: str | None = None) -> tuple[str, str]:
    """Strip bot mention + persona prefix, return (agent_id, cleaned_text)."""
    cleaned = text or ""

    if bot_user_id:
        cleaned = re.sub(rf"<@{re.escape(bot_user_id)}>\s*", "", cleaned).strip()
    else:
        cleaned = cleaned.strip()

    m = re.match(r"^([A-Za-z]+)[,\s]+(.*)$", cleaned, flags=re.DOTALL)
    if m:
        candidate = m.group(1).lower()
        if candidate in PERSONA_TO_AGENT:
            return PERSONA_TO_AGENT[candidate], m.group(2).strip()

    return DEFAULT_AGENT_ID, cleaned
