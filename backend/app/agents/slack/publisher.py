"""High-level outbound Slack dispatch.

The rest of the system (approvals.py, routes.py, the weekly skill modules)
calls these functions. They handle formatting, channel selection, and
"no broadcast channel configured" no-op behaviour.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from .client import post_as_agent


logger = logging.getLogger("agents.slack.publisher")
PUBLIC_BASE = "https://nanoeasm.com"
MESSAGE_CHAR_CAP = 3000


def _broadcast_channel() -> str:
    return os.environ.get("SLACK_BROADCAST_CHANNEL_ID", "")


def _chunk(text: str, cap: int = MESSAGE_CHAR_CAP) -> list[str]:
    if len(text) <= cap:
        return [text]
    chunks: list[str] = []
    remaining = text
    while remaining:
        chunks.append(remaining[:cap])
        remaining = remaining[cap:]
    return chunks


def broadcast_brief(agent_id: str, subject: str, body: str) -> None:
    """Post a scheduled brief to #nano-broadcast.

    Long briefs are chunked across consecutive channel posts.
    No-op when SLACK_BROADCAST_CHANNEL_ID is unset.
    """
    channel = _broadcast_channel()
    if not channel:
        return

    head = f"*{subject}*\n\n"
    chunks = _chunk(head + body, cap=MESSAGE_CHAR_CAP)
    if not post_as_agent(channel=channel, agent_id=agent_id, text=chunks[0]):
        return
    for c in chunks[1:]:
        post_as_agent(channel=channel, agent_id=agent_id, text=c)


def broadcast_approval_pending(action: Any) -> None:
    """Post an approval-pending card to #nano-broadcast.

    `action` is a PendingAction row (or duck-typed equivalent with .id,
    .agent_id, .action_type, .target).
    """
    channel = _broadcast_channel()
    if not channel:
        return
    link = f"{PUBLIC_BASE}/admin/agents/approvals/{action.id}"
    label = (action.action_type or "action").replace("-", " ").title()
    target = f" — `{action.target}`" if action.target else ""
    text = (
        f":bell: Pending approval: *{label}*{target}\n"
        f"<{link}|Review in admin>"
    )
    post_as_agent(channel=channel, agent_id=action.agent_id, text=text)


def broadcast_run_completed(run: Any) -> None:
    """Post a one-line run-completion summary to #nano-broadcast.

    Skipped silently when channel is unset OR when the run did not complete
    successfully (failures already surface via inline error posts).
    """
    channel = _broadcast_channel()
    if not channel:
        return
    if getattr(run, "status", None) != "completed":
        return

    cost = getattr(run, "cost_usd", None)
    cost_str = f"${float(cost):.2f}" if cost else "$0.00"
    text = f":white_check_mark: Run #{run.id} completed — {cost_str}"
    post_as_agent(channel=channel, agent_id=run.agent_id, text=text)
