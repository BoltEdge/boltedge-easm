"""Slack Web API client — chat.postMessage with chat:write.customize.

One bot identity (the @nano app), but every post sets username + icon_url
so each agent looks like their own persona in Slack.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import requests

from app.agents.profile_loader import load_profile_by_name


logger = logging.getLogger("agents.slack.client")
POST_URL = "https://slack.com/api/chat.postMessage"
TIMEOUT_SECONDS = 10


def post_as_agent(
    channel: str,
    agent_id: str,
    text: str,
    thread_ts: str | None = None,
) -> bool:
    """Post a message to Slack under the agent's persona.

    Returns True iff Slack returned ok=True. Logs + returns False on any
    failure (network, 4xx, 5xx, ok=false). NEVER raises.
    """
    token = os.environ.get("SLACK_BOT_TOKEN_AGENTS", "")
    if not token:
        logger.info("slack post skipped — SLACK_BOT_TOKEN_AGENTS unset")
        return False

    try:
        profile = load_profile_by_name(agent_id)
    except Exception as e:
        logger.warning("slack post skipped — profile %r missing: %s", agent_id, e)
        return False

    payload: dict[str, Any] = {
        "channel": channel,
        "text": text,
        "username": profile.slack_display_name or agent_id,
    }
    if profile.slack_icon_url:
        payload["icon_url"] = profile.slack_icon_url
    if thread_ts:
        payload["thread_ts"] = thread_ts

    try:
        resp = requests.post(
            POST_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json; charset=utf-8",
            },
            json=payload,
            timeout=TIMEOUT_SECONDS,
        )
        body = resp.json() if resp.content else {}
        if not body.get("ok"):
            logger.warning(
                "slack post failed: channel=%s agent=%s error=%s",
                channel, agent_id, body.get("error") or f"http_{resp.status_code}",
            )
            return False
        return True
    except Exception as e:
        logger.warning(
            "slack post errored: channel=%s agent=%s err=%s",
            channel, agent_id, e,
        )
        return False
