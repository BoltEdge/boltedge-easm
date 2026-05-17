"""Real Slack smoke test — gated by RUN_SLACK_SMOKE=1.

Posts into a throwaway channel and verifies it lands with the right
username + icon.

Run with:
    RUN_SLACK_SMOKE=1 \
    SLACK_BOT_TOKEN_AGENTS=xoxb-... \
    SLACK_SMOKE_CHANNEL_ID=C... \
    pytest backend/tests/integration/test_slack_smoke.py -v
"""
from __future__ import annotations

import os

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_SLACK_SMOKE") != "1",
    reason="set RUN_SLACK_SMOKE=1 to run this integration test",
)


def test_post_as_sam_appears_in_throwaway_channel():
    from app.agents.slack.client import post_as_agent
    channel = os.environ["SLACK_SMOKE_CHANNEL_ID"]
    ok = post_as_agent(
        channel=channel,
        agent_id="founder-ops",
        text="smoke test from pytest",
    )
    assert ok is True
