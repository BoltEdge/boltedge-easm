"""Publisher — formatting + channel selection for outbound posts."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest


BROADCAST = "C_BROADCAST"


@patch.dict("os.environ", {
    "SLACK_BROADCAST_CHANNEL_ID": BROADCAST,
    "SLACK_BOT_TOKEN_AGENTS": "xoxb-test",
})
@patch("app.agents.slack.publisher.post_as_agent")
def test_broadcast_brief_posts_to_broadcast(mock_post):
    from app.agents.slack.publisher import broadcast_brief
    mock_post.return_value = True
    broadcast_brief(agent_id="founder-ops",
                    subject="Weekly summary — week of 2026-05-12",
                    body="Three asks landed, two findings flagged.")
    assert mock_post.called
    kwargs = mock_post.call_args.kwargs
    assert kwargs["channel"] == BROADCAST
    assert kwargs["agent_id"] == "founder-ops"
    assert "Weekly summary" in kwargs["text"]
    assert "Three asks" in kwargs["text"]


@patch.dict("os.environ", {
    "SLACK_BROADCAST_CHANNEL_ID": BROADCAST,
    "SLACK_BOT_TOKEN_AGENTS": "xoxb-test",
})
@patch("app.agents.slack.publisher.post_as_agent")
def test_broadcast_approval_pending_includes_link(mock_post):
    from app.agents.slack.publisher import broadcast_approval_pending
    mock_post.return_value = True
    action = MagicMock()
    action.id = 42
    action.agent_id = "engineer"
    action.action_type = "code-pr"
    action.target = "feat/fix-foo"
    broadcast_approval_pending(action)
    text = mock_post.call_args.kwargs["text"]
    assert "approvals/42" in text
    assert mock_post.call_args.kwargs["agent_id"] == "engineer"
    assert mock_post.call_args.kwargs["channel"] == BROADCAST


@patch.dict("os.environ", {
    "SLACK_BROADCAST_CHANNEL_ID": BROADCAST,
    "SLACK_BOT_TOKEN_AGENTS": "xoxb-test",
})
@patch("app.agents.slack.publisher.post_as_agent")
def test_broadcast_run_completed_includes_cost(mock_post):
    from app.agents.slack.publisher import broadcast_run_completed
    mock_post.return_value = True
    run = MagicMock()
    run.id = 7
    run.agent_id = "engineer"
    run.cost_usd = 0.04
    run.status = "completed"
    broadcast_run_completed(run)
    text = mock_post.call_args.kwargs["text"]
    assert "0.04" in text


@patch.dict("os.environ", {
    "SLACK_BROADCAST_CHANNEL_ID": BROADCAST,
    "SLACK_BOT_TOKEN_AGENTS": "xoxb-test",
})
@patch("app.agents.slack.publisher.post_as_agent")
def test_broadcast_run_completed_skips_failed_run(mock_post):
    from app.agents.slack.publisher import broadcast_run_completed
    mock_post.return_value = True
    run = MagicMock()
    run.id = 8
    run.agent_id = "engineer"
    run.cost_usd = 0.01
    run.status = "errored"
    broadcast_run_completed(run)
    assert not mock_post.called


@patch("app.agents.slack.publisher.post_as_agent")
def test_publisher_noop_when_broadcast_channel_unset(mock_post, monkeypatch):
    from app.agents.slack.publisher import broadcast_brief
    monkeypatch.delenv("SLACK_BROADCAST_CHANNEL_ID", raising=False)
    broadcast_brief(agent_id="founder-ops", subject="x", body="y")
    assert not mock_post.called


@patch.dict("os.environ", {
    "SLACK_BROADCAST_CHANNEL_ID": BROADCAST,
    "SLACK_BOT_TOKEN_AGENTS": "xoxb-test",
})
@patch("app.agents.slack.publisher.post_as_agent")
def test_long_brief_chunks(mock_post):
    from app.agents.slack.publisher import broadcast_brief
    mock_post.return_value = True
    body = ("x" * 100 + "\n") * 50  # ~5100 chars, exceeds 3000 cap
    broadcast_brief(agent_id="founder-ops", subject="big", body=body)
    assert mock_post.call_count >= 2
