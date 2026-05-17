"""Slack Web API client — posts as per-agent persona.

These tests are pure-unit: no DB, no Flask app. The client only reads
os.environ + agent profiles, then calls requests.post.
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest


def _ok_response(ok=True, body=None):
    resp = MagicMock()
    resp.status_code = 200
    resp.content = b"{}"
    resp.json.return_value = body if body is not None else {"ok": ok}
    return resp


@patch.dict("os.environ", {"SLACK_BOT_TOKEN_AGENTS": "xoxb-test"})
@patch("app.agents.slack.client.requests.post")
def test_post_includes_persona_username_and_icon(mock_post):
    from app.agents.slack.client import post_as_agent
    mock_post.return_value = _ok_response()
    post_as_agent(channel="C123", agent_id="engineer", text="hi")
    args, kwargs = mock_post.call_args
    assert args[0] == "https://slack.com/api/chat.postMessage"
    payload = kwargs["json"]
    assert payload["channel"] == "C123"
    assert payload["text"] == "hi"
    assert payload["username"] == "Rob"
    assert payload["icon_url"] == "https://nanoeasm.com/agents/rob.png"


@patch.dict("os.environ", {"SLACK_BOT_TOKEN_AGENTS": "xoxb-test"})
@patch("app.agents.slack.client.requests.post")
def test_post_threads_when_thread_ts_given(mock_post):
    from app.agents.slack.client import post_as_agent
    mock_post.return_value = _ok_response()
    post_as_agent(channel="C123", agent_id="engineer",
                  text="hi", thread_ts="1715890000.123")
    payload = mock_post.call_args.kwargs["json"]
    assert payload["thread_ts"] == "1715890000.123"


@patch.dict("os.environ", {"SLACK_BOT_TOKEN_AGENTS": "xoxb-test"})
@patch("app.agents.slack.client.requests.post")
def test_post_logs_and_returns_false_on_slack_error(mock_post, caplog):
    from app.agents.slack.client import post_as_agent
    mock_post.return_value = _ok_response(body={"ok": False, "error": "channel_not_found"})
    result = post_as_agent(channel="Cbad", agent_id="engineer", text="hi")
    assert result is False
    assert "channel_not_found" in caplog.text


@patch.dict("os.environ", {"SLACK_BOT_TOKEN_AGENTS": "xoxb-test"})
@patch("app.agents.slack.client.requests.post", side_effect=ConnectionError("boom"))
def test_post_swallows_network_error(mock_post, caplog):
    from app.agents.slack.client import post_as_agent
    result = post_as_agent(channel="C123", agent_id="engineer", text="hi")
    assert result is False
    assert "boom" in caplog.text


def test_post_noop_when_token_missing(monkeypatch):
    from app.agents.slack.client import post_as_agent
    monkeypatch.delenv("SLACK_BOT_TOKEN_AGENTS", raising=False)
    result = post_as_agent(channel="C123", agent_id="engineer", text="hi")
    assert result is False
