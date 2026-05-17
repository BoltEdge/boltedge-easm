"""POST /api/integrations/slack/events — verify, ack-fast, enqueue.

Uses a minimal Flask app with ONLY the slack blueprint registered, so
the test doesn't need to boot the full app + DB. (The real app factory
is exercised via Task 8.)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from unittest.mock import patch

import pytest
from flask import Flask

from app.agents.slack.events import bp as slack_bp


SECRET = "test-signing-secret"
BOT_USER_ID = "U_NANO"
FOUNDER_USER = "U_FOUNDER"
CHAT_CHANNEL = "C_CHAT"


@pytest.fixture()
def app():
    flask_app = Flask(__name__)
    flask_app.config["TESTING"] = True
    flask_app.register_blueprint(slack_bp)
    yield flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def _slack_env(monkeypatch):
    monkeypatch.setenv("SLACK_SIGNING_SECRET_AGENTS", SECRET)
    monkeypatch.setenv("SLACK_BOT_USER_ID_AGENTS", BOT_USER_ID)
    monkeypatch.setenv("FOUNDER_SLACK_USER_ID", FOUNDER_USER)
    monkeypatch.setenv("SLACK_CHAT_CHANNEL_ID", CHAT_CHANNEL)


@pytest.fixture(autouse=True)
def _reset_dedupe_cache():
    """Each test starts with an empty event-id seen-set."""
    from app.agents.slack import events as ev
    ev._event_seen.clear()
    yield


def _sign_request(client, body: dict, secret=SECRET):
    raw = json.dumps(body).encode()
    ts = str(int(time.time()))
    base = f"v0:{ts}:".encode() + raw
    sig = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return client.post(
        "/api/integrations/slack/events",
        data=raw,
        content_type="application/json",
        headers={"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts},
    )


def test_url_verification_challenge(client):
    body = {"type": "url_verification", "challenge": "abc123"}
    resp = _sign_request(client, body)
    assert resp.status_code == 200
    assert resp.get_json()["challenge"] == "abc123"


def test_bad_signature_returns_403(client):
    body = {"type": "event_callback"}
    raw = json.dumps(body).encode()
    resp = client.post(
        "/api/integrations/slack/events",
        data=raw,
        content_type="application/json",
        headers={"X-Slack-Signature": "v0=bogus",
                 "X-Slack-Request-Timestamp": str(int(time.time()))},
    )
    assert resp.status_code == 403


def test_wrong_user_returns_200_silent(client):
    body = {
        "type": "event_callback",
        "event_id": "Ev_silent_user",
        "event": {"type": "app_mention", "user": "U_STRANGER",
                  "channel": CHAT_CHANNEL, "text": f"<@{BOT_USER_ID}> rob, hi",
                  "ts": "1715890000.001"},
    }
    with patch("app.agents.slack.events._run_async") as mock_run:
        resp = _sign_request(client, body)
    assert resp.status_code == 200
    assert not mock_run.called


def test_wrong_channel_returns_200_silent(client):
    body = {
        "type": "event_callback",
        "event_id": "Ev_silent_chan",
        "event": {"type": "app_mention", "user": FOUNDER_USER,
                  "channel": "C_OTHER", "text": f"<@{BOT_USER_ID}> rob, hi",
                  "ts": "1715890000.002"},
    }
    with patch("app.agents.slack.events._run_async") as mock_run:
        resp = _sign_request(client, body)
    assert resp.status_code == 200
    assert not mock_run.called


def test_valid_app_mention_enqueues_and_acks(client):
    body = {
        "type": "event_callback",
        "event_id": "Ev_valid",
        "event": {"type": "app_mention", "user": FOUNDER_USER,
                  "channel": CHAT_CHANNEL, "text": f"<@{BOT_USER_ID}> rob, hi",
                  "ts": "1715890000.100"},
    }
    with patch("app.agents.slack.events._run_async") as mock_run:
        resp = _sign_request(client, body)
    assert resp.status_code == 200
    assert mock_run.called
    args = mock_run.call_args.args
    assert args[0] == "engineer"
    assert args[1] == "hi"
    assert args[2] == CHAT_CHANNEL


def test_duplicate_event_id_skipped(client):
    body = {
        "type": "event_callback",
        "event_id": "Ev_dup",
        "event": {"type": "app_mention", "user": FOUNDER_USER,
                  "channel": CHAT_CHANNEL, "text": f"<@{BOT_USER_ID}> rob, hi",
                  "ts": "1715890000.200"},
    }
    with patch("app.agents.slack.events._run_async") as mock_run:
        r1 = _sign_request(client, body)
        r2 = _sign_request(client, body)
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert mock_run.call_count == 1


def test_thread_reply_uses_thread_owner_lookup(client):
    """A message in an existing thread (no @mention) uses thread_owner."""
    from app.agents.slack.thread_owner import owner_cache
    owner_cache.set("1715890000.300", "security-analyst")
    body = {
        "type": "event_callback",
        "event_id": "Ev_thread",
        "event": {"type": "message", "user": FOUNDER_USER,
                  "channel": CHAT_CHANNEL, "text": "follow-up question",
                  "ts": "1715890000.301", "thread_ts": "1715890000.300"},
    }
    with patch("app.agents.slack.events._run_async") as mock_run:
        resp = _sign_request(client, body)
    assert resp.status_code == 200
    assert mock_run.called
    args = mock_run.call_args.args
    assert args[0] == "security-analyst"
    assert args[1] == "follow-up question"


def test_bot_self_message_ignored(client):
    """Bot's own posts arrive as message events too — must not loop."""
    body = {
        "type": "event_callback",
        "event_id": "Ev_botself",
        "event": {"type": "message", "user": FOUNDER_USER,
                  "channel": CHAT_CHANNEL, "text": "hi",
                  "ts": "1715890000.400",
                  "bot_id": "B_NANO"},
    }
    with patch("app.agents.slack.events._run_async") as mock_run:
        resp = _sign_request(client, body)
    assert resp.status_code == 200
    assert not mock_run.called
