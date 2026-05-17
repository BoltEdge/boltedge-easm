"""Slack Events API endpoint.

POST /api/integrations/slack/events

1. Verify HMAC-SHA256 signature (5-min replay window).
2. Handle url_verification challenge.
3. Dedupe by event_id (in-process LRU).
4. Founder + channel allowlist (silent 200 on mismatch).
5. Skip the bot's own messages (no infinite loop).
6. Enqueue the run in a daemon thread.
7. Ack 200 within ~50ms.
"""
from __future__ import annotations

import logging
import os
import threading
from collections import OrderedDict
from threading import Lock

from flask import Blueprint, current_app, jsonify, request

from .client import post_as_agent
from .publisher import broadcast_run_completed
from .router import parse_message
from .signing import verify_signature
from .thread_map import map_cache
from .thread_owner import owner_cache


logger = logging.getLogger("agents.slack.events")

bp = Blueprint("agents_slack", __name__, url_prefix="/api/integrations/slack")


_event_seen: OrderedDict[str, bool] = OrderedDict()
_event_seen_lock = Lock()
_EVENT_SEEN_MAX = 1000


def _seen(event_id: str) -> bool:
    """Return True iff this event_id has already been processed."""
    if not event_id:
        return False
    with _event_seen_lock:
        if event_id in _event_seen:
            return True
        _event_seen[event_id] = True
        while len(_event_seen) > _EVENT_SEEN_MAX:
            _event_seen.popitem(last=False)
    return False


@bp.route("/events", methods=["POST"])
def slack_events():
    raw = request.get_data()

    if not verify_signature(dict(request.headers), raw):
        return ("forbidden", 403)

    body = request.get_json(silent=True) or {}

    if body.get("type") == "url_verification":
        return jsonify({"challenge": body.get("challenge", "")})

    if body.get("type") != "event_callback":
        return ("", 200)

    event_id = body.get("event_id", "")
    if _seen(event_id):
        return ("", 200)

    event = body.get("event") or {}
    event_type = event.get("type")
    user = event.get("user")
    channel = event.get("channel")
    text = event.get("text") or ""
    ts = event.get("ts")
    thread_ts = event.get("thread_ts")
    bot_id = event.get("bot_id")

    founder = os.environ.get("FOUNDER_SLACK_USER_ID", "")
    chat_channel = os.environ.get("SLACK_CHAT_CHANNEL_ID", "")
    if not founder or not chat_channel:
        return ("", 200)
    if user != founder:
        return ("", 200)
    if channel != chat_channel:
        return ("", 200)
    if bot_id:
        return ("", 200)
    if event_type not in ("app_mention", "message"):
        return ("", 200)

    bot_user_id = os.environ.get("SLACK_BOT_USER_ID_AGENTS", "")
    agent_id, cleaned = parse_message(text, bot_user_id=bot_user_id)

    is_explicit_address = (
        bool(bot_user_id)
        and (text or "").strip().startswith(f"<@{bot_user_id}>")
    )

    if thread_ts and not is_explicit_address:
        agent_id = owner_cache.get(thread_ts)

    if not thread_ts:
        owner_cache.set(ts, agent_id)

    if thread_ts and is_explicit_address:
        owner = owner_cache.get(thread_ts)
        if owner == "founder-ops":
            re_routed, cleaned = parse_message(text, bot_user_id=bot_user_id)
            agent_id = re_routed

    convo_ts = thread_ts or ts

    _run_async(agent_id, cleaned, channel, convo_ts)
    return ("", 200)


def _run_async(agent_id: str, prompt: str, channel: str, convo_ts: str) -> None:
    """Spawn the agent run in a daemon thread so we ack Slack within 3s."""
    flask_app = current_app._get_current_object()

    def _worker():
        with flask_app.app_context():
            try:
                _do_run(agent_id, prompt, channel, convo_ts)
            except Exception as e:
                logger.exception("slack run failed: agent=%s err=%s", agent_id, e)
                post_as_agent(
                    channel=channel,
                    agent_id=agent_id,
                    text=":warning: Hit a problem mid-run. Check /admin/agents for details.",
                    thread_ts=convo_ts,
                )

    threading.Thread(target=_worker, daemon=True).start()


def _do_run(agent_id: str, prompt: str, channel: str, convo_ts: str) -> None:
    """Inside-thread: optional ack, run agent, post reply, broadcast completion."""
    from app.agents.profile_loader import load_profile_by_name
    from app.agents.runtime import run_agent
    from app.extensions import db

    profile = load_profile_by_name(agent_id)

    if profile.slack_send_ack:
        post_as_agent(channel=channel, agent_id=agent_id,
                      text="_On it._", thread_ts=convo_ts)

    thread_id = map_cache.get(convo_ts)
    result = run_agent(
        agent_name=agent_id,
        user_prompt=prompt,
        skill=None,
        memory_tags=[],
        thread_id=thread_id,
    )
    db.session.commit()

    if thread_id is None and result.thread is not None:
        map_cache.set(convo_ts, result.thread.id)

    reply = (result.text or "").strip() or "_(no reply)_"
    post_as_agent(channel=channel, agent_id=agent_id, text=reply, thread_ts=convo_ts)
    broadcast_run_completed(result.run)
