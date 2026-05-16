"""Persona-prefix routing: '@nano rob, hi' -> ('engineer', 'hi')."""
from __future__ import annotations

import pytest

from app.agents.slack.router import parse_message, DEFAULT_AGENT_ID


BOT_USER_ID = "U_NANO"


def test_parses_persona_prefix_rob():
    text = "<@U_NANO> rob, can you look at this?"
    agent, cleaned = parse_message(text, bot_user_id=BOT_USER_ID)
    assert agent == "engineer"
    assert cleaned == "can you look at this?"


def test_parses_persona_prefix_sam():
    text = "<@U_NANO> sam, what's new?"
    agent, cleaned = parse_message(text, bot_user_id=BOT_USER_ID)
    assert agent == "founder-ops"
    assert cleaned == "what's new?"


def test_parses_all_six_personas():
    cases = [
        ("sam", "founder-ops"),
        ("rob", "engineer"),
        ("aisha", "qa"),
        ("maya", "security-analyst"),
        ("ava", "strategy"),
        ("john", "voice"),
    ]
    for persona, expected_id in cases:
        text = f"<@U_NANO> {persona}, hi"
        agent, _ = parse_message(text, bot_user_id=BOT_USER_ID)
        assert agent == expected_id, f"{persona} -> {agent} (wanted {expected_id})"


def test_case_insensitive():
    text = "<@U_NANO> ROB, hi"
    agent, cleaned = parse_message(text, bot_user_id=BOT_USER_ID)
    assert agent == "engineer"
    assert cleaned == "hi"


def test_no_prefix_falls_back_to_default():
    text = "<@U_NANO> hi what's up"
    agent, cleaned = parse_message(text, bot_user_id=BOT_USER_ID)
    assert agent == DEFAULT_AGENT_ID
    assert cleaned == "hi what's up"


def test_strips_bot_mention_when_no_prefix():
    text = "<@U_NANO>   hello"
    agent, cleaned = parse_message(text, bot_user_id=BOT_USER_ID)
    assert agent == DEFAULT_AGENT_ID
    assert cleaned == "hello"


def test_no_mention_returns_default_agent():
    text = "hi"
    agent, cleaned = parse_message(text, bot_user_id=BOT_USER_ID)
    assert agent == DEFAULT_AGENT_ID
    assert cleaned == "hi"


def test_prefix_without_comma_still_works():
    text = "<@U_NANO> rob can you check this"
    agent, cleaned = parse_message(text, bot_user_id=BOT_USER_ID)
    assert agent == "engineer"
    assert cleaned == "can you check this"


def test_unknown_persona_falls_back_to_default():
    text = "<@U_NANO> bob, hi"
    agent, cleaned = parse_message(text, bot_user_id=BOT_USER_ID)
    assert agent == DEFAULT_AGENT_ID
    assert cleaned == "bob, hi"
