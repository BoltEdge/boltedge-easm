"""LRU caches for thread -> agent ownership + thread -> agent_thread id mapping."""
from __future__ import annotations

import pytest

from app.agents.slack.thread_owner import ThreadOwnerCache, DEFAULT_AGENT_ID
from app.agents.slack.thread_map import ThreadMapCache


def test_set_and_get_owner():
    cache = ThreadOwnerCache(max_entries=10)
    cache.set("1715890000.123", "engineer")
    assert cache.get("1715890000.123") == "engineer"


def test_missing_key_returns_default():
    cache = ThreadOwnerCache(max_entries=10)
    assert cache.get("missing-ts") == DEFAULT_AGENT_ID


def test_lru_eviction_at_cap():
    cache = ThreadOwnerCache(max_entries=2)
    cache.set("a", "engineer")
    cache.set("b", "qa")
    cache.set("c", "security-analyst")
    assert cache.get("a") == DEFAULT_AGENT_ID
    assert cache.get("b") == "qa"
    assert cache.get("c") == "security-analyst"


def test_get_updates_recency():
    cache = ThreadOwnerCache(max_entries=2)
    cache.set("a", "engineer")
    cache.set("b", "qa")
    cache.get("a")
    cache.set("c", "security-analyst")
    assert cache.get("a") == "engineer"
    assert cache.get("b") == DEFAULT_AGENT_ID
    assert cache.get("c") == "security-analyst"


def test_thread_map_basic():
    cache = ThreadMapCache(max_entries=10)
    assert cache.get("1715890000.123") is None
    cache.set("1715890000.123", 42)
    assert cache.get("1715890000.123") == 42


def test_thread_map_eviction():
    cache = ThreadMapCache(max_entries=2)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.set("c", 3)
    assert cache.get("a") is None
    assert cache.get("b") == 2
    assert cache.get("c") == 3
