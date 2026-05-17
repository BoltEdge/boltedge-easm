"""In-memory LRU mapping Slack thread_ts -> AgentThread.id."""
from __future__ import annotations

from collections import OrderedDict
from threading import Lock


class ThreadMapCache:
    """Process-local LRU: maps Slack thread_ts -> AgentThread.id.

    Miss returns None — caller starts a fresh AgentThread.
    """

    def __init__(self, max_entries: int = 512) -> None:
        self._data: OrderedDict[str, int] = OrderedDict()
        self._max = max_entries
        self._lock = Lock()

    def set(self, thread_ts: str, agent_thread_id: int) -> None:
        with self._lock:
            if thread_ts in self._data:
                self._data.move_to_end(thread_ts)
            self._data[thread_ts] = agent_thread_id
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def get(self, thread_ts: str) -> int | None:
        with self._lock:
            if thread_ts in self._data:
                self._data.move_to_end(thread_ts)
                return self._data[thread_ts]
            return None


map_cache = ThreadMapCache(max_entries=512)
