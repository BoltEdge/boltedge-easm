"""In-memory LRU mapping Slack thread_ts -> agent_id."""
from __future__ import annotations

from collections import OrderedDict
from threading import Lock


DEFAULT_AGENT_ID = "founder-ops"


class ThreadOwnerCache:
    """Process-local LRU: which agent owns a Slack thread.

    Process restart resets the cache; misses fall back to DEFAULT_AGENT_ID.
    """

    def __init__(self, max_entries: int = 512) -> None:
        self._data: OrderedDict[str, str] = OrderedDict()
        self._max = max_entries
        self._lock = Lock()

    def set(self, thread_ts: str, agent_id: str) -> None:
        with self._lock:
            if thread_ts in self._data:
                self._data.move_to_end(thread_ts)
            self._data[thread_ts] = agent_id
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def get(self, thread_ts: str) -> str:
        with self._lock:
            if thread_ts in self._data:
                self._data.move_to_end(thread_ts)
                return self._data[thread_ts]
            return DEFAULT_AGENT_ID


owner_cache = ThreadOwnerCache(max_entries=512)
