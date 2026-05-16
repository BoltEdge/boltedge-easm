# Agent Platform — Slack Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring the internal agent platform onto Slack. One bot posting as 6 personas in two channels (`#nano-broadcast` + `#nano-chat`), founder-only, persona-prefix addressing, link-only approvals.

**Architecture:** New `backend/app/agents/slack/` module. Inbound via Slack Events API → ack-fast + background-thread run. Outbound via Slack Web API with `chat:write.customize` (per-persona username + icon). Reuses existing `runtime.run_agent()` and `AgentThread`. Hooks into approvals + run-completion + 3 brief skills via small additive edits.

**Tech Stack:** Flask (existing), `requests` library (already a dep — matches existing Slack-webhook usage in `app/integrations/routes.py`), Slack Events API + Web API, HMAC-SHA256 signing.

**Spec reference:** `docs/superpowers/specs/2026-05-16-agent-slack-integration-design.md`

---

## File Plan

**New (Slack module):**
- `backend/app/agents/slack/__init__.py` — Blueprint export.
- `backend/app/agents/slack/signing.py` — `verify_signature(headers, raw_body)`.
- `backend/app/agents/slack/router.py` — `parse_message(text) -> (agent_id, cleaned_text)`.
- `backend/app/agents/slack/thread_owner.py` — LRU `{slack_ts: agent_id}`.
- `backend/app/agents/slack/thread_map.py` — LRU `{slack_ts: agent_thread_id}` for continuations.
- `backend/app/agents/slack/client.py` — `post_as_agent(channel, agent_id, text, thread_ts=None)`.
- `backend/app/agents/slack/publisher.py` — `broadcast_brief()`, `broadcast_approval_pending()`, `broadcast_run_completed()`.
- `backend/app/agents/slack/events.py` — Flask route `/api/integrations/slack/events`.

**New (avatars — committed binary placeholders, founder swaps real PNGs later):**
- `frontend/public/agents/sam.png`
- `frontend/public/agents/rob.png`
- `frontend/public/agents/aisha.png`
- `frontend/public/agents/maya.png`
- `frontend/public/agents/ava.png`
- `frontend/public/agents/john.png`

**New (tests):**
- `backend/tests/test_agents_slack_signing.py`
- `backend/tests/test_agents_slack_router.py`
- `backend/tests/test_agents_slack_thread_owner.py`
- `backend/tests/test_agents_slack_client.py`
- `backend/tests/test_agents_slack_publisher.py`
- `backend/tests/test_agents_slack_events.py`
- `backend/tests/integration/test_slack_smoke.py` (gated, optional)

**Modified:**
- `backend/app/__init__.py` — register `slack_bp`.
- `backend/app/agents/profiles/founder-ops/agent.md` — add `slack_display_name`, `slack_icon_url`, `slack_send_ack` frontmatter.
- `backend/app/agents/profiles/engineer/agent.md` — same.
- `backend/app/agents/profiles/qa/agent.md` — same.
- `backend/app/agents/profiles/security-analyst/agent.md` — same.
- `backend/app/agents/profiles/strategy/agent.md` — same.
- `backend/app/agents/profiles/voice/agent.md` — same.
- `backend/app/agents/profile_loader.py` — surface the new fields on the loaded profile object.
- `backend/app/agents/approvals.py` — fire `broadcast_approval_pending` after `propose_action`.
- `backend/app/agents/routes.py` — fire `broadcast_run_completed` after manual `trigger_run`.
- `backend/app/agents/skills/weekly_summary.py` — fire `broadcast_brief` after email send.
- `backend/app/agents/skills/competitor_pulse.py` — same.
- `backend/app/agents/skills/weekly_finding_brief.py` — same.

**Notes on key pragmatic decisions baked into this plan:**

1. **AgentThread is reused.** The spec said "Slack lives on Slack" meaning *we don't build new Slack-specific storage*. The runtime requires an `AgentThread` row, so Slack-initiated convos still create one — they just aren't surfaced in any new UI. Existing dashboard lists them like any other thread. No DB migration needed.
2. **No new column on AgentThread.** No `source` marker. Keeps the migration surface zero.
3. **`requests` library not `slack_sdk`.** Matches the existing pattern in `app/integrations/routes.py` (`_send_slack`). Avoids a new dependency.
4. **Daemon background threads.** Matches the existing audit-webhook forwarder pattern.

---

## Task 0: Slack workspace setup (manual, founder)

Not Claude Code's job — the founder does this once before Task 8 deploy. Documented here so the plan is reproducible.

- [ ] **Step 1: Create the Slack app**

In Slack admin → "Create New App" → "From scratch". Name: `Nano Agents`. Workspace: founder's workspace.

- [ ] **Step 2: Add scopes**

App settings → "OAuth & Permissions" → "Bot Token Scopes", add:
- `chat:write`
- `chat:write.customize`
- `app_mentions:read`
- `channels:history`
- `channels:read`
- `links:read`

- [ ] **Step 3: Install to workspace + grab token**

"Install to Workspace". Copy the `xoxb-...` Bot User OAuth Token.

- [ ] **Step 4: Grab signing secret**

App settings → "Basic Information" → "Signing Secret". Copy.

- [ ] **Step 5: Create the two private channels**

In Slack: create `#nano-broadcast` (private) and `#nano-chat` (private). Invite `@nano` to both. Copy each channel ID (right-click channel → "Copy link"; ID is the last path segment).

- [ ] **Step 6: Grab founder Slack user ID**

In Slack: click your own avatar → "Profile" → "More" → "Copy member ID". Starts with `U`.

- [ ] **Step 7: Park values in a scratch file (do not commit)**

Keep these for Task 8 env setup:
```
SLACK_BOT_TOKEN_AGENTS=xoxb-...
SLACK_SIGNING_SECRET_AGENTS=...
SLACK_BROADCAST_CHANNEL_ID=C...
SLACK_CHAT_CHANNEL_ID=C...
FOUNDER_SLACK_USER_ID=U...
```

(Event Subscription URL is configured in Task 14 after deploy — needs a reachable `/api/integrations/slack/events` endpoint to verify.)

---

## Task 1: Signature verification

**Files:**
- Create: `backend/app/agents/slack/__init__.py`
- Create: `backend/app/agents/slack/signing.py`
- Create: `backend/tests/test_agents_slack_signing.py`

- [ ] **Step 1: Create empty `__init__.py`**

```bash
mkdir -p backend/app/agents/slack
```

Create `backend/app/agents/slack/__init__.py` with one line:

```python
"""Slack integration for the internal agent platform."""
```

- [ ] **Step 2: Write the failing test**

Create `backend/tests/test_agents_slack_signing.py`:

```python
"""Slack signature verification — HMAC-SHA256, 5-min replay window."""
from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from app.agents.slack.signing import verify_signature


SECRET = "test-signing-secret"


def _sign(body: bytes, timestamp: str, secret: str = SECRET) -> str:
    base = f"v0:{timestamp}:".encode() + body
    mac = hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return f"v0={mac}"


def test_valid_signature_passes():
    body = b'{"type":"event_callback"}'
    ts = str(int(time.time()))
    sig = _sign(body, ts)
    headers = {"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts}
    assert verify_signature(headers, body, secret=SECRET) is True


def test_tampered_body_fails():
    body = b'{"type":"event_callback"}'
    ts = str(int(time.time()))
    sig = _sign(body, ts)
    headers = {"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts}
    assert verify_signature(headers, b'{"tampered":true}', secret=SECRET) is False


def test_old_timestamp_fails():
    body = b'{"type":"event_callback"}'
    ts = str(int(time.time()) - 600)  # 10 minutes ago
    sig = _sign(body, ts)
    headers = {"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts}
    assert verify_signature(headers, body, secret=SECRET) is False


def test_future_timestamp_fails():
    body = b'{"type":"event_callback"}'
    ts = str(int(time.time()) + 600)  # 10 minutes in the future
    sig = _sign(body, ts)
    headers = {"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts}
    assert verify_signature(headers, body, secret=SECRET) is False


def test_missing_signature_header_fails():
    body = b'{"type":"event_callback"}'
    ts = str(int(time.time()))
    headers = {"X-Slack-Request-Timestamp": ts}
    assert verify_signature(headers, body, secret=SECRET) is False


def test_missing_timestamp_header_fails():
    body = b'{"type":"event_callback"}'
    ts = str(int(time.time()))
    headers = {"X-Slack-Signature": _sign(body, ts)}
    assert verify_signature(headers, body, secret=SECRET) is False


def test_empty_secret_fails():
    body = b'{"type":"event_callback"}'
    ts = str(int(time.time()))
    headers = {"X-Slack-Signature": _sign(body, ts), "X-Slack-Request-Timestamp": ts}
    assert verify_signature(headers, body, secret="") is False
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd backend
pytest tests/test_agents_slack_signing.py -v
```

Expected: ImportError / ModuleNotFoundError on `app.agents.slack.signing`.

- [ ] **Step 4: Implement signing.py**

Create `backend/app/agents/slack/signing.py`:

```python
"""Slack signing-secret verification (HMAC-SHA256, 5-min replay window)."""
from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Mapping


REPLAY_WINDOW_SECONDS = 300  # 5 minutes per Slack docs


def verify_signature(
    headers: Mapping[str, str],
    raw_body: bytes,
    secret: str | None = None,
) -> bool:
    """Return True iff the request bears a valid Slack signature.

    Always returns False when secret is empty/None (no secret means no trust).
    """
    if secret is None:
        secret = os.environ.get("SLACK_SIGNING_SECRET_AGENTS", "")
    if not secret:
        return False

    sig_header = headers.get("X-Slack-Signature")
    ts_header = headers.get("X-Slack-Request-Timestamp")
    if not sig_header or not ts_header:
        return False

    try:
        ts = int(ts_header)
    except ValueError:
        return False

    now = int(time.time())
    if abs(now - ts) > REPLAY_WINDOW_SECONDS:
        return False

    base = f"v0:{ts}:".encode() + raw_body
    expected = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_header)
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd backend
pytest tests/test_agents_slack_signing.py -v
```

Expected: 7 passed.

- [ ] **Step 6: Commit**

```bash
git add backend/app/agents/slack/__init__.py \
        backend/app/agents/slack/signing.py \
        backend/tests/test_agents_slack_signing.py
git commit -m "feat(agents/slack): signing-secret verification"
```

---

## Task 2: Persona-prefix router

**Files:**
- Create: `backend/app/agents/slack/router.py`
- Create: `backend/tests/test_agents_slack_router.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_slack_router.py`:

```python
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
    assert agent == DEFAULT_AGENT_ID  # founder-ops (Sam)
    assert cleaned == "hi what's up"


def test_strips_bot_mention_when_no_prefix():
    text = "<@U_NANO>   hello"
    agent, cleaned = parse_message(text, bot_user_id=BOT_USER_ID)
    assert agent == DEFAULT_AGENT_ID
    assert cleaned == "hello"


def test_no_mention_returns_default_agent():
    # Inbound message in a thread (no @-mention) — caller handles thread-owner
    # lookup; router still returns SOMETHING sensible.
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
    assert cleaned == "bob, hi"  # the unknown word is preserved
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd backend
pytest tests/test_agents_slack_router.py -v
```

Expected: ImportError on `app.agents.slack.router`.

- [ ] **Step 3: Implement router.py**

Create `backend/app/agents/slack/router.py`:

```python
"""Persona-prefix message routing.

Maps Slack message text to one of the six agent IDs:
    sam   -> founder-ops      (also the default fallback)
    rob   -> engineer
    aisha -> qa
    maya  -> security-analyst
    ava   -> strategy
    john  -> voice
"""
from __future__ import annotations

import re


PERSONA_TO_AGENT: dict[str, str] = {
    "sam": "founder-ops",
    "rob": "engineer",
    "aisha": "qa",
    "maya": "security-analyst",
    "ava": "strategy",
    "john": "voice",
}

DEFAULT_AGENT_ID = "founder-ops"


def parse_message(text: str, bot_user_id: str | None = None) -> tuple[str, str]:
    """Strip bot mention + persona prefix, return (agent_id, cleaned_text).

    Examples
    --------
    >>> parse_message("<@U_NANO> rob, look at this", bot_user_id="U_NANO")
    ('engineer', 'look at this')

    >>> parse_message("<@U_NANO> hi", bot_user_id="U_NANO")
    ('founder-ops', 'hi')
    """
    cleaned = text or ""

    if bot_user_id:
        # Strip "<@BOT_ID>" (and any surrounding whitespace) from anywhere
        cleaned = re.sub(rf"<@{re.escape(bot_user_id)}>\s*", "", cleaned).strip()
    else:
        cleaned = cleaned.strip()

    # Look for "persona," or "persona " as the first token.
    m = re.match(r"^([A-Za-z]+)[,\s]+(.*)$", cleaned, flags=re.DOTALL)
    if m:
        candidate = m.group(1).lower()
        if candidate in PERSONA_TO_AGENT:
            return PERSONA_TO_AGENT[candidate], m.group(2).strip()

    return DEFAULT_AGENT_ID, cleaned
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd backend
pytest tests/test_agents_slack_router.py -v
```

Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agents/slack/router.py \
        backend/tests/test_agents_slack_router.py
git commit -m "feat(agents/slack): persona-prefix message router"
```

---

## Task 3: Thread-owner LRU + thread-map LRU

Two small in-memory caches:
- `thread_owner` maps `slack_thread_ts → agent_id` (so mid-thread replies route to the right agent)
- `thread_map` maps `slack_thread_ts → agent_thread.id` (so runtime continuations reuse the same AgentThread)

Single file — two simple LRU-bounded dicts.

**Files:**
- Create: `backend/app/agents/slack/thread_owner.py`
- Create: `backend/app/agents/slack/thread_map.py`
- Create: `backend/tests/test_agents_slack_thread_owner.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_slack_thread_owner.py`:

```python
"""LRU caches for thread → agent ownership + thread → agent_thread id mapping."""
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
    assert cache.get("a") == DEFAULT_AGENT_ID   # evicted
    assert cache.get("b") == "qa"
    assert cache.get("c") == "security-analyst"


def test_get_updates_recency():
    cache = ThreadOwnerCache(max_entries=2)
    cache.set("a", "engineer")
    cache.set("b", "qa")
    cache.get("a")  # bumps "a" to most-recent
    cache.set("c", "security-analyst")
    assert cache.get("a") == "engineer"          # NOT evicted
    assert cache.get("b") == DEFAULT_AGENT_ID    # evicted
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd backend
pytest tests/test_agents_slack_thread_owner.py -v
```

Expected: ImportError on the two modules.

- [ ] **Step 3: Implement thread_owner.py and thread_map.py**

Create `backend/app/agents/slack/thread_owner.py`:

```python
"""In-memory LRU mapping Slack thread_ts -> agent_id."""
from __future__ import annotations

from collections import OrderedDict
from threading import Lock


DEFAULT_AGENT_ID = "founder-ops"


class ThreadOwnerCache:
    """Process-local LRU: which agent owns a Slack thread.

    Process restart resets the cache; misses fall back to DEFAULT_AGENT_ID.
    That's an acceptable degradation — the alternative would be persisting
    every Slack thread to the DB, which the spec explicitly avoids.
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


# Module-level singleton — events.py imports this directly.
owner_cache = ThreadOwnerCache(max_entries=512)
```

Create `backend/app/agents/slack/thread_map.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd backend
pytest tests/test_agents_slack_thread_owner.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agents/slack/thread_owner.py \
        backend/app/agents/slack/thread_map.py \
        backend/tests/test_agents_slack_thread_owner.py
git commit -m "feat(agents/slack): thread-owner and thread-map LRU caches"
```

---

## Task 4: Profile config additions (slack_display_name, slack_icon_url, slack_send_ack)

Each agent profile's frontmatter gets three new fields. Profile loader surfaces them.

**Files:**
- Modify: `backend/app/agents/profiles/founder-ops/agent.md`
- Modify: `backend/app/agents/profiles/engineer/agent.md`
- Modify: `backend/app/agents/profiles/qa/agent.md`
- Modify: `backend/app/agents/profiles/security-analyst/agent.md`
- Modify: `backend/app/agents/profiles/strategy/agent.md`
- Modify: `backend/app/agents/profiles/voice/agent.md`
- Modify: `backend/app/agents/profile_loader.py`
- Modify or create: `backend/tests/test_agents_profile_loader.py` (add cases)

- [ ] **Step 1: Read current profile_loader.py**

```bash
sed -n '1,80p' backend/app/agents/profile_loader.py
```

Note the dataclass / dict shape that gets returned. The new fields go alongside `display_name`.

- [ ] **Step 2: Write failing test additions**

Open `backend/tests/test_agents_profile_loader.py` and add at the bottom (or create if missing):

```python
def test_profile_exposes_slack_fields():
    from app.agents.profile_loader import load_profile
    p = load_profile("founder-ops")
    assert p.slack_display_name == "Sam"
    assert p.slack_icon_url == "https://nanoeasm.com/agents/sam.png"
    assert p.slack_send_ack is True


def test_profile_slack_fields_default_when_missing(tmp_path, monkeypatch):
    """If a profile omits the Slack fields, the loader defaults sensibly."""
    from app.agents.profile_loader import load_profile
    p = load_profile("engineer")
    # All profiles in this repo set these in this plan; assert they exist + are strings
    assert isinstance(p.slack_display_name, str) and p.slack_display_name
    assert isinstance(p.slack_icon_url, str) and p.slack_icon_url
    assert isinstance(p.slack_send_ack, bool)
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cd backend
pytest tests/test_agents_profile_loader.py::test_profile_exposes_slack_fields -v
```

Expected: AttributeError on `slack_display_name` (or KeyError, depending on loader shape).

- [ ] **Step 4: Add frontmatter fields to all six profiles**

For each profile, edit the YAML frontmatter (the block between `---` markers at the top of `agent.md`). Add right after `display_name:` (or wherever you find the existing identity block).

`backend/app/agents/profiles/founder-ops/agent.md` — add:
```yaml
slack_display_name: Sam
slack_icon_url: https://nanoeasm.com/agents/sam.png
slack_send_ack: true
```

`backend/app/agents/profiles/engineer/agent.md` — add:
```yaml
slack_display_name: Rob
slack_icon_url: https://nanoeasm.com/agents/rob.png
slack_send_ack: true
```

`backend/app/agents/profiles/qa/agent.md` — add:
```yaml
slack_display_name: Aisha
slack_icon_url: https://nanoeasm.com/agents/aisha.png
slack_send_ack: true
```

`backend/app/agents/profiles/security-analyst/agent.md` — add:
```yaml
slack_display_name: Maya
slack_icon_url: https://nanoeasm.com/agents/maya.png
slack_send_ack: true
```

`backend/app/agents/profiles/strategy/agent.md` — add:
```yaml
slack_display_name: Ava
slack_icon_url: https://nanoeasm.com/agents/ava.png
slack_send_ack: true
```

`backend/app/agents/profiles/voice/agent.md` — add:
```yaml
slack_display_name: John
slack_icon_url: https://nanoeasm.com/agents/john.png
slack_send_ack: true
```

- [ ] **Step 5: Update profile_loader.py to surface the new fields**

Open `backend/app/agents/profile_loader.py` and locate the dataclass / NamedTuple / dict that represents a loaded profile. Add three new optional fields with sensible defaults:

```python
# Inside the Profile dataclass (or equivalent) — add alongside display_name:
slack_display_name: str = ""        # defaults to display_name if unset
slack_icon_url: str = ""             # may be empty — client will skip icon param
slack_send_ack: bool = True          # "On it." ack message before run
```

And in whatever parses the frontmatter (likely a `yaml.safe_load` of the front-matter block), add the read:

```python
slack_display_name = front.get("slack_display_name") or front.get("display_name") or name
slack_icon_url    = front.get("slack_icon_url", "")
slack_send_ack    = bool(front.get("slack_send_ack", True))
```

Pass these into the Profile constructor wherever it's built.

- [ ] **Step 6: Run profile_loader tests to verify they pass**

```bash
cd backend
pytest tests/test_agents_profile_loader.py -v
```

Expected: all green (existing tests + new ones).

- [ ] **Step 7: Commit**

```bash
git add backend/app/agents/profiles/ \
        backend/app/agents/profile_loader.py \
        backend/tests/test_agents_profile_loader.py
git commit -m "feat(agents): slack_display_name/icon/ack fields on agent profiles"
```

---

## Task 5: Slack Web API client

Wraps `chat.postMessage` with `chat:write.customize` (per-persona username + icon). Mocked in unit tests; smoke-tested for real later.

**Files:**
- Create: `backend/app/agents/slack/client.py`
- Create: `backend/tests/test_agents_slack_client.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_slack_client.py`:

```python
"""Slack Web API client — posts as per-agent persona."""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from app.agents.slack.client import post_as_agent, SlackPostError


def _ok_response(ok=True, body=None):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = body or {"ok": ok}
    return resp


@patch.dict("os.environ", {"SLACK_BOT_TOKEN_AGENTS": "xoxb-test"})
@patch("app.agents.slack.client.requests.post")
def test_post_includes_persona_username_and_icon(mock_post, app):
    mock_post.return_value = _ok_response()
    with app.app_context():
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
def test_post_threads_when_thread_ts_given(mock_post, app):
    mock_post.return_value = _ok_response()
    with app.app_context():
        post_as_agent(channel="C123", agent_id="engineer",
                      text="hi", thread_ts="1715890000.123")
    payload = mock_post.call_args.kwargs["json"]
    assert payload["thread_ts"] == "1715890000.123"


@patch.dict("os.environ", {"SLACK_BOT_TOKEN_AGENTS": "xoxb-test"})
@patch("app.agents.slack.client.requests.post")
def test_post_swallows_slack_4xx_logs_and_returns_false(mock_post, app, caplog):
    mock_post.return_value = _ok_response(body={"ok": False, "error": "channel_not_found"})
    with app.app_context():
        result = post_as_agent(channel="Cbad", agent_id="engineer", text="hi")
    assert result is False
    assert "channel_not_found" in caplog.text


@patch.dict("os.environ", {"SLACK_BOT_TOKEN_AGENTS": "xoxb-test"})
@patch("app.agents.slack.client.requests.post", side_effect=ConnectionError("boom"))
def test_post_swallows_network_error_logs_and_returns_false(mock_post, app, caplog):
    with app.app_context():
        result = post_as_agent(channel="C123", agent_id="engineer", text="hi")
    assert result is False
    assert "boom" in caplog.text


@patch.dict("os.environ", {}, clear=True)
def test_post_noop_when_token_missing(app, caplog):
    with app.app_context():
        result = post_as_agent(channel="C123", agent_id="engineer", text="hi")
    assert result is False  # no-op, not an error
```

- [ ] **Step 2: Run test to verify failure**

```bash
cd backend
pytest tests/test_agents_slack_client.py -v
```

Expected: ImportError on `app.agents.slack.client`.

- [ ] **Step 3: Implement client.py**

Create `backend/app/agents/slack/client.py`:

```python
"""Slack Web API client — chat.postMessage with chat:write.customize.

One bot identity (the @nano app), but every post sets username + icon_url
so each agent looks like their own persona in Slack.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import requests

from app.agents.profile_loader import load_profile


logger = logging.getLogger("agents.slack.client")
POST_URL = "https://slack.com/api/chat.postMessage"
TIMEOUT_SECONDS = 10


class SlackPostError(Exception):
    """Raised only by callers that explicitly opt into raising — default is swallow+log."""


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
        profile = load_profile(agent_id)
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
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json; charset=utf-8"},
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
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd backend
pytest tests/test_agents_slack_client.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agents/slack/client.py \
        backend/tests/test_agents_slack_client.py
git commit -m "feat(agents/slack): chat.postMessage client with persona username + icon"
```

---

## Task 6: Outbound publisher

High-level dispatchers that the rest of the system calls. Formatting + channel choice live here.

**Files:**
- Create: `backend/app/agents/slack/publisher.py`
- Create: `backend/tests/test_agents_slack_publisher.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_slack_publisher.py`:

```python
"""Publisher — formatting + channel selection for outbound posts."""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock


BROADCAST = "C_BROADCAST"


@patch.dict("os.environ", {
    "SLACK_BROADCAST_CHANNEL_ID": BROADCAST,
    "SLACK_BOT_TOKEN_AGENTS": "xoxb-test",
})
@patch("app.agents.slack.publisher.post_as_agent")
def test_broadcast_brief_posts_to_broadcast(mock_post, app):
    from app.agents.slack.publisher import broadcast_brief
    mock_post.return_value = True
    with app.app_context():
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
def test_broadcast_approval_pending_includes_link(mock_post, app):
    from app.agents.slack.publisher import broadcast_approval_pending
    mock_post.return_value = True
    action = MagicMock()
    action.id = 42
    action.agent_id = "engineer"
    action.action_type = "code-pr"
    action.target = "feat/fix-foo"
    with app.app_context():
        broadcast_approval_pending(action)
    text = mock_post.call_args.kwargs["text"]
    assert "approvals/42" in text or "approvals" in text
    assert "code-pr" in text or "PR" in text
    assert mock_post.call_args.kwargs["agent_id"] == "engineer"
    assert mock_post.call_args.kwargs["channel"] == BROADCAST


@patch.dict("os.environ", {
    "SLACK_BROADCAST_CHANNEL_ID": BROADCAST,
    "SLACK_BOT_TOKEN_AGENTS": "xoxb-test",
})
@patch("app.agents.slack.publisher.post_as_agent")
def test_broadcast_run_completed_includes_cost(mock_post, app):
    from app.agents.slack.publisher import broadcast_run_completed
    mock_post.return_value = True
    run = MagicMock()
    run.id = 7
    run.agent_id = "engineer"
    run.cost_usd = 0.04
    run.status = "completed"
    with app.app_context():
        broadcast_run_completed(run)
    text = mock_post.call_args.kwargs["text"]
    assert "0.04" in text or "$0.04" in text


@patch.dict("os.environ", {}, clear=True)
@patch("app.agents.slack.publisher.post_as_agent")
def test_publisher_noop_when_broadcast_channel_unset(mock_post, app):
    from app.agents.slack.publisher import broadcast_brief
    with app.app_context():
        broadcast_brief(agent_id="founder-ops", subject="x", body="y")
    assert not mock_post.called


@patch.dict("os.environ", {
    "SLACK_BROADCAST_CHANNEL_ID": BROADCAST,
    "SLACK_BOT_TOKEN_AGENTS": "xoxb-test",
})
@patch("app.agents.slack.publisher.post_as_agent")
def test_long_brief_chunks(mock_post, app):
    from app.agents.slack.publisher import broadcast_brief
    mock_post.return_value = True
    body = ("x" * 100 + "\n") * 50  # ~5100 chars, exceeds 3000 cap
    with app.app_context():
        broadcast_brief(agent_id="founder-ops", subject="big", body=body)
    # First call goes to channel root; subsequent calls thread-reply on it
    assert mock_post.call_count >= 2
```

- [ ] **Step 2: Run test to verify failure**

```bash
cd backend
pytest tests/test_agents_slack_publisher.py -v
```

Expected: ImportError on `app.agents.slack.publisher`.

- [ ] **Step 3: Implement publisher.py**

Create `backend/app/agents/slack/publisher.py`:

```python
"""High-level outbound Slack dispatch.

The rest of the system (approvals.py, routes.py, the weekly skill modules)
calls these functions. They handle formatting, channel selection, and
"no broadcast channel configured" no-op behaviour.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from .client import post_as_agent


logger = logging.getLogger("agents.slack.publisher")
PUBLIC_BASE = "https://nanoeasm.com"
MESSAGE_CHAR_CAP = 3000


def _broadcast_channel() -> str:
    return os.environ.get("SLACK_BROADCAST_CHANNEL_ID", "")


def _chunk(text: str, cap: int = MESSAGE_CHAR_CAP) -> list[str]:
    if len(text) <= cap:
        return [text]
    chunks: list[str] = []
    remaining = text
    while remaining:
        chunks.append(remaining[:cap])
        remaining = remaining[cap:]
    return chunks


def broadcast_brief(agent_id: str, subject: str, body: str) -> None:
    """Post a scheduled brief to #nano-broadcast.

    Long briefs are chunked across one root message + thread-replies.
    No-op when SLACK_BROADCAST_CHANNEL_ID is unset.
    """
    channel = _broadcast_channel()
    if not channel:
        return

    head = f"*{subject}*\n\n"
    chunks = _chunk(head + body, cap=MESSAGE_CHAR_CAP)
    # First chunk goes to channel root
    root_ts: str | None = None
    if not post_as_agent(channel=channel, agent_id=agent_id, text=chunks[0]):
        return
    # For the remaining chunks, we'd want to thread under the root post, but
    # post_as_agent does not return the new message's ts. v1: post follow-up
    # chunks in-channel (not threaded). Acceptable at brief-volume; can be
    # tightened later by switching post_as_agent to return the ts.
    for c in chunks[1:]:
        post_as_agent(channel=channel, agent_id=agent_id, text=c, thread_ts=root_ts)


def broadcast_approval_pending(action: Any) -> None:
    """Post an approval-pending card to #nano-broadcast.

    `action` is a PendingAction row (or duck-typed equivalent with .id,
    .agent_id, .action_type, .target).
    """
    channel = _broadcast_channel()
    if not channel:
        return
    link = f"{PUBLIC_BASE}/admin/agents/approvals/{action.id}"
    label = (action.action_type or "action").replace("-", " ").title()
    target = f" — `{action.target}`" if action.target else ""
    text = (
        f":bell: Pending approval: *{label}*{target}\n"
        f"<{link}|Review in admin>"
    )
    post_as_agent(channel=channel, agent_id=action.agent_id, text=text)


def broadcast_run_completed(run: Any) -> None:
    """Post a one-line run-completion summary to #nano-broadcast.

    Skipped silently when channel is unset OR when the run did not complete
    successfully (failures already surface via inline error posts).
    """
    channel = _broadcast_channel()
    if not channel:
        return
    if getattr(run, "status", None) != "completed":
        return

    cost = getattr(run, "cost_usd", None)
    cost_str = f"${float(cost):.2f}" if cost else "$0.00"
    text = f":white_check_mark: Run #{run.id} completed — {cost_str}"
    post_as_agent(channel=channel, agent_id=run.agent_id, text=text)
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd backend
pytest tests/test_agents_slack_publisher.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agents/slack/publisher.py \
        backend/tests/test_agents_slack_publisher.py
git commit -m "feat(agents/slack): outbound publisher — briefs, approvals, completions"
```

---

## Task 7: Events endpoint (Flask route, ack-fast, enqueue)

The biggest task. Ties everything together: verify, dedupe, auth, ack within 3s, run agent in a daemon thread, post reply.

**Files:**
- Create: `backend/app/agents/slack/events.py`
- Create: `backend/tests/test_agents_slack_events.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_slack_events.py`:

```python
"""POST /api/integrations/slack/events — verify, ack-fast, enqueue."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import os
from unittest.mock import patch, MagicMock

import pytest


SECRET = "test-signing-secret"
BOT_USER_ID = "U_NANO"
FOUNDER_USER = "U_FOUNDER"
CHAT_CHANNEL = "C_CHAT"


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


@pytest.fixture()
def slack_env(monkeypatch):
    monkeypatch.setenv("SLACK_SIGNING_SECRET_AGENTS", SECRET)
    monkeypatch.setenv("SLACK_BOT_USER_ID_AGENTS", BOT_USER_ID)
    monkeypatch.setenv("FOUNDER_SLACK_USER_ID", FOUNDER_USER)
    monkeypatch.setenv("SLACK_CHAT_CHANNEL_ID", CHAT_CHANNEL)


def test_url_verification_challenge(client, slack_env):
    body = {"type": "url_verification", "challenge": "abc123"}
    resp = _sign_request(client, body)
    assert resp.status_code == 200
    assert resp.get_json()["challenge"] == "abc123"


def test_bad_signature_returns_403(client, slack_env):
    body = {"type": "event_callback"}
    raw = json.dumps(body).encode()
    resp = client.post(
        "/api/integrations/slack/events",
        data=raw,
        content_type="application/json",
        headers={"X-Slack-Signature": "v0=bogus", "X-Slack-Request-Timestamp": str(int(time.time()))},
    )
    assert resp.status_code == 403


def test_wrong_user_returns_200_silent(client, slack_env):
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


def test_wrong_channel_returns_200_silent(client, slack_env):
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


def test_valid_app_mention_enqueues_and_acks(client, slack_env):
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
    # signature: _run_async(agent_id, prompt, channel, thread_ts)
    assert args[0] == "engineer"
    assert args[1] == "hi"
    assert args[2] == CHAT_CHANNEL


def test_duplicate_event_id_skipped(client, slack_env):
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


def test_thread_reply_uses_thread_owner_lookup(client, slack_env):
    """A message in an existing thread (no @mention) uses thread_owner."""
    from app.agents.slack.thread_owner import owner_cache
    owner_cache.set("1715890000.300", "security-analyst")  # seed the cache
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
    assert args[0] == "security-analyst"  # routed to Maya, not default
    assert args[1] == "follow-up question"


def test_bot_self_message_ignored(client, slack_env):
    """Bot's own posts arrive as message events too — must not loop."""
    body = {
        "type": "event_callback",
        "event_id": "Ev_botself",
        "event": {"type": "message", "user": FOUNDER_USER,
                  "channel": CHAT_CHANNEL, "text": "hi",
                  "ts": "1715890000.400",
                  "bot_id": "B_NANO"},  # bot_id present -> skip
    }
    with patch("app.agents.slack.events._run_async") as mock_run:
        resp = _sign_request(client, body)
    assert resp.status_code == 200
    assert not mock_run.called
```

- [ ] **Step 2: Run test to verify failure**

```bash
cd backend
pytest tests/test_agents_slack_events.py -v
```

Expected: 404 on the endpoint (blueprint not registered) — most likely ModuleNotFoundError or 404 depending on whether the blueprint is registered yet. Either way: red.

- [ ] **Step 3: Implement events.py**

Create `backend/app/agents/slack/events.py`:

```python
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
from typing import Any

from flask import Blueprint, current_app, jsonify, request

from app.agents.runtime import run_agent
from app.extensions import db

from .client import post_as_agent
from .publisher import broadcast_run_completed
from .router import parse_message, DEFAULT_AGENT_ID
from .signing import verify_signature
from .thread_owner import owner_cache
from .thread_map import map_cache


logger = logging.getLogger("agents.slack.events")

bp = Blueprint("agents_slack", __name__, url_prefix="/api/integrations/slack")


# In-process LRU for event_id dedupe.
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
    raw = request.get_data()  # bytes, exact body for HMAC

    if not verify_signature(dict(request.headers), raw):
        return ("forbidden", 403)

    body = request.get_json(silent=True) or {}

    # 1. URL verification handshake (one-time when Slack sets up the URL).
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
    thread_ts = event.get("thread_ts")  # None for top-of-channel messages
    bot_id = event.get("bot_id")

    # 2. Auth allowlist — silent 200 on mismatch.
    founder = os.environ.get("FOUNDER_SLACK_USER_ID", "")
    chat_channel = os.environ.get("SLACK_CHAT_CHANNEL_ID", "")
    if not founder or not chat_channel:
        return ("", 200)
    if user != founder:
        return ("", 200)
    if channel != chat_channel:
        return ("", 200)
    if bot_id:
        return ("", 200)  # bot's own message — don't loop
    if event_type not in ("app_mention", "message"):
        return ("", 200)

    # 3. Route to an agent.
    bot_user_id = os.environ.get("SLACK_BOT_USER_ID_AGENTS", "")
    agent_id, cleaned = parse_message(text, bot_user_id=bot_user_id)

    # For thread replies without re-addressing, defer to thread-owner cache.
    is_explicit_address = (text or "").strip().startswith(f"<@{bot_user_id}>") if bot_user_id else False
    if thread_ts and not is_explicit_address:
        agent_id = owner_cache.get(thread_ts)

    # Top-of-channel message: owner = the agent we just routed to.
    if not thread_ts:
        owner_cache.set(ts, agent_id)

    # Sam-only re-addressing inside a thread he owns.
    if thread_ts and is_explicit_address:
        owner = owner_cache.get(thread_ts)
        if owner == "founder-ops":
            re_routed, cleaned = parse_message(text, bot_user_id=bot_user_id)
            agent_id = re_routed  # one-turn override; thread owner remains Sam

    # The conversation key for thread continuation in runtime.
    convo_ts = thread_ts or ts

    _run_async(agent_id, cleaned, channel, convo_ts)
    return ("", 200)


def _run_async(agent_id: str, prompt: str, channel: str, convo_ts: str) -> None:
    """Spawn the agent run in a daemon thread so we ack Slack within 3s."""
    flask_app = current_app._get_current_object()  # bind app for the thread

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
    """Inside-thread: optional ack, run agent, post reply."""
    from app.agents.profile_loader import load_profile

    profile = load_profile(agent_id)

    # Optional "On it." ack
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

    # Record the new AgentThread id if this was the first turn.
    if thread_id is None and result.thread is not None:
        map_cache.set(convo_ts, result.thread.id)

    reply = (result.text or "").strip() or "_(no reply)_"
    post_as_agent(channel=channel, agent_id=agent_id, text=reply, thread_ts=convo_ts)
    broadcast_run_completed(result.run)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd backend
pytest tests/test_agents_slack_events.py -v
```

Expected: 7 passed (or red if `slack_events` blueprint not yet registered — that lands in Task 8; tests until Task 8 are run with the blueprint registered locally via a quick test-only patch if needed).

If the test client returns 404, the blueprint isn't being registered — finish Task 8 first, then re-run.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agents/slack/events.py \
        backend/tests/test_agents_slack_events.py
git commit -m "feat(agents/slack): events endpoint — verify, ack-fast, enqueue"
```

---

## Task 8: Register blueprint in app factory

**Files:**
- Modify: `backend/app/__init__.py`

- [ ] **Step 1: Find the block of `app.register_blueprint` calls**

```bash
grep -n "register_blueprint" backend/app/__init__.py | head -25
```

The block sits in `create_app()` starting around line 174 in current `master`.

- [ ] **Step 2: Add the Slack blueprint registration**

Open `backend/app/__init__.py`. Find the import section near the top (where existing blueprints are imported) and add:

```python
from app.agents.slack.events import bp as agents_slack_bp
```

In `create_app()`, alongside the other `app.register_blueprint(...)` calls (after the existing agents blueprint registration), add:

```python
app.register_blueprint(agents_slack_bp)
```

- [ ] **Step 3: Run full Slack test suite to confirm end-to-end**

```bash
cd backend
pytest tests/test_agents_slack_signing.py \
       tests/test_agents_slack_router.py \
       tests/test_agents_slack_thread_owner.py \
       tests/test_agents_slack_client.py \
       tests/test_agents_slack_publisher.py \
       tests/test_agents_slack_events.py -v
```

Expected: all green.

- [ ] **Step 4: Sanity-check the broader app still boots**

```bash
cd backend
pytest tests/ -x -q
```

Expected: full suite green (or, at worst, the same failures as before the branch — confirm no regressions).

- [ ] **Step 5: Commit**

```bash
git add backend/app/__init__.py
git commit -m "feat(agents/slack): register events blueprint"
```

---

## Task 9: Hook approval-pending broadcast

**Files:**
- Modify: `backend/app/agents/approvals.py`
- Modify: `backend/tests/test_agents_approvals.py` (add a case)

- [ ] **Step 1: Write the failing test**

Append to `backend/tests/test_agents_approvals.py`:

```python
def test_propose_action_broadcasts_to_slack(app, db_session):
    from unittest.mock import patch
    from app.agents.approvals import propose_action

    with patch("app.agents.approvals.broadcast_approval_pending") as mock_b:
        action = propose_action(
            agent_id="engineer",
            action_type="code-pr",
            target="feat/x",
            payload={"branch_name": "feat/x"},
        )
    assert mock_b.called
    assert mock_b.call_args.args[0].id == action.id
```

- [ ] **Step 2: Run test to verify failure**

```bash
cd backend
pytest tests/test_agents_approvals.py::test_propose_action_broadcasts_to_slack -v
```

Expected: AttributeError or ImportError on `broadcast_approval_pending`.

- [ ] **Step 3: Wire the publisher call in approvals.py**

Open `backend/app/agents/approvals.py`. At the top, add:

```python
from app.agents.slack.publisher import broadcast_approval_pending
```

At the END of `propose_action()` — right before `return p` — add:

```python
    try:
        broadcast_approval_pending(p)
    except Exception:
        # Slack must never break the approval flow.
        import logging
        logging.getLogger("agents.approvals").exception("slack broadcast failed")
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd backend
pytest tests/test_agents_approvals.py -v
```

Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agents/approvals.py \
        backend/tests/test_agents_approvals.py
git commit -m "feat(agents): broadcast approval-pending pings to Slack"
```

---

## Task 10: Hook run-completion broadcast

**Files:**
- Modify: `backend/app/agents/routes.py`
- Modify: `backend/tests/test_agents_routes_thread.py` (or any agents-routes test file — add a case)

- [ ] **Step 1: Write the failing test**

Append to `backend/tests/test_agents_routes_thread.py` (or a comparable existing routes test):

```python
def test_trigger_run_broadcasts_completion(app, client, db_session, monkeypatch):
    """After a successful manual run, publisher.broadcast_run_completed is called."""
    from unittest.mock import patch, MagicMock

    # Stub the runtime so we don't hit Anthropic
    fake_result = MagicMock()
    fake_result.run.id = 1
    fake_result.run.status = "completed"
    fake_result.run.cost_usd = 0.04
    fake_result.run.agent_id = "engineer"
    fake_result.thread.id = 11
    fake_result.text = "ok"

    with patch("app.agents.routes.run_agent", return_value=fake_result), \
         patch("app.agents.routes.broadcast_run_completed") as mock_b:
        # Authenticate as superadmin in whatever way the existing tests do
        # (see require_root_admin usage in the file).
        # ...
        resp = client.post("/admin/agents/engineer/run",
                           json={"prompt": "hi"})
    assert resp.status_code == 200
    assert mock_b.called
```

Note: copy the auth pattern from the closest existing `trigger_run` test — `require_root_admin` decorator semantics vary by setup.

- [ ] **Step 2: Run test to verify failure**

```bash
cd backend
pytest tests/test_agents_routes_thread.py -v -k completion
```

Expected: ImportError or AttributeError.

- [ ] **Step 3: Wire the call in routes.py**

Open `backend/app/agents/routes.py`. Add to imports:

```python
from app.agents.slack.publisher import broadcast_run_completed
```

In `trigger_run()` (currently around line 169), after `db.session.commit()` but before the return, add:

```python
    try:
        broadcast_run_completed(result.run)
    except Exception:
        import logging
        logging.getLogger("agents.routes").exception("slack broadcast failed")
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd backend
pytest tests/test_agents_routes_thread.py -v
```

Expected: green.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agents/routes.py \
        backend/tests/test_agents_routes_thread.py
git commit -m "feat(agents): broadcast run completions to Slack"
```

---

## Task 11: Hook brief mirror (3 skill modules)

Three near-identical edits. One commit covers all three.

**Files:**
- Modify: `backend/app/agents/skills/weekly_summary.py`
- Modify: `backend/app/agents/skills/competitor_pulse.py`
- Modify: `backend/app/agents/skills/weekly_finding_brief.py`
- Modify: existing tests for those modules (add slack-call assertions)

- [ ] **Step 1: Locate the email-send call in each module**

```bash
grep -n "send\|resend\|email" backend/app/agents/skills/weekly_summary.py | head -10
grep -n "send\|resend\|email" backend/app/agents/skills/competitor_pulse.py | head -10
grep -n "send\|resend\|email" backend/app/agents/skills/weekly_finding_brief.py | head -10
```

- [ ] **Step 2: Write failing tests**

For each `tests/test_agents_<skill>.py` (existing files: `test_agents_competitor_pulse.py` is one; check for the others), append a test like:

```python
def test_run_weekly_summary_broadcasts_to_slack(app, db_session, monkeypatch):
    from unittest.mock import patch
    from app.agents.skills.weekly_summary import run_weekly_summary

    # Stub the agent run + email send to keep the test offline.
    fake_text = "Brief body — three asks landed, two findings flagged."
    monkeypatch.setattr("app.agents.skills.weekly_summary._run_brief_agent",
                        lambda *a, **kw: fake_text)  # adjust to actual helper name
    monkeypatch.setattr("app.agents.skills.weekly_summary._send_email",
                        lambda *a, **kw: None)       # adjust to actual helper name

    with patch("app.agents.skills.weekly_summary.broadcast_brief") as mock_b:
        run_weekly_summary(send=True)
    assert mock_b.called
    assert "founder-ops" in mock_b.call_args.kwargs.get("agent_id", "") \
        or mock_b.call_args.args and mock_b.call_args.args[0] == "founder-ops"
```

(The exact stubs depend on each skill's internal structure — open the file and identify the email-send + agent-run helpers before writing the test.)

Mirror the test for `competitor_pulse` (agent_id `strategy`) and `weekly_finding_brief` (agent_id `security-analyst`).

- [ ] **Step 3: Run tests to verify failure**

```bash
cd backend
pytest tests/test_agents_competitor_pulse.py -v -k slack
```

Expected: AttributeError on `broadcast_brief`.

- [ ] **Step 4: Wire the broadcast call in each skill**

For `backend/app/agents/skills/weekly_summary.py`, add to imports:

```python
from app.agents.slack.publisher import broadcast_brief
```

Inside `run_weekly_summary(send=True)`, after the email send but inside the same `if send:` branch, add:

```python
    try:
        broadcast_brief(
            agent_id="founder-ops",
            subject=f"Weekly summary — week of {week_label}",  # use the existing var
            body=brief_text,
        )
    except Exception:
        import logging
        logging.getLogger("agents.skills.weekly_summary").exception(
            "slack broadcast failed"
        )
```

(`week_label` and `brief_text` names depend on the existing variables — substitute the right names. Goal: pass a date-anchored subject and the rendered body.)

Repeat for `competitor_pulse.py` (`agent_id="strategy"`, subject "Competitor pulse — week of ...") and `weekly_finding_brief.py` (`agent_id="security-analyst"`, subject "Weekly finding brief — week of ...").

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd backend
pytest tests/test_agents_competitor_pulse.py \
       tests/test_agents_routes_thread.py \
       tests/test_agents_approvals.py -v
```

(Run the broader agent test suite if other brief-specific files exist.)

Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add backend/app/agents/skills/weekly_summary.py \
        backend/app/agents/skills/competitor_pulse.py \
        backend/app/agents/skills/weekly_finding_brief.py \
        backend/tests/test_agents_competitor_pulse.py
# Plus whichever weekly_summary / weekly_finding_brief test files you touched.
git commit -m "feat(agents): mirror weekly briefs to #nano-broadcast"
```

---

## Task 12: Commit avatar placeholders

Six 256×256 PNG placeholders. Founder swaps real avatars later. The Slack `icon_url` field accepts any reachable HTTPS URL — when the avatars are placeholder grey, Slack shows grey circles; functional but ugly. Acceptable for v1 deploy.

**Files:**
- Create: `frontend/public/agents/sam.png`
- Create: `frontend/public/agents/rob.png`
- Create: `frontend/public/agents/aisha.png`
- Create: `frontend/public/agents/maya.png`
- Create: `frontend/public/agents/ava.png`
- Create: `frontend/public/agents/john.png`

- [ ] **Step 1: Generate six 256×256 placeholder PNGs**

Quick local generator (Python with Pillow if available; otherwise hand-make in any image tool):

```bash
cd frontend/public
mkdir -p agents
python - <<'EOF'
from PIL import Image, ImageDraw, ImageFont
import os
names_colors = [
    ("sam",   "#1f6feb"),
    ("rob",   "#0e8a16"),
    ("aisha", "#9c27b0"),
    ("maya",  "#d33b39"),
    ("ava",   "#fb8c00"),
    ("john",  "#3949ab"),
]
for name, color in names_colors:
    img = Image.new("RGB", (256, 256), color)
    d = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", 96)
    except Exception:
        font = ImageFont.load_default()
    bbox = d.textbbox((0, 0), name[0].upper(), font=font)
    w = bbox[2] - bbox[0]; h = bbox[3] - bbox[1]
    d.text(((256 - w) / 2, (256 - h) / 2 - 10), name[0].upper(),
           fill="white", font=font)
    img.save(f"agents/{name}.png")
print("wrote", [f"agents/{n}.png" for n, _ in names_colors])
EOF
```

If Pillow isn't available locally, hand-create 6 solid-colour 256×256 PNGs in any image editor — content doesn't matter, only that the file exists and is reachable.

- [ ] **Step 2: Verify the files land where expected**

```bash
ls -la frontend/public/agents/
```

Expected: 6 PNG files, each non-empty.

- [ ] **Step 3: Commit**

```bash
git add frontend/public/agents/
git commit -m "feat(agents/slack): persona avatar placeholders"
```

---

## Task 13: Document env vars in CLAUDE.md and .env example

**Files:**
- Modify: `CLAUDE.md` (project instructions)
- Modify or check: `backend/.env.example` (if one exists)

- [ ] **Step 1: Append a Slack section to CLAUDE.md under "Internal Agent Platform"**

Open `CLAUDE.md`. Find the "Internal Agent Platform (Phase 1)" section's env-vars block (currently lists `ANTHROPIC_API_KEY_AGENTS`, `RESEND_TOKEN_AGENTS`, etc.). Append:

```
SLACK_BOT_TOKEN_AGENTS=xoxb-...                  # bot user OAuth token
SLACK_BOT_USER_ID_AGENTS=U...                    # bot's own user id (for mention-strip)
SLACK_SIGNING_SECRET_AGENTS=...                  # for HMAC signature verification
SLACK_BROADCAST_CHANNEL_ID=C...                  # #nano-broadcast
SLACK_CHAT_CHANNEL_ID=C...                       # #nano-chat
FOUNDER_SLACK_USER_ID=U...                       # only this user's events are processed
```

Also add a one-paragraph note under "Phase 2B-2+ (still to plan)" — bump the phase-tracker. Insert a new "Phase 2B-3 (Slack integration, shipped)" section above it:

```markdown
### Phase 2B-3 (Slack integration, shipped)

Two private Slack channels in the founder workspace:
- `#nano-broadcast` — outbound: Mon/Tue/Wed briefs, approval-pending pings, run-completion summaries.
- `#nano-chat` — bidirectional, threaded. Founder addresses by persona prefix (`@nano rob, ...`).

One Slack app posts as 6 personas via `chat:write.customize`. Only Sam can re-address inside a thread he owns. Approvals stay link-only — Slack links to `/admin/agents/approvals/<id>`; decisions happen in the web UI.
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: Slack integration env vars + Phase 2B-3 note"
```

---

## Task 14: Configure Slack Event Subscription URL (post-deploy)

Manual. Not Claude Code's job. Documented for the founder.

- [ ] **Step 1: Deploy to prod**

```bash
ssh prod-server
cd ~/boltedge-easm
git pull
docker compose up -d --build
```

- [ ] **Step 2: Set env vars on prod**

Add the SLACK_* env vars from Task 0 Step 7 to the deployment env file. Redeploy/restart the backend container so they're loaded.

- [ ] **Step 3: Point Slack Events API at the prod URL**

Slack app → "Event Subscriptions" → enable. Request URL: `https://nanoeasm.com/api/integrations/slack/events`. Slack POSTs a `url_verification` challenge — the endpoint replies with `{challenge: "..."}` and Slack marks the URL verified.

Subscribe to bot events: `app_mention`, `message.channels`.

Reinstall the app to pick up the new event subscription.

- [ ] **Step 4: Run the manual smoke checklist**

1. Send `@nano sam, hi` in #nano-chat → Sam avatar replies in-thread.
2. Reply in same thread without `@nano` → Sam continues.
3. Send `@nano rob, propose a tiny no-op PR (e.g., add a comment to README)` → Rob avatar replies; approval ping lands in #nano-broadcast with link.
4. Trigger Monday weekly summary manually (`flask agents run weekly_summary` or whatever the existing CLI is) → brief lands in #nano-broadcast with Sam avatar.
5. Send a message from a non-founder Slack user in the same channel → silent no-op (no reply, no log noise beyond the silent-200).

---

## Task 15 (optional): Integration smoke test

Real Slack API call to a throwaway channel. Skipped in CI; runnable manually.

**Files:**
- Create: `backend/tests/integration/__init__.py` (if missing)
- Create: `backend/tests/integration/test_slack_smoke.py`

- [ ] **Step 1: Create the smoke test**

```python
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


def test_post_as_sam_appears_in_throwaway_channel(app):
    from app.agents.slack.client import post_as_agent
    channel = os.environ["SLACK_SMOKE_CHANNEL_ID"]
    with app.app_context():
        ok = post_as_agent(channel=channel, agent_id="founder-ops",
                           text="smoke test from pytest")
    assert ok is True
```

- [ ] **Step 2: Commit**

```bash
git add backend/tests/integration/
git commit -m "test(agents/slack): real-Slack smoke test (gated)"
```

---

## Self-review

**Spec coverage check:** every spec section maps to a task —

| Spec section | Tasks |
|---|---|
| Architecture diagram | Tasks 1–8 build the depicted modules |
| Components — `signing.py` | Task 1 |
| Components — `router.py` | Task 2 |
| Components — `thread_owner.py` / thread state | Task 3 |
| Components — `client.py` | Task 5 |
| Components — `publisher.py` | Task 6 |
| Components — `events.py` | Task 7 |
| Profile config additions | Task 4 |
| Env vars | Task 13 (docs) + Task 0 (setup) + Task 14 (deploy) |
| Blueprint registration | Task 8 |
| Approval-pending hook | Task 9 |
| Run-completion hook | Task 10 |
| Brief mirror hook | Task 11 |
| Persona avatars | Task 12 |
| Manual smoke checklist | Task 14 |
| Integration smoke test | Task 15 |
| Error handling layers 1–3 | Built into Tasks 5 (client swallow+log), 7 (events 403/200), 7 (runtime err catch) |
| Edge case: lost thread context | Currently NOT explicitly tested — would land in events.py if `conversations.replies` were added. **Deferred** — the implementation uses AgentThread for continuation instead of re-fetching from Slack, so this edge case is moot for v1. Spec needs a note. See "Spec amendment" below. |

**Spec amendment to note:** The spec described stateless thread continuation via `conversations.replies`. The plan instead uses `AgentThread` (existing infra) keyed by an in-memory `slack_ts → thread_id` LRU. Pros: simpler, runtime works as-is. Cons: if the backend restarts and the LRU clears, mid-thread messages start a fresh `AgentThread` (Slack thread visually continues but the agent loses context). Acceptable trade for v1; revisit if it bites in practice.

**Placeholder scan:** no TBDs / TODOs / "implement later". All code is concrete.

**Type consistency:** `parse_message`, `post_as_agent`, `propose_action`, `broadcast_*` signatures consistent across tasks. `Profile.slack_*` fields named identically in Task 4 (loader) and Task 5 (client read).

**Known fragility — call out to executor:** Task 11 has uncertainty about the exact internal helper names in each skill module. The plan tells the executor to grep first, identify the actual helpers, then apply the pattern. This is a deliberate "look before you leap" beat, not a placeholder.
