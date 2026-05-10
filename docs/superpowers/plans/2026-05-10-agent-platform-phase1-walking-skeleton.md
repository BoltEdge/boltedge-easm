# Internal Agent Platform — Phase 1 Walking Skeleton

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the smallest end-to-end working slice of the internal agent platform — one fully operational agent (Founder Ops), full memory model, full approval queue, full admin UI for one agent, one scheduled brief (Monday `weekly-summary`). After this plan: the founder can manually invoke Founder Ops, see runs persist, approve/reject memory writes, and receive a Monday morning weekly summary email.

**Architecture:** Co-hosted Flask blueprint at `backend/app/agents/` plus Next.js admin UI at `frontend/app/(authenticated)/admin/agents/`. New `agent_*` Postgres tables. Per-agent read-only API keys gate the `/api/internal/...` blueprint that agents call from inside the same app (preserving the API seam). Memory is per-agent isolated (tag-matched retrieval) plus a small shared `team_memory`. Approval queue gates every memory write and externally-visible output.

**Tech Stack:**
- **Backend:** Flask + SQLAlchemy 1.x style (`db.Column(...)`, naive UTC via `now_utc()`), Alembic via Flask-Migrate, APScheduler (already wired), Anthropic Python SDK (`anthropic>=0.40`), Resend (already wired).
- **Frontend:** Next.js 16 App Router + Tailwind, existing API client at `frontend/app/lib/api.ts`.
- **Tests:** pytest (existing), no mocking of the Anthropic API in tests — use a `FakeAnthropicClient` injected at runtime for unit tests; one manual smoke test for live Anthropic.
- **Auth on agent endpoints:** new `require_agent_key` decorator validating bearer key with `kind='agent'` from the existing `api_key` table.
- **Auth on admin UI endpoints:** existing `require_superadmin` decorator.

**Out of scope for this plan (covered in Plan 2 later):**
- Other 5 agents (Engineer, QA, Security Analyst, Strategy, Voice) — only stub profile files exist after this plan.
- Tuesday + Wednesday briefs (Strategy `competitor-pulse`, Security Analyst `weekly-finding-brief`).
- Other 4 internal API endpoints (`findings/recent`, `contact-requests/recent`, `audit-log/recent`, `scans/recent`) — only `stats/weekly` is built.
- Memory hygiene weekly job, low-confidence review queue.
- Memory viewer UI (only basic listing in admin profile page).
- Agent thread chat UI beyond run history.

**Milestones inside this plan** (each is a viable stopping point with working software):

| Stage | Outcome | Tasks |
|---|---|---|
| A | DB tables exist, blueprint registers | 1–4 |
| B | Internal API stats endpoint works with agent key | 5–7 |
| C | Founder Ops profile loads from disk | 8–10 |
| D | Memory CRUD + retrieval works | 11–14 |
| E | Anthropic client wrapper with cost tracking | 15–17 |
| F | Agent runs end-to-end (manual prompt → persisted run + message) | 18–20 |
| G | Approval queue + memory-write gate | 21–24 |
| H | Send service ready (Resend digest + post-approval send) | 25–26 |
| I | `weekly-summary` skill + Monday scheduled brief | 27–29 |
| J | Admin UI: list, detail, run, approvals | 30–34 |
| K | End-to-end smoke + docs | 35–37 |

---

## Stage A — Database foundation

### Task 1: Add `kind` column to `api_key` table

**Files:**
- Modify: `backend/app/models.py` (the `ApiKey` class)
- Test: `backend/tests/test_api_key_kind.py` (create)

- [ ] **Step 1: Verify `ApiKey` model exists and read its current shape**

Run: `grep -n "class ApiKey" backend/app/models.py`
Expected: prints a line number where `class ApiKey(db.Model):` is defined. If the class doesn't exist, stop and report — this plan assumes it does (it's referenced by the existing API-key flow described in CLAUDE.md). Do not proceed.

- [ ] **Step 2: Write the failing test**

Create `backend/tests/test_api_key_kind.py`:

```python
from app.models import ApiKey

def test_api_key_has_kind_column_with_default_customer():
    """ApiKey rows must have a `kind` column defaulting to 'customer'.
    Agent platform tags new keys as kind='agent' to keep them out of
    customer-facing listings."""
    key = ApiKey(
        organization_id=1,
        user_id=1,
        name="test",
        key_hash="abc",
        prefix="nk_test",
    )
    assert key.kind == "customer"


def test_api_key_kind_can_be_agent():
    key = ApiKey(
        organization_id=1,
        user_id=1,
        name="test",
        key_hash="abc",
        prefix="nk_test",
        kind="agent",
    )
    assert key.kind == "agent"
```

- [ ] **Step 3: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_api_key_kind.py -v`
Expected: FAIL with `AttributeError: ... has no attribute 'kind'` (or similar).

- [ ] **Step 4: Add the column to the model**

In `backend/app/models.py`, locate the `ApiKey` class. Add a new column after the existing string columns:

```python
    # Phase-1 agent platform: 'customer' for normal API keys, 'agent' for
    # internal agent platform keys (read-only scoped, hidden from
    # customer-facing listings).
    kind = db.Column(
        db.String(20), nullable=False,
        default="customer", server_default=db.text("'customer'"),
        index=True,
    )
```

- [ ] **Step 5: Run the test — verify it passes**

Run: `cd backend && pytest tests/test_api_key_kind.py -v`
Expected: PASS for both tests.

- [ ] **Step 6: Commit**

```bash
git add backend/app/models.py backend/tests/test_api_key_kind.py
git commit -m "feat(agents): add kind column to api_key for agent-platform keys"
```

---

### Task 2: Add agent platform models to `models.py`

**Files:**
- Modify: `backend/app/models.py` (append new classes)
- Test: `backend/tests/test_agent_models.py` (create)

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agent_models.py`:

```python
from app.models import (
    AgentMemory,
    TeamMemory,
    AgentThread,
    AgentMessage,
    AgentRun,
    AgentTask,
    PendingAction,
)


def test_agent_memory_fields():
    m = AgentMemory(
        agent_id="founder-ops",
        key="customer:acme:plan_tier",
        value={"tier": "Pro"},
        tags=["customer:acme", "topic:plan"],
        source="user-told",
    )
    assert m.agent_id == "founder-ops"
    assert m.key == "customer:acme:plan_tier"
    assert m.confidence == 1.00
    assert m.tags == ["customer:acme", "topic:plan"]


def test_team_memory_fields():
    m = TeamMemory(
        key="brand:never_use_boltedge",
        value={"rule": "Always use 'Nano EASM', never 'BoltEdge'"},
        tags=["brand", "rule"],
    )
    assert m.key == "brand:never_use_boltedge"


def test_agent_thread_message_relation():
    t = AgentThread(agent_id="founder-ops", title="weekly-summary 2026-05-11")
    msg = AgentMessage(role="user", content={"text": "Run the weekly summary"})
    t.messages.append(msg)
    assert msg.thread is t


def test_agent_run_status_default():
    r = AgentRun(
        agent_id="founder-ops",
        skill="weekly-summary",
        input={"prompt": "go"},
        status="success",
    )
    assert r.status == "success"


def test_agent_task_fields():
    t = AgentTask(title="Ship walking skeleton", status="pending", priority=1)
    assert t.title == "Ship walking skeleton"


def test_pending_action_fields():
    p = PendingAction(
        agent_id="founder-ops",
        action_type="memory-write",
        target="customer:acme:plan_tier",
        payload={"value": "Pro"},
        rationale="Heard in the support thread.",
    )
    assert p.action_type == "memory-write"
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agent_models.py -v`
Expected: FAIL with `ImportError` for the new models.

- [ ] **Step 3: Add models to `backend/app/models.py`**

Append these classes (at the bottom of the file, before the file ends; if there's an explicit end marker, place them above it):

```python
# ─────────────────────────────────────────────────────────────────────
# Phase-1 internal agent platform — see
# docs/superpowers/specs/2026-05-10-internal-agent-platform-design.md
# ─────────────────────────────────────────────────────────────────────


class AgentMemory(db.Model):
    """Per-agent operational memory. Isolated by agent_id."""

    __tablename__ = "agent_memory"

    id = db.Column(db.BigInteger, primary_key=True)
    agent_id = db.Column(db.String(64), nullable=False, index=True)
    key = db.Column(db.String(255), nullable=False)
    value = db.Column(db.JSON, nullable=False)
    tags = db.Column(db.JSON, nullable=False, default=list,
                     server_default=db.text("'[]'::json"))
    source = db.Column(db.String(40), nullable=False)  # user-told|inferred|api-fetched
    confidence = db.Column(db.Numeric(3, 2), nullable=False,
                            default=1.00, server_default=db.text("1.00"))
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    expires_at = db.Column(db.DateTime, nullable=True, index=True)
    superseded_by_id = db.Column(db.BigInteger,
                                  db.ForeignKey("agent_memory.id"),
                                  nullable=True)

    __table_args__ = (
        UniqueConstraint("agent_id", "key", name="uq_agent_memory_agent_key"),
    )


class TeamMemory(db.Model):
    """Universal facts visible to every agent. Founder writes only."""

    __tablename__ = "team_memory"

    id = db.Column(db.BigInteger, primary_key=True)
    key = db.Column(db.String(255), nullable=False, unique=True)
    value = db.Column(db.JSON, nullable=False)
    tags = db.Column(db.JSON, nullable=False, default=list,
                     server_default=db.text("'[]'::json"))
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc)


class AgentThread(db.Model):
    __tablename__ = "agent_thread"

    id = db.Column(db.BigInteger, primary_key=True)
    agent_id = db.Column(db.String(64), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    archived_at = db.Column(db.DateTime, nullable=True)

    messages = db.relationship(
        "AgentMessage",
        backref="thread",
        cascade="all, delete-orphan",
        order_by="AgentMessage.created_at",
    )


class AgentMessage(db.Model):
    __tablename__ = "agent_message"

    id = db.Column(db.BigInteger, primary_key=True)
    thread_id = db.Column(db.BigInteger,
                           db.ForeignKey("agent_thread.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    role = db.Column(db.String(20), nullable=False)  # user|assistant|tool
    content = db.Column(db.JSON, nullable=False)
    tokens_used = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)


class AgentRun(db.Model):
    """Immutable execution trace of one agent invocation."""

    __tablename__ = "agent_run"

    id = db.Column(db.BigInteger, primary_key=True)
    agent_id = db.Column(db.String(64), nullable=False, index=True)
    skill = db.Column(db.String(100), nullable=True)
    thread_id = db.Column(db.BigInteger,
                           db.ForeignKey("agent_thread.id"), nullable=True)
    input = db.Column(db.JSON, nullable=False)
    output = db.Column(db.JSON, nullable=True)
    tool_calls = db.Column(db.JSON, nullable=True)
    status = db.Column(db.String(30), nullable=False)  # success|failed|timeout|over-budget
    error = db.Column(db.Text, nullable=True)
    cost_usd = db.Column(db.Numeric(8, 4), nullable=True)
    duration_ms = db.Column(db.Integer, nullable=True)
    started_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    finished_at = db.Column(db.DateTime, nullable=True)


class AgentTask(db.Model):
    """Internal task list — Founder Ops writes; admin UI displays."""

    __tablename__ = "agent_task"

    id = db.Column(db.BigInteger, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default="pending")
    priority = db.Column(db.Integer, nullable=False, default=3)
    agent_owner = db.Column(db.String(64), nullable=True)
    due_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc)


class PendingAction(db.Model):
    """Approval queue. Every memory write / external output / code PR
    queues here until the founder approves, rejects, or it expires."""

    __tablename__ = "pending_action"

    id = db.Column(db.BigInteger, primary_key=True)
    agent_id = db.Column(db.String(64), nullable=False, index=True)
    skill = db.Column(db.String(100), nullable=True)
    action_type = db.Column(db.String(40), nullable=False, index=True)
    # action_type: memory-write | team-memory-write | external-output |
    #              code-pr | integration-write | nano-easm-write
    target = db.Column(db.String(255), nullable=True)
    payload = db.Column(db.JSON, nullable=False)
    rationale = db.Column(db.Text, nullable=True)
    proposed_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    expires_at = db.Column(db.DateTime, nullable=False)  # default proposed_at + 7d set in code
    decided_at = db.Column(db.DateTime, nullable=True)
    decision = db.Column(db.String(30), nullable=True)
    # decision: approved | rejected | edited-and-approved | expired
    decided_by = db.Column(db.String(255), nullable=True)
    decision_note = db.Column(db.Text, nullable=True)
    run_id = db.Column(db.BigInteger,
                        db.ForeignKey("agent_run.id"), nullable=True)
```

- [ ] **Step 4: Run the test — verify it passes**

Run: `cd backend && pytest tests/test_agent_models.py -v`
Expected: PASS for all six tests.

- [ ] **Step 5: Commit**

```bash
git add backend/app/models.py backend/tests/test_agent_models.py
git commit -m "feat(agents): add agent platform model classes"
```

---

### Task 3: Generate and apply Alembic migration

**Files:**
- Create: `backend/migrations/versions/<auto-named>_agent_platform_phase1.py` (Alembic-generated, then edited)

- [ ] **Step 1: Generate the migration**

Run from `backend/`:

```bash
flask db migrate -m "agent_platform_phase1"
```

Expected: a new file appears under `backend/migrations/versions/`. Note the filename — Alembic generates a 12-char hex prefix.

- [ ] **Step 2: Open the generated file and verify content**

The generated migration should contain `op.create_table(...)` for: `agent_memory`, `team_memory`, `agent_thread`, `agent_message`, `agent_run`, `agent_task`, `pending_action`. It should also contain `op.add_column('api_key', sa.Column('kind', ...))`.

If any table is missing, the migration is incomplete — fix the model in Task 2 and re-run `flask db migrate`. Delete the bad migration file before re-running.

- [ ] **Step 3: Apply the migration to local dev DB**

Run from `backend/`:

```bash
flask db upgrade
```

Expected: applies cleanly with no errors.

- [ ] **Step 4: Smoke-test schema in psql**

Run:

```bash
psql -h localhost -U easm_user -d easm -c "\d agent_memory"
```

Expected: table description prints with columns matching the model.

Repeat for `team_memory`, `agent_thread`, `agent_message`, `agent_run`, `agent_task`, `pending_action`. Also:

```bash
psql -h localhost -U easm_user -d easm -c "\d api_key" | grep kind
```

Expected: `kind | character varying(20)` row appears.

- [ ] **Step 5: Commit**

```bash
git add backend/migrations/versions/
git commit -m "feat(agents): migration for agent platform tables and api_key.kind"
```

---

### Task 4: Create the agents blueprint package

**Files:**
- Create: `backend/app/agents/__init__.py`
- Create: `backend/app/agents/routes.py` (admin endpoints — empty for now, blueprint only)
- Create: `backend/app/agents/internal_routes.py` (the `/api/internal/...` blueprint — empty for now)
- Modify: `backend/app/__init__.py` (register blueprints)

- [ ] **Step 1: Create blueprint package files**

Create `backend/app/agents/__init__.py`:

```python
"""Internal agent platform — co-hosted in Nano EASM.

Spec: docs/superpowers/specs/2026-05-10-internal-agent-platform-design.md
"""
```

Create `backend/app/agents/routes.py`:

```python
"""Admin UI endpoints for the agent platform.

All routes are gated by the existing `require_superadmin` decorator.
URL prefix: /admin/agents
"""
from flask import Blueprint

bp = Blueprint("agents_admin", __name__, url_prefix="/admin/agents")
```

Create `backend/app/agents/internal_routes.py`:

```python
"""Read-only API endpoints that agent code calls from inside the same
Flask app. Even though there is no network boundary, agents go through
this seam to avoid schema-coupling and to leave an audit trail.

URL prefix: /api/internal
Auth: require_agent_key (validates bearer key with kind='agent')
"""
from flask import Blueprint

bp = Blueprint("agents_internal", __name__, url_prefix="/api/internal")
```

- [ ] **Step 2: Register both blueprints in the app factory**

Find `backend/app/__init__.py`. It contains the app factory and a series of `app.register_blueprint(...)` calls (visible by grepping `register_blueprint`).

Add (alongside the other `register_blueprint` calls):

```python
    from .agents.routes import bp as agents_admin_bp
    from .agents.internal_routes import bp as agents_internal_bp
    app.register_blueprint(agents_admin_bp)
    app.register_blueprint(agents_internal_bp)
```

- [ ] **Step 3: Smoke test the blueprints register**

Run from `backend/`:

```bash
python -c "from app import create_app; app = create_app(); print([r.rule for r in app.url_map.iter_rules() if '/agents' in r.rule or '/api/internal' in r.rule])"
```

Expected: prints an empty list `[]` (no routes yet, but the import succeeded with no errors). If there's an `ImportError`, fix it before continuing.

- [ ] **Step 4: Commit**

```bash
git add backend/app/agents/ backend/app/__init__.py
git commit -m "feat(agents): scaffold agents blueprint package"
```

---

## Stage B — Internal API: stats/weekly endpoint

### Task 5: Build `require_agent_key` decorator

**Files:**
- Create: `backend/app/agents/auth.py`
- Test: `backend/tests/test_agents_auth.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_auth.py`:

```python
from flask import Flask, jsonify
from app.agents.auth import require_agent_key
from app.extensions import db
from app.models import ApiKey
import hashlib


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def test_missing_header_returns_401(app, client):
    @app.route("/_test_internal")
    @require_agent_key(scope="read:stats")
    def view():
        return jsonify(ok=True)

    resp = client.get("/_test_internal")
    assert resp.status_code == 401


def test_invalid_key_returns_401(app, client):
    @app.route("/_test_internal2")
    @require_agent_key(scope="read:stats")
    def view():
        return jsonify(ok=True)

    resp = client.get("/_test_internal2",
                       headers={"Authorization": "Bearer bogus"})
    assert resp.status_code == 401


def test_customer_kind_key_rejected(app, client, db_session):
    # An ordinary customer key must not be usable as an agent key
    raw = "nk_test_" + "a" * 32
    db_session.add(ApiKey(
        organization_id=1, user_id=1, name="cust",
        prefix="nk_test_", key_hash=_sha256(raw),
        kind="customer",
    ))
    db_session.commit()

    @app.route("/_test_internal3")
    @require_agent_key(scope="read:stats")
    def view():
        return jsonify(ok=True)

    resp = client.get("/_test_internal3",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 401


def test_agent_kind_key_with_scope_allowed(app, client, db_session):
    raw = "nk_agent_" + "b" * 32
    db_session.add(ApiKey(
        organization_id=1, user_id=1, name="founder-ops",
        prefix="nk_agent_", key_hash=_sha256(raw),
        kind="agent", scopes=["read:stats", "read:findings"],
    ))
    db_session.commit()

    @app.route("/_test_internal4")
    @require_agent_key(scope="read:stats")
    def view():
        return jsonify(ok=True)

    resp = client.get("/_test_internal4",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200


def test_agent_key_missing_scope_rejected(app, client, db_session):
    raw = "nk_agent_" + "c" * 32
    db_session.add(ApiKey(
        organization_id=1, user_id=1, name="founder-ops",
        prefix="nk_agent_", key_hash=_sha256(raw),
        kind="agent", scopes=["read:findings"],   # missing read:stats
    ))
    db_session.commit()

    @app.route("/_test_internal5")
    @require_agent_key(scope="read:stats")
    def view():
        return jsonify(ok=True)

    resp = client.get("/_test_internal5",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 403
```

This assumes a `scopes` JSON column on `ApiKey`. Check if it exists:

```bash
psql -h localhost -U easm_user -d easm -c "\d api_key" | grep scopes
```

If it does **not** exist, add it the same way as `kind` in Task 1 (column type `db.JSON`, default `list`, server_default `'[]'::json`), generate and apply a migration, then come back here. If it does exist, proceed.

- [ ] **Step 2: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_auth.py -v`
Expected: FAIL with `ImportError: cannot import name 'require_agent_key'` (the module doesn't exist yet).

- [ ] **Step 3: Implement the decorator**

Create `backend/app/agents/auth.py`:

```python
"""Authentication for agent platform endpoints.

`require_agent_key(scope=...)` validates that the request bears an API
key with `kind='agent'` and the requested scope. On any failure it
returns 401 (missing/invalid key) or 403 (key valid but scope absent).
Every successful call is audit-logged with category='agent'.
"""
from __future__ import annotations
import hashlib
from functools import wraps
from typing import Callable

from flask import request, g, jsonify

from app.extensions import db
from app.models import ApiKey


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _extract_bearer(req) -> str | None:
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return auth[len("Bearer "):].strip() or None


def require_agent_key(scope: str) -> Callable:
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            raw = _extract_bearer(request)
            if not raw:
                return jsonify({"error": "missing_bearer"}), 401

            key = ApiKey.query.filter_by(
                key_hash=_sha256(raw), kind="agent",
            ).first()
            if not key:
                return jsonify({"error": "invalid_key"}), 401

            scopes = key.scopes or []
            if scope not in scopes:
                return jsonify({"error": "scope_denied",
                                "required": scope}), 403

            g.agent_api_key = key
            g.agent_id = key.name  # convention: ApiKey.name == agent_id
            return fn(*args, **kwargs)

        return wrapper

    return decorator
```

- [ ] **Step 4: Run the test — verify it passes**

Run: `cd backend && pytest tests/test_agents_auth.py -v`
Expected: PASS for all five tests.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agents/auth.py backend/tests/test_agents_auth.py
git commit -m "feat(agents): require_agent_key decorator with scope check"
```

---

### Task 6: Implement `/api/internal/stats/weekly`

**Files:**
- Modify: `backend/app/agents/internal_routes.py`
- Create: `backend/app/agents/internal_stats.py`
- Test: `backend/tests/test_agents_internal_stats.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_internal_stats.py`:

```python
import hashlib
from datetime import datetime, timedelta
from app.extensions import db
from app.models import ApiKey, Organization, ScanJob


def _sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _make_agent_key(db_session, scopes):
    raw = "nk_agent_" + "z" * 32
    db_session.add(ApiKey(
        organization_id=1, user_id=1, name="founder-ops",
        prefix="nk_agent_", key_hash=_sha256(raw),
        kind="agent", scopes=scopes,
    ))
    db_session.commit()
    return raw


def test_weekly_stats_requires_read_stats_scope(client, db_session):
    raw = _make_agent_key(db_session, scopes=["read:findings"])
    resp = client.get("/api/internal/stats/weekly",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 403


def test_weekly_stats_returns_expected_shape(client, db_session):
    raw = _make_agent_key(db_session, scopes=["read:stats"])
    resp = client.get("/api/internal/stats/weekly",
                       headers={"Authorization": f"Bearer {raw}"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "window" in data
    assert "from" in data["window"]
    assert "to" in data["window"]
    for k in ("orgs_total", "users_total", "signups_in_window",
              "scans_in_window", "plan_mix"):
        assert k in data, f"missing key {k}"
    assert isinstance(data["plan_mix"], dict)
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_internal_stats.py -v`
Expected: FAIL with 404 (route not registered yet).

- [ ] **Step 3: Implement the stats query module**

Create `backend/app/agents/internal_stats.py`:

```python
"""Read-only aggregate stats consumed by the Founder Ops weekly summary.

This is the only place agent code touches Nano EASM customer data
*directly* via SQLAlchemy — and only because this module IS the seam.
The /api/internal/stats/weekly endpoint wraps it. Everything outside
this seam (agent runtime, skills, etc.) goes through the API.
"""
from __future__ import annotations
from datetime import datetime, timedelta

from sqlalchemy import func

from app.extensions import db
from app.models import Organization, User, ScanJob, now_utc


def weekly_stats(window_days: int = 7) -> dict:
    end = now_utc()
    start = end - timedelta(days=window_days)

    orgs_total = db.session.query(func.count(Organization.id)).scalar() or 0
    users_total = db.session.query(func.count(User.id)).scalar() or 0
    signups_in_window = (
        db.session.query(func.count(User.id))
        .filter(User.created_at >= start)
        .scalar() or 0
    )
    scans_in_window = (
        db.session.query(func.count(ScanJob.id))
        .filter(ScanJob.created_at >= start)
        .scalar() or 0
    )

    plan_rows = (
        db.session.query(Organization.plan, func.count(Organization.id))
        .group_by(Organization.plan)
        .all()
    )
    plan_mix = {plan or "unknown": cnt for plan, cnt in plan_rows}

    return {
        "window": {
            "from": start.isoformat() + "Z",
            "to": end.isoformat() + "Z",
            "days": window_days,
        },
        "orgs_total": orgs_total,
        "users_total": users_total,
        "signups_in_window": signups_in_window,
        "scans_in_window": scans_in_window,
        "plan_mix": plan_mix,
    }
```

If the column names differ in your `Organization`, `User`, or `ScanJob` models (e.g. `created_at` may be named differently), check them and adjust. The pattern stays the same.

- [ ] **Step 4: Wire the endpoint into `internal_routes.py`**

Replace the body of `backend/app/agents/internal_routes.py` with:

```python
"""Read-only API endpoints that agent code calls from inside the same
Flask app. Even though there is no network boundary, agents go through
this seam to avoid schema-coupling and to leave an audit trail.

URL prefix: /api/internal
Auth: require_agent_key (validates bearer key with kind='agent')
"""
from flask import Blueprint, jsonify, request

from .auth import require_agent_key
from .internal_stats import weekly_stats

bp = Blueprint("agents_internal", __name__, url_prefix="/api/internal")


@bp.route("/stats/weekly", methods=["GET"])
@require_agent_key(scope="read:stats")
def stats_weekly():
    days = request.args.get("days", default=7, type=int)
    return jsonify(weekly_stats(window_days=max(1, min(days, 90))))
```

- [ ] **Step 5: Run the test — verify it passes**

Run: `cd backend && pytest tests/test_agents_internal_stats.py -v`
Expected: PASS for both tests.

- [ ] **Step 6: Commit**

```bash
git add backend/app/agents/internal_routes.py backend/app/agents/internal_stats.py backend/tests/test_agents_internal_stats.py
git commit -m "feat(agents): /api/internal/stats/weekly endpoint"
```

---

### Task 7: Audit-log every agent API call

**Files:**
- Modify: `backend/app/agents/auth.py` (extend `require_agent_key` to write audit log)

- [ ] **Step 1: Find the existing audit-log helper**

Run: `grep -rn "def log_audit" backend/app/audit/`
Expected: prints the function signature (likely `def log_audit(...)` in `backend/app/audit/routes.py` per CLAUDE.md).

Read it and note the parameters. The function probably accepts `category`, `action`, `actor`, `description`, `metadata`.

- [ ] **Step 2: Write the failing test**

Append to `backend/tests/test_agents_auth.py`:

```python
def test_successful_call_writes_audit_log(app, client, db_session):
    from app.models import AuditLog

    raw = "nk_agent_" + "d" * 32
    import hashlib
    db_session.add(ApiKey(
        organization_id=1, user_id=1, name="founder-ops",
        prefix="nk_agent_",
        key_hash=hashlib.sha256(raw.encode()).hexdigest(),
        kind="agent", scopes=["read:stats"],
    ))
    db_session.commit()

    @app.route("/_test_audit")
    @require_agent_key(scope="read:stats")
    def view():
        from flask import jsonify
        return jsonify(ok=True)

    before = db_session.query(AuditLog).count()
    client.get("/_test_audit",
                headers={"Authorization": f"Bearer {raw}"})
    after = db_session.query(AuditLog).count()
    assert after == before + 1

    last = db_session.query(AuditLog).order_by(AuditLog.id.desc()).first()
    assert last.category == "agent"
```

- [ ] **Step 3: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_auth.py::test_successful_call_writes_audit_log -v`
Expected: FAIL — count unchanged.

- [ ] **Step 4: Update the decorator to write the audit log**

In `backend/app/agents/auth.py`, replace the success branch (after scope check passes) with:

```python
            g.agent_api_key = key
            g.agent_id = key.name

            # Audit-log the call. Use the existing audit helper so this
            # surfaces in /admin/audit-log alongside everything else.
            from app.audit.routes import log_audit  # local import avoids cycles
            log_audit(
                category="agent",
                action=f"{request.method} {request.path}",
                actor=f"agent:{key.name}",
                description=f"scope={scope}",
                metadata={"key_id": key.id, "scope": scope,
                          "remote_addr": request.remote_addr},
            )

            return fn(*args, **kwargs)
```

If `log_audit`'s signature differs, adjust the kwargs to match. The category MUST be `"agent"` — that's how the admin audit-log filter will surface them.

- [ ] **Step 5: Run the tests — verify all pass**

Run: `cd backend && pytest tests/test_agents_auth.py -v`
Expected: PASS for all six tests now.

- [ ] **Step 6: Commit**

```bash
git add backend/app/agents/auth.py backend/tests/test_agents_auth.py
git commit -m "feat(agents): audit-log every agent API call"
```

---

## Stage C — Founder Ops profile loader

### Task 8: Define the agent profile file format

**Files:**
- Create: `backend/app/agents/profiles/__init__.py`
- Create: `backend/app/agents/profile_loader.py`
- Test: `backend/tests/test_agents_profile_loader.py`

- [ ] **Step 1: Decide the format and document it**

Profiles are markdown files with a YAML frontmatter block delimited by `---` lines. Body of the markdown is the system prompt (for the agent's identity).

Example layout:

```markdown
---
name: founder-ops
display_name: Founder Ops
allowed_tools:
  - read_internal_api
  - web_fetch
secrets_allowed:
  - NANOEASM_API_KEY_RO
external_writes: false
hand_off_to: []
hand_off_from: []
cost_cap_monthly_usd: 50
runtime_cap_seconds: 300
tool_call_cap_per_run: 50
default_model: claude-opus-4-7
---
You are Founder Ops, the operational assistant for Nano EASM's solo founder.
... (system prompt body) ...
```

- [ ] **Step 2: Write the failing test**

Create `backend/tests/test_agents_profile_loader.py`:

```python
import textwrap
from app.agents.profile_loader import AgentProfile, load_profile


def test_load_profile_parses_frontmatter_and_body(tmp_path):
    p = tmp_path / "founder-ops" / "agent.md"
    p.parent.mkdir(parents=True)
    p.write_text(textwrap.dedent("""\
        ---
        name: founder-ops
        display_name: Founder Ops
        allowed_tools:
          - read_internal_api
        secrets_allowed:
          - NANOEASM_API_KEY_RO
        external_writes: false
        cost_cap_monthly_usd: 50
        runtime_cap_seconds: 300
        tool_call_cap_per_run: 50
        default_model: claude-opus-4-7
        ---
        You are Founder Ops, the operational assistant.
        """))

    prof = load_profile(p)
    assert isinstance(prof, AgentProfile)
    assert prof.name == "founder-ops"
    assert prof.display_name == "Founder Ops"
    assert prof.allowed_tools == ["read_internal_api"]
    assert prof.external_writes is False
    assert prof.cost_cap_monthly_usd == 50
    assert "Founder Ops" in prof.system_prompt


def test_load_profile_missing_required_raises(tmp_path):
    p = tmp_path / "broken" / "agent.md"
    p.parent.mkdir(parents=True)
    p.write_text("---\nfoo: bar\n---\nbody\n")
    import pytest
    with pytest.raises(ValueError, match="missing required field"):
        load_profile(p)


def test_load_profile_external_writes_default_false(tmp_path):
    p = tmp_path / "min" / "agent.md"
    p.parent.mkdir(parents=True)
    p.write_text(textwrap.dedent("""\
        ---
        name: min
        display_name: Min
        allowed_tools: []
        secrets_allowed: []
        cost_cap_monthly_usd: 10
        runtime_cap_seconds: 60
        tool_call_cap_per_run: 10
        default_model: claude-opus-4-7
        ---
        body
        """))
    prof = load_profile(p)
    assert prof.external_writes is False
```

- [ ] **Step 3: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_profile_loader.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 4: Implement the loader**

Create `backend/app/agents/profiles/__init__.py` (empty file).

Create `backend/app/agents/profile_loader.py`:

```python
"""Loads agent identity from a markdown file with YAML frontmatter.

Profile path convention:
    backend/app/agents/profiles/<agent-name>/agent.md

The frontmatter declares: name, display_name, allowed_tools,
secrets_allowed, external_writes, hand_off_to, hand_off_from,
cost_cap_monthly_usd, runtime_cap_seconds, tool_call_cap_per_run,
default_model. The markdown body below the frontmatter is the
system prompt.
"""
from __future__ import annotations
import dataclasses
from pathlib import Path
from typing import Any

import yaml


REQUIRED = (
    "name", "display_name", "allowed_tools", "secrets_allowed",
    "cost_cap_monthly_usd", "runtime_cap_seconds",
    "tool_call_cap_per_run", "default_model",
)


@dataclasses.dataclass(frozen=True)
class AgentProfile:
    name: str
    display_name: str
    allowed_tools: list[str]
    secrets_allowed: list[str]
    external_writes: bool
    hand_off_to: list[str]
    hand_off_from: list[str]
    cost_cap_monthly_usd: int
    runtime_cap_seconds: int
    tool_call_cap_per_run: int
    default_model: str
    system_prompt: str
    source_path: str


def load_profile(path: Path) -> AgentProfile:
    text = Path(path).read_text(encoding="utf-8")
    if not text.startswith("---"):
        raise ValueError(f"{path}: missing frontmatter")

    _, fm, body = text.split("---", 2)
    meta: dict[str, Any] = yaml.safe_load(fm) or {}

    for r in REQUIRED:
        if r not in meta:
            raise ValueError(f"{path}: missing required field '{r}'")

    return AgentProfile(
        name=meta["name"],
        display_name=meta["display_name"],
        allowed_tools=list(meta["allowed_tools"]),
        secrets_allowed=list(meta["secrets_allowed"]),
        external_writes=bool(meta.get("external_writes", False)),
        hand_off_to=list(meta.get("hand_off_to", [])),
        hand_off_from=list(meta.get("hand_off_from", [])),
        cost_cap_monthly_usd=int(meta["cost_cap_monthly_usd"]),
        runtime_cap_seconds=int(meta["runtime_cap_seconds"]),
        tool_call_cap_per_run=int(meta["tool_call_cap_per_run"]),
        default_model=str(meta["default_model"]),
        system_prompt=body.strip(),
        source_path=str(path),
    )


PROFILES_DIR = Path(__file__).parent / "profiles"


def load_profile_by_name(agent_name: str) -> AgentProfile:
    p = PROFILES_DIR / agent_name / "agent.md"
    if not p.exists():
        raise FileNotFoundError(f"no profile at {p}")
    return load_profile(p)
```

If `pyyaml` isn't already a dependency, add it: `cd backend && pip install pyyaml && pip freeze | grep -i pyyaml >> requirements.txt` (or the equivalent for your dependency manager).

- [ ] **Step 5: Run the test — verify it passes**

Run: `cd backend && pytest tests/test_agents_profile_loader.py -v`
Expected: PASS for all three tests.

- [ ] **Step 6: Commit**

```bash
git add backend/app/agents/profile_loader.py backend/app/agents/profiles/__init__.py backend/tests/test_agents_profile_loader.py
git commit -m "feat(agents): profile loader with frontmatter parsing"
```

---

### Task 9: Create the Founder Ops agent profile

**Files:**
- Create: `backend/app/agents/profiles/founder-ops/agent.md`
- Create: `backend/app/agents/profiles/founder-ops/skills/.gitkeep`

- [ ] **Step 1: Create the directory and profile**

Create `backend/app/agents/profiles/founder-ops/agent.md`:

```markdown
---
name: founder-ops
display_name: Founder Ops
allowed_tools:
  - read_internal_api
  - web_fetch
  - write_agent_task
secrets_allowed:
  - NANOEASM_API_KEY_AGENTS
external_writes: false
hand_off_to: []
hand_off_from: []
cost_cap_monthly_usd: 50
runtime_cap_seconds: 600
tool_call_cap_per_run: 50
default_model: claude-opus-4-7
---
You are Founder Ops, the operational assistant for the solo founder of Nano EASM (an External Attack Surface Management platform).

Your job is to reduce the founder's cognitive load. You produce: weekly summaries from Nano EASM stats and audit logs, launch checklists, task triage, priority matrices. You write to an internal task list (`agent_task` table) but you NEVER produce customer-facing output, NEVER touch production, NEVER make pricing or commercial decisions, NEVER deploy, NEVER grant access. Those are the founder's calls.

When you write to memory, propose a write — the founder approves before it persists. When you propose anything externally visible, you flag it; nothing of yours reaches a customer without explicit approval.

Voice: terse, factual, useful. Numbers where possible. Lead with the punch line. No filler. The founder is busy and wants signal.
```

Create `backend/app/agents/profiles/founder-ops/skills/.gitkeep` (empty placeholder file).

- [ ] **Step 2: Verify the profile loads**

Run from `backend/`:

```bash
python -c "from app.agents.profile_loader import load_profile_by_name; p = load_profile_by_name('founder-ops'); print(p.name, p.display_name, p.cost_cap_monthly_usd, len(p.system_prompt))"
```

Expected: prints `founder-ops Founder Ops 50 <some-int>` with the integer being the system-prompt length (a few hundred chars).

- [ ] **Step 3: Commit**

```bash
git add backend/app/agents/profiles/founder-ops/
git commit -m "feat(agents): Founder Ops agent profile"
```

---

### Task 10: Stub profile files for the other 5 agents

**Files:**
- Create: `backend/app/agents/profiles/{engineer,qa,security-analyst,strategy,voice}/agent.md`

- [ ] **Step 1: Create stub profiles**

For each of `engineer`, `qa`, `security-analyst`, `strategy`, `voice`, create `backend/app/agents/profiles/<name>/agent.md` with a minimal but valid profile. Below is the Engineer stub; do the same shape for the others, adjusting `name`, `display_name`, `allowed_tools`, `secrets_allowed`, `external_writes`, and the system-prompt body.

Engineer stub — `backend/app/agents/profiles/engineer/agent.md`:

```markdown
---
name: engineer
display_name: Engineer
allowed_tools:
  - read_internal_api
  - git_read
  - web_fetch
  - github_pr_create
secrets_allowed:
  - NANOEASM_API_KEY_AGENTS
  - GITHUB_TOKEN_AGENTS
external_writes: false
hand_off_to: []
hand_off_from: []
cost_cap_monthly_usd: 100
runtime_cap_seconds: 600
tool_call_cap_per_run: 80
default_model: claude-opus-4-7
---
You are Engineer (placeholder profile for Phase 1 — full prompt is written in Plan 2).

You will not be invoked by skills in this Walking Skeleton plan. The profile exists so the admin UI can list all 6 agents and the system can be tested with the full roster.
```

QA stub — `backend/app/agents/profiles/qa/agent.md`:

```markdown
---
name: qa
display_name: QA
allowed_tools:
  - read_internal_api
  - git_read
  - test_runner
secrets_allowed:
  - NANOEASM_API_KEY_AGENTS
external_writes: false
hand_off_to: []
hand_off_from: []
cost_cap_monthly_usd: 50
runtime_cap_seconds: 600
tool_call_cap_per_run: 60
default_model: claude-opus-4-7
---
You are QA (placeholder profile for Phase 1 — full prompt is written in Plan 2).
```

Security Analyst stub — `backend/app/agents/profiles/security-analyst/agent.md`:

```markdown
---
name: security-analyst
display_name: Security Analyst
allowed_tools:
  - read_internal_api
  - web_fetch
secrets_allowed:
  - NANOEASM_API_KEY_AGENTS
external_writes: false
hand_off_to: []
hand_off_from: []
cost_cap_monthly_usd: 50
runtime_cap_seconds: 600
tool_call_cap_per_run: 60
default_model: claude-opus-4-7
---
You are Security Analyst (placeholder profile for Phase 1 — full prompt is written in Plan 2).
```

Strategy stub — `backend/app/agents/profiles/strategy/agent.md`:

```markdown
---
name: strategy
display_name: Strategy
allowed_tools:
  - read_internal_api
  - web_fetch
  - web_search
secrets_allowed:
  - NANOEASM_API_KEY_AGENTS
external_writes: false
hand_off_to: []
hand_off_from: []
cost_cap_monthly_usd: 75
runtime_cap_seconds: 600
tool_call_cap_per_run: 60
default_model: claude-opus-4-7
---
You are Strategy (placeholder profile for Phase 1 — full prompt is written in Plan 2).
```

Voice stub — `backend/app/agents/profiles/voice/agent.md`:

```markdown
---
name: voice
display_name: Voice
allowed_tools:
  - read_internal_api
  - web_fetch
secrets_allowed:
  - NANOEASM_API_KEY_AGENTS
external_writes: false
hand_off_to: []
hand_off_from: []
cost_cap_monthly_usd: 50
runtime_cap_seconds: 600
tool_call_cap_per_run: 60
default_model: claude-opus-4-7
---
You are Voice (placeholder profile for Phase 1 — full prompt is written in Plan 2).

CRITICAL: Voice never sends. Drafts always queue for founder approval. The platform's send service handles delivery only after explicit approval.
```

- [ ] **Step 2: Verify all six profiles load**

Run from `backend/`:

```bash
python -c "
from app.agents.profile_loader import load_profile_by_name
for n in ['founder-ops', 'engineer', 'qa', 'security-analyst', 'strategy', 'voice']:
    p = load_profile_by_name(n)
    print(p.name, '->', p.display_name, p.cost_cap_monthly_usd)
"
```

Expected: six lines printing each name → display name → cost cap.

- [ ] **Step 3: Commit**

```bash
git add backend/app/agents/profiles/
git commit -m "feat(agents): stub profiles for the other 5 agents"
```

---

## Stage D — Memory module

### Task 11: Memory CRUD + retrieval — `agent_memory`

**Files:**
- Create: `backend/app/agents/memory.py`
- Test: `backend/tests/test_agents_memory.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_memory.py`:

```python
from datetime import datetime, timedelta
from app.agents.memory import (
    write_memory, retrieve_for_agent, retrieve_team_memory,
    write_team_memory,
)
from app.models import AgentMemory, TeamMemory, now_utc
from app.extensions import db


def test_write_and_retrieve_isolated_per_agent(db_session):
    write_memory(agent_id="founder-ops",
                  key="customer:acme:tier",
                  value={"tier": "Pro"},
                  tags=["customer:acme", "topic:plan"],
                  source="user-told")
    write_memory(agent_id="strategy",
                  key="competitor:foo:price",
                  value={"price": "$99"},
                  tags=["competitor:foo"],
                  source="api-fetched")

    # Founder Ops should see its own memory but not Strategy's
    fo = retrieve_for_agent(agent_id="founder-ops", tags=["customer:acme"])
    assert len(fo) == 1
    assert fo[0].key == "customer:acme:tier"

    fo_strategy_tag = retrieve_for_agent(agent_id="founder-ops",
                                          tags=["competitor:foo"])
    assert fo_strategy_tag == []


def test_retrieve_orders_recent_first(db_session):
    write_memory("founder-ops", "k1", {"v": 1}, ["t"], "user-told")
    write_memory("founder-ops", "k2", {"v": 2}, ["t"], "user-told")
    write_memory("founder-ops", "k3", {"v": 3}, ["t"], "user-told")
    rs = retrieve_for_agent("founder-ops", tags=["t"])
    assert [r.key for r in rs] == ["k3", "k2", "k1"]


def test_retrieve_skips_expired(db_session):
    past = now_utc() - timedelta(days=1)
    write_memory("founder-ops", "old", {"v": 1}, ["t"],
                  "user-told", expires_at=past)
    write_memory("founder-ops", "new", {"v": 2}, ["t"], "user-told")
    rs = retrieve_for_agent("founder-ops", tags=["t"])
    assert [r.key for r in rs] == ["new"]


def test_team_memory_visible_to_all(db_session):
    write_team_memory("brand:never_use_boltedge",
                       value={"rule": "Always 'Nano EASM'"},
                       tags=["brand"])
    rs = retrieve_team_memory()
    assert len(rs) == 1
    assert rs[0].key == "brand:never_use_boltedge"


def test_retrieve_caps_at_top_n(db_session):
    for i in range(50):
        write_memory("founder-ops", f"k{i:02d}", {"i": i},
                      ["bulk"], "user-told")
    rs = retrieve_for_agent("founder-ops", tags=["bulk"], top_n=10)
    assert len(rs) == 10
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_memory.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Implement the memory module**

Create `backend/app/agents/memory.py`:

```python
"""Agent memory CRUD + retrieval.

`agent_memory` is per-agent isolated. `team_memory` is universal (all
agents read; only the founder writes — agents may *propose* via the
approval queue but never auto-write).
"""
from __future__ import annotations
from datetime import datetime
from typing import Iterable

from sqlalchemy import or_, cast
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import text

from app.extensions import db
from app.models import AgentMemory, TeamMemory, now_utc


def write_memory(
    agent_id: str,
    key: str,
    value: dict,
    tags: Iterable[str],
    source: str,
    confidence: float = 1.00,
    expires_at: datetime | None = None,
) -> AgentMemory:
    """Direct write — bypasses the approval queue. Use only for the
    founder's manual seeds. Agent-proposed writes go through
    `app.agents.approvals.propose_memory_write` instead.
    """
    existing = (
        AgentMemory.query
        .filter_by(agent_id=agent_id, key=key)
        .first()
    )
    if existing:
        existing.value = value
        existing.tags = list(tags)
        existing.source = source
        existing.confidence = confidence
        existing.updated_at = now_utc()
        existing.expires_at = expires_at
        db.session.commit()
        return existing

    m = AgentMemory(
        agent_id=agent_id, key=key, value=value,
        tags=list(tags), source=source, confidence=confidence,
        expires_at=expires_at,
    )
    db.session.add(m)
    db.session.commit()
    return m


def write_team_memory(
    key: str,
    value: dict,
    tags: Iterable[str],
) -> TeamMemory:
    existing = TeamMemory.query.filter_by(key=key).first()
    if existing:
        existing.value = value
        existing.tags = list(tags)
        existing.updated_at = now_utc()
        db.session.commit()
        return existing
    m = TeamMemory(key=key, value=value, tags=list(tags))
    db.session.add(m)
    db.session.commit()
    return m


def retrieve_for_agent(
    agent_id: str,
    tags: Iterable[str] | None = None,
    top_n: int = 30,
) -> list[AgentMemory]:
    """Returns at most `top_n` of this agent's non-expired memories,
    most recent first. If `tags` is given, only memories whose tags
    intersect with the requested tags are returned.
    """
    q = AgentMemory.query.filter(AgentMemory.agent_id == agent_id)
    q = q.filter(or_(AgentMemory.expires_at.is_(None),
                      AgentMemory.expires_at > now_utc()))

    if tags:
        # JSON containment for the small expected sizes is fine without
        # a GIN index. If memory grows past ~1000 rows per agent this
        # should be revisited.
        tag_list = list(tags)
        q = q.filter(or_(*[
            cast(AgentMemory.tags, JSONB).contains(cast([t], JSONB))
            for t in tag_list
        ]))

    q = q.order_by(AgentMemory.updated_at.desc(), AgentMemory.confidence.desc())
    return q.limit(top_n).all()


def retrieve_team_memory() -> list[TeamMemory]:
    return TeamMemory.query.order_by(TeamMemory.updated_at.desc()).all()
```

- [ ] **Step 4: Run the test — verify it passes**

Run: `cd backend && pytest tests/test_agents_memory.py -v`
Expected: PASS for all five tests.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agents/memory.py backend/tests/test_agents_memory.py
git commit -m "feat(agents): memory CRUD and tag-based retrieval"
```

---

### Task 12: Seed initial `team_memory` facts

**Files:**
- Create: `backend/scripts/seed_team_memory.py`

- [ ] **Step 1: Write the seeder**

Create `backend/scripts/seed_team_memory.py`:

```python
"""One-shot seed for the universal `team_memory` namespace.

Run once after Phase-1 setup. Re-running is idempotent (upserts by key).

Usage:
    cd backend && python -m scripts.seed_team_memory
"""
from app import create_app
from app.agents.memory import write_team_memory


SEEDS = [
    ("brand:never_use_boltedge",
     {"rule": "Always say 'Nano EASM'. The product was rebranded April "
              "2026 from 'BoltEdge EASM'. No reference to 'BoltEdge' "
              "should ever appear in any output."},
     ["brand", "rule"]),
    ("brand:no_community_framing",
     {"rule": "Do NOT describe Nano EASM as 'community edition', "
              "'community preview', or 'community version'. The accepted "
              "phrasing is 'free upgrades until further notice', "
              "'currently free', or 'free to use'."},
     ["brand", "rule"]),
    ("market:global",
     {"rule": "Customer base is global (APAC, USA, Europe, Africa, "
              "Australia). Do not pitch as Australia-only or use AU "
              "sovereignty as a primary differentiator."},
     ["market", "rule"]),
    ("compliance:no_audit_ready_claims",
     {"rule": "Never claim 'audit-ready for SOC 2' or 'audit-ready for "
              "ISO 27001'. Marketing copy should say 'surfaces findings "
              "that may inform your compliance evidence — verify with "
              "your auditor'."},
     ["compliance", "rule"]),
    ("billing:disabled",
     {"rule": "Billing is currently disabled (ENABLE_BILLING=false). "
              "Plans are free upgrade tiers — no payment required. Do "
              "not surface prices, trials, or checkout in user-facing "
              "copy until billing is re-enabled."},
     ["billing", "current-state"]),
    ("approval:hard_gates",
     {"rule": "Never agent-initiated, always founder action: production "
              "deploys, DNS/cert/secrets changes, pricing/plan/commercial "
              "decisions, legal/policy/terms changes, granting access, "
              "outbound spend."},
     ["approval", "rule"]),
    ("voice:tone",
     {"rule": "Brand voice: terse, factual, useful. Lead with the punch "
              "line. Numbers where possible. No filler."},
     ["voice", "rule"]),
    ("nano_easm:url",
     {"rule": "Production URL is https://nanoeasm.com."},
     ["fact"]),
]


def main():
    app = create_app()
    with app.app_context():
        for key, value, tags in SEEDS:
            write_team_memory(key, value, tags)
            print(f"  seeded: {key}")
        print(f"\nseeded {len(SEEDS)} team_memory facts.")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run the seeder**

Run from `backend/`:

```bash
python -m scripts.seed_team_memory
```

Expected: prints 8 `seeded: ...` lines.

- [ ] **Step 3: Verify in psql**

Run:

```bash
psql -h localhost -U easm_user -d easm -c "SELECT key, jsonb_pretty(value::jsonb) FROM team_memory ORDER BY key;"
```

Expected: 8 rows printed with formatted JSON values.

- [ ] **Step 4: Commit**

```bash
git add backend/scripts/seed_team_memory.py
git commit -m "feat(agents): seed initial team_memory facts"
```

---

## Stage E — Anthropic client + cost tracking

### Task 13: Anthropic client wrapper with cost tracking

**Files:**
- Create: `backend/app/agents/anthropic_client.py`
- Test: `backend/tests/test_agents_anthropic.py`

- [ ] **Step 1: Add `anthropic` to dependencies**

Run from `backend/`:

```bash
pip install 'anthropic>=0.40' && pip freeze | grep -i '^anthropic==' >> requirements.txt
```

Verify by opening `requirements.txt` and confirming a line like `anthropic==0.40.x` is present (deduplicate if it appeared twice).

- [ ] **Step 2: Write the failing test**

Create `backend/tests/test_agents_anthropic.py`:

```python
from app.agents.anthropic_client import (
    LlmCall, FakeAnthropicClient, compute_cost_usd,
)


def test_compute_cost_opus_4_7():
    # Opus 4.7 pricing as of 2026: $15/MTok input, $75/MTok output.
    # 1,000 input + 500 output tokens.
    cost = compute_cost_usd(model="claude-opus-4-7",
                             input_tokens=1000, output_tokens=500)
    # 1000 * 15/1_000_000 + 500 * 75/1_000_000 = 0.015 + 0.0375
    assert round(cost, 4) == 0.0525


def test_compute_cost_unknown_model_returns_none():
    assert compute_cost_usd(model="random-model",
                             input_tokens=100, output_tokens=10) is None


def test_fake_client_returns_canned_response():
    fc = FakeAnthropicClient(canned_text="hello world")
    call = LlmCall(
        model="claude-opus-4-7",
        system="be helpful",
        messages=[{"role": "user", "content": "hi"}],
        max_tokens=100,
    )
    out = fc.call(call)
    assert out.text == "hello world"
    assert out.input_tokens > 0
    assert out.output_tokens > 0
    assert out.stop_reason == "end_turn"
```

- [ ] **Step 3: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_anthropic.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 4: Implement the wrapper**

Create `backend/app/agents/anthropic_client.py`:

```python
"""Anthropic API client wrapper with cost tracking and a fake for tests.

Production code uses `RealAnthropicClient`. Tests use `FakeAnthropicClient`
injected via the `client` parameter on `runtime.run_agent`. There is one
manual smoke test in Task 35 that exercises the real client end-to-end.
"""
from __future__ import annotations
import dataclasses
import os
import time
from typing import Iterable

# Prices in USD per 1M tokens. Update when Anthropic pricing changes.
PRICING = {
    "claude-opus-4-7":   {"input": 15.00, "output": 75.00},
    "claude-sonnet-4-6": {"input":  3.00, "output": 15.00},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.00},
}


@dataclasses.dataclass(frozen=True)
class LlmCall:
    model: str
    system: str
    messages: list[dict]
    max_tokens: int = 4096


@dataclasses.dataclass(frozen=True)
class LlmResult:
    text: str
    input_tokens: int
    output_tokens: int
    cost_usd: float | None
    stop_reason: str
    duration_ms: int


def compute_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float | None:
    p = PRICING.get(model)
    if not p:
        return None
    return (input_tokens * p["input"] + output_tokens * p["output"]) / 1_000_000


class RealAnthropicClient:
    def __init__(self, api_key: str | None = None):
        import anthropic  # local import — keeps test imports cheap
        self._client = anthropic.Anthropic(
            api_key=api_key or os.environ["ANTHROPIC_API_KEY_AGENTS"],
        )

    def call(self, call: LlmCall) -> LlmResult:
        start = time.monotonic()
        msg = self._client.messages.create(
            model=call.model,
            system=call.system,
            messages=call.messages,
            max_tokens=call.max_tokens,
        )
        dur = int((time.monotonic() - start) * 1000)
        text = "".join(
            block.text for block in msg.content
            if getattr(block, "type", "") == "text"
        )
        cost = compute_cost_usd(
            call.model, msg.usage.input_tokens, msg.usage.output_tokens,
        )
        return LlmResult(
            text=text,
            input_tokens=msg.usage.input_tokens,
            output_tokens=msg.usage.output_tokens,
            cost_usd=cost,
            stop_reason=msg.stop_reason or "unknown",
            duration_ms=dur,
        )


class FakeAnthropicClient:
    """Deterministic stub for tests. Echoes the canned text and reports
    realistic-looking token counts (proportional to lengths)."""

    def __init__(self, canned_text: str = "ok"):
        self._text = canned_text

    def call(self, call: LlmCall) -> LlmResult:
        # Rough token estimate: 1 token ≈ 4 chars.
        in_tok = max(1, sum(len(m.get("content", "")) for m in call.messages) // 4
                       + len(call.system) // 4)
        out_tok = max(1, len(self._text) // 4)
        cost = compute_cost_usd(call.model, in_tok, out_tok)
        return LlmResult(
            text=self._text,
            input_tokens=in_tok,
            output_tokens=out_tok,
            cost_usd=cost,
            stop_reason="end_turn",
            duration_ms=1,
        )
```

- [ ] **Step 5: Run the test — verify it passes**

Run: `cd backend && pytest tests/test_agents_anthropic.py -v`
Expected: PASS for all three tests.

- [ ] **Step 6: Commit**

```bash
git add backend/app/agents/anthropic_client.py backend/tests/test_agents_anthropic.py backend/requirements.txt
git commit -m "feat(agents): Anthropic client wrapper + cost tracking + fake for tests"
```

---

### Task 14: Monthly cost cap enforcement

**Files:**
- Create: `backend/app/agents/budget.py`
- Test: `backend/tests/test_agents_budget.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_budget.py`:

```python
from datetime import timedelta
from decimal import Decimal
from app.agents.budget import current_month_spend, check_within_cap
from app.models import AgentRun, now_utc
from app.extensions import db


def _make_run(db_session, agent_id, cost):
    db_session.add(AgentRun(
        agent_id=agent_id, skill="test",
        input={"x": 1}, status="success",
        cost_usd=Decimal(str(cost)),
        started_at=now_utc(), finished_at=now_utc(),
    ))
    db_session.commit()


def test_current_month_spend_sums_only_this_agent(db_session):
    _make_run(db_session, "founder-ops", 1.50)
    _make_run(db_session, "founder-ops", 2.50)
    _make_run(db_session, "engineer", 5.00)
    assert float(current_month_spend("founder-ops")) == 4.00


def test_current_month_spend_ignores_old_runs(db_session):
    old = AgentRun(
        agent_id="founder-ops", skill="test",
        input={}, status="success", cost_usd=Decimal("99"),
        started_at=now_utc() - timedelta(days=40),
        finished_at=now_utc() - timedelta(days=40),
    )
    db_session.add(old)
    _make_run(db_session, "founder-ops", 1.00)
    db_session.commit()
    assert float(current_month_spend("founder-ops")) == 1.00


def test_check_within_cap_passes_when_under(db_session):
    _make_run(db_session, "founder-ops", 10.00)
    # Under the $50 monthly cap → no exception
    check_within_cap("founder-ops", monthly_cap_usd=50)


def test_check_within_cap_raises_when_over(db_session):
    _make_run(db_session, "founder-ops", 60.00)
    import pytest
    with pytest.raises(RuntimeError, match="over_budget"):
        check_within_cap("founder-ops", monthly_cap_usd=50)
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_budget.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Implement the budget module**

Create `backend/app/agents/budget.py`:

```python
"""Per-agent monthly cost caps. Enforced before every Anthropic call."""
from __future__ import annotations
from datetime import datetime
from decimal import Decimal

from sqlalchemy import func

from app.extensions import db
from app.models import AgentRun, now_utc


def _month_start(t: datetime) -> datetime:
    return t.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def current_month_spend(agent_id: str) -> Decimal:
    start = _month_start(now_utc())
    total = (
        db.session.query(func.coalesce(func.sum(AgentRun.cost_usd), 0))
        .filter(AgentRun.agent_id == agent_id)
        .filter(AgentRun.started_at >= start)
        .scalar()
    )
    return Decimal(str(total))


def check_within_cap(agent_id: str, monthly_cap_usd: int) -> None:
    """Raises RuntimeError('over_budget: ...') if over the cap.
    Returns None if within. Call this before starting a new run."""
    spend = current_month_spend(agent_id)
    if spend >= monthly_cap_usd:
        raise RuntimeError(
            f"over_budget: {agent_id} has spent ${spend:.2f} this month, "
            f"monthly cap is ${monthly_cap_usd}"
        )
```

- [ ] **Step 4: Run the test — verify it passes**

Run: `cd backend && pytest tests/test_agents_budget.py -v`
Expected: PASS for all four tests.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agents/budget.py backend/tests/test_agents_budget.py
git commit -m "feat(agents): per-agent monthly cost cap enforcement"
```

---

## Stage F — Agent runtime

### Task 15: Prompt assembly — identity + memory + thread

**Files:**
- Create: `backend/app/agents/prompt_builder.py`
- Test: `backend/tests/test_agents_prompt_builder.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_prompt_builder.py`:

```python
from app.agents.prompt_builder import build_messages_and_system
from app.agents.profile_loader import load_profile_by_name
from app.agents.memory import write_memory, write_team_memory
from app.models import AgentThread, AgentMessage
from app.extensions import db


def test_build_minimal_no_memory_no_thread(db_session):
    prof = load_profile_by_name("founder-ops")
    sys, msgs = build_messages_and_system(
        profile=prof,
        user_prompt="Run weekly summary please.",
        thread=None,
        memory_tags=[],
    )
    assert "Founder Ops" in sys
    assert msgs == [{"role": "user", "content": "Run weekly summary please."}]


def test_build_includes_team_memory(db_session):
    write_team_memory("brand:test_rule", {"rule": "be terse"}, ["brand"])
    prof = load_profile_by_name("founder-ops")
    sys, _ = build_messages_and_system(
        profile=prof,
        user_prompt="hi",
        thread=None,
        memory_tags=[],
    )
    assert "TEAM MEMORY" in sys or "team memory" in sys.lower()
    assert "be terse" in sys


def test_build_includes_agent_memory_by_tag(db_session):
    write_memory("founder-ops", "fact:vol_q2",
                  {"signups_q2": 120}, ["topic:metrics"], "user-told")
    prof = load_profile_by_name("founder-ops")
    sys, _ = build_messages_and_system(
        profile=prof,
        user_prompt="weekly summary",
        thread=None,
        memory_tags=["topic:metrics"],
    )
    assert "120" in sys


def test_build_includes_thread_history(db_session):
    t = AgentThread(agent_id="founder-ops", title="t")
    t.messages.append(AgentMessage(role="user",
                                    content={"text": "first"}))
    t.messages.append(AgentMessage(role="assistant",
                                    content={"text": "reply"}))
    db_session.add(t)
    db_session.commit()

    prof = load_profile_by_name("founder-ops")
    _, msgs = build_messages_and_system(
        profile=prof,
        user_prompt="next thing",
        thread=t,
        memory_tags=[],
    )
    # Past turns + current turn
    assert len(msgs) == 3
    assert msgs[0] == {"role": "user", "content": "first"}
    assert msgs[1] == {"role": "assistant", "content": "reply"}
    assert msgs[-1] == {"role": "user", "content": "next thing"}
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_prompt_builder.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Implement the prompt builder**

Create `backend/app/agents/prompt_builder.py`:

```python
"""Builds the system prompt + message list for one agent run.

System prompt = profile.system_prompt + team_memory + relevant agent_memory.
Messages = thread history (if any) + current user prompt.
"""
from __future__ import annotations
from typing import Iterable

from .profile_loader import AgentProfile
from .memory import retrieve_for_agent, retrieve_team_memory
from app.models import AgentThread


def _format_team_memory_block() -> str:
    rows = retrieve_team_memory()
    if not rows:
        return ""
    bullets = "\n".join(
        f"- {r.key}: {r.value.get('rule', r.value)}" for r in rows
    )
    return f"\n\n## TEAM MEMORY (universal facts every agent must respect)\n{bullets}"


def _format_agent_memory_block(agent_id: str, tags: Iterable[str]) -> str:
    rows = retrieve_for_agent(agent_id, tags=tags or None, top_n=30)
    if not rows:
        return ""
    bullets = "\n".join(
        f"- {r.key}: {r.value}" for r in rows
    )
    return f"\n\n## YOUR MEMORY (relevant facts you've recorded)\n{bullets}"


def build_messages_and_system(
    profile: AgentProfile,
    user_prompt: str,
    thread: AgentThread | None,
    memory_tags: Iterable[str],
) -> tuple[str, list[dict]]:
    system = profile.system_prompt
    system += _format_team_memory_block()
    system += _format_agent_memory_block(profile.name, memory_tags)

    messages: list[dict] = []
    if thread is not None:
        for m in thread.messages:
            content = m.content.get("text", "") if isinstance(m.content, dict) else str(m.content)
            messages.append({"role": m.role, "content": content})
    messages.append({"role": "user", "content": user_prompt})

    return system, messages
```

- [ ] **Step 4: Run the test — verify it passes**

Run: `cd backend && pytest tests/test_agents_prompt_builder.py -v`
Expected: PASS for all four tests.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agents/prompt_builder.py backend/tests/test_agents_prompt_builder.py
git commit -m "feat(agents): prompt builder — identity + memory + thread"
```

---

### Task 16: Agent runtime — full run lifecycle

**Files:**
- Create: `backend/app/agents/runtime.py`
- Test: `backend/tests/test_agents_runtime.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_runtime.py`:

```python
from app.agents.runtime import run_agent
from app.agents.anthropic_client import FakeAnthropicClient
from app.models import AgentRun, AgentThread, AgentMessage
from app.extensions import db


def test_run_agent_persists_run_and_messages(db_session):
    fake = FakeAnthropicClient(canned_text="weekly summary: 5 signups")
    result = run_agent(
        agent_name="founder-ops",
        user_prompt="run the weekly summary",
        skill=None,
        memory_tags=["topic:metrics"],
        client=fake,
    )

    assert result.run.status == "success"
    assert result.run.cost_usd is not None
    assert result.thread.id is not None
    msgs = [m.role for m in result.thread.messages]
    assert msgs == ["user", "assistant"]
    last = result.thread.messages[-1]
    assert "weekly summary" in (last.content.get("text") or "")


def test_run_agent_continues_existing_thread(db_session):
    fake1 = FakeAnthropicClient(canned_text="first reply")
    r1 = run_agent("founder-ops", "first message", None, [], fake1)

    fake2 = FakeAnthropicClient(canned_text="second reply")
    r2 = run_agent("founder-ops", "second message", None, [], fake2,
                    thread_id=r1.thread.id)

    assert r2.thread.id == r1.thread.id
    roles = [m.role for m in r2.thread.messages]
    assert roles == ["user", "assistant", "user", "assistant"]


def test_run_agent_blocks_on_budget_overrun(db_session):
    from decimal import Decimal
    from app.models import AgentRun, now_utc
    db_session.add(AgentRun(
        agent_id="founder-ops", skill="prior",
        input={}, status="success", cost_usd=Decimal("75"),
        started_at=now_utc(),
    ))
    db_session.commit()

    fake = FakeAnthropicClient(canned_text="x")
    result = run_agent("founder-ops", "any prompt", None, [], fake)
    assert result.run.status == "over-budget"
    assert result.run.error and "over_budget" in result.run.error
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_runtime.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Implement the runtime**

Create `backend/app/agents/runtime.py`:

```python
"""Run-an-agent — the central runtime.

Loads the agent's profile, assembles prompt context (identity + memory +
thread), enforces the cost cap, calls the Anthropic client, persists
both the run trace and the new thread messages.
"""
from __future__ import annotations
import dataclasses
from datetime import datetime
from typing import Iterable

from app.extensions import db
from app.models import AgentRun, AgentThread, AgentMessage, now_utc

from .profile_loader import load_profile_by_name, AgentProfile
from .anthropic_client import LlmCall, RealAnthropicClient, LlmResult
from .prompt_builder import build_messages_and_system
from .budget import check_within_cap


@dataclasses.dataclass
class RunResult:
    run: AgentRun
    thread: AgentThread
    text: str | None


def _get_or_create_thread(agent_id: str, thread_id: int | None,
                            user_prompt: str) -> AgentThread:
    if thread_id is not None:
        t = AgentThread.query.get(thread_id)
        if not t:
            raise ValueError(f"thread {thread_id} not found")
        return t
    title = (user_prompt[:80] + "…") if len(user_prompt) > 80 else user_prompt
    t = AgentThread(agent_id=agent_id, title=title)
    db.session.add(t)
    db.session.flush()
    return t


def run_agent(
    agent_name: str,
    user_prompt: str,
    skill: str | None,
    memory_tags: Iterable[str],
    client=None,
    thread_id: int | None = None,
) -> RunResult:
    profile = load_profile_by_name(agent_name)
    thread = _get_or_create_thread(profile.name, thread_id, user_prompt)
    started = now_utc()

    run = AgentRun(
        agent_id=profile.name, skill=skill,
        thread_id=thread.id,
        input={"prompt": user_prompt, "memory_tags": list(memory_tags)},
        status="running",
        started_at=started,
    )
    db.session.add(run)
    db.session.flush()

    # Cost cap check — before we spend
    try:
        check_within_cap(profile.name, profile.cost_cap_monthly_usd)
    except RuntimeError as e:
        run.status = "over-budget"
        run.error = str(e)
        run.finished_at = now_utc()
        db.session.commit()
        return RunResult(run=run, thread=thread, text=None)

    # Persist the user message before calling out
    user_msg = AgentMessage(thread_id=thread.id, role="user",
                              content={"text": user_prompt})
    db.session.add(user_msg)
    db.session.flush()

    system, messages = build_messages_and_system(
        profile=profile, user_prompt=user_prompt,
        thread=thread, memory_tags=memory_tags,
    )
    # The last "user" entry is the current prompt — already handled by
    # build_messages_and_system, which appends it. Drop our just-persisted
    # user_msg from the messages list to avoid double-sending.
    # (build_messages_and_system reads thread.messages BEFORE we appended,
    # so the persisted message is *not* in the list — leaving the appended
    # one is correct. Clarifying comment so future changes don't regress.)

    try:
        c = client or RealAnthropicClient()
        result: LlmResult = c.call(LlmCall(
            model=profile.default_model,
            system=system,
            messages=messages,
            max_tokens=4096,
        ))
    except Exception as e:
        run.status = "failed"
        run.error = repr(e)[:1000]
        run.finished_at = now_utc()
        db.session.commit()
        return RunResult(run=run, thread=thread, text=None)

    assistant_msg = AgentMessage(
        thread_id=thread.id, role="assistant",
        content={"text": result.text},
        tokens_used=result.input_tokens + result.output_tokens,
    )
    db.session.add(assistant_msg)

    run.status = "success"
    run.output = {"text": result.text}
    run.cost_usd = result.cost_usd
    run.duration_ms = result.duration_ms
    run.finished_at = now_utc()
    db.session.commit()

    return RunResult(run=run, thread=thread, text=result.text)
```

- [ ] **Step 4: Run the test — verify it passes**

Run: `cd backend && pytest tests/test_agents_runtime.py -v`
Expected: PASS for all three tests.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agents/runtime.py backend/tests/test_agents_runtime.py
git commit -m "feat(agents): agent runtime — load, call Anthropic, persist run + thread"
```

---

## Stage G — Approval queue

### Task 17: Approval queue model and CRUD

**Files:**
- Create: `backend/app/agents/approvals.py`
- Test: `backend/tests/test_agents_approvals.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_approvals.py`:

```python
from datetime import timedelta
from app.agents.approvals import (
    propose_action, approve, reject, list_pending, expire_old,
)
from app.models import PendingAction, AgentMemory, now_utc
from app.extensions import db


def test_propose_action_persists(db_session):
    p = propose_action(
        agent_id="founder-ops",
        action_type="memory-write",
        target="customer:acme:tier",
        payload={"value": {"tier": "Pro"}, "tags": ["customer:acme"]},
        rationale="Heard in support thread",
        skill="weekly-summary",
    )
    assert p.id is not None
    assert p.expires_at > now_utc()
    assert p.decision is None


def test_approve_memory_write_creates_memory(db_session):
    p = propose_action(
        agent_id="founder-ops",
        action_type="memory-write",
        target="customer:acme:tier",
        payload={
            "value": {"tier": "Pro"},
            "tags": ["customer:acme"],
            "source": "user-told",
        },
        rationale="x",
    )
    approve(p.id, decided_by="founder@example.com")

    m = AgentMemory.query.filter_by(agent_id="founder-ops",
                                     key="customer:acme:tier").first()
    assert m is not None
    assert m.value == {"tier": "Pro"}

    p2 = PendingAction.query.get(p.id)
    assert p2.decision == "approved"


def test_reject_records_reason(db_session):
    p = propose_action(
        agent_id="founder-ops", action_type="memory-write",
        target="x", payload={}, rationale="y",
    )
    reject(p.id, decided_by="founder@example.com", note="not a real fact")
    p2 = PendingAction.query.get(p.id)
    assert p2.decision == "rejected"
    assert p2.decision_note == "not a real fact"


def test_list_pending_returns_only_undecided(db_session):
    propose_action("founder-ops", "memory-write", "k1", {}, "r")
    p2 = propose_action("founder-ops", "memory-write", "k2", {}, "r")
    reject(p2.id, decided_by="me")

    pending = list_pending()
    assert len(pending) == 1
    assert pending[0].target == "k1"


def test_expire_old_marks_past_due(db_session):
    p = propose_action(
        agent_id="founder-ops", action_type="memory-write",
        target="old", payload={}, rationale="r",
    )
    p.expires_at = now_utc() - timedelta(days=1)
    db_session.commit()

    expire_old()

    p2 = PendingAction.query.get(p.id)
    assert p2.decision == "expired"
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_approvals.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Implement the approvals module**

Create `backend/app/agents/approvals.py`:

```python
"""Approval queue for agent actions.

Every memory write, every externally-visible output, every code PR,
every integration write proposes a `PendingAction`. The founder
approves/rejects from the admin UI. Approval applies the underlying
write; rejection captures the reason as feedback.
"""
from __future__ import annotations
from datetime import timedelta

from app.extensions import db
from app.models import PendingAction, now_utc

from .memory import write_memory


DEFAULT_EXPIRY_DAYS = 7


def propose_action(
    agent_id: str,
    action_type: str,
    target: str | None,
    payload: dict,
    rationale: str | None = None,
    skill: str | None = None,
    run_id: int | None = None,
) -> PendingAction:
    p = PendingAction(
        agent_id=agent_id,
        skill=skill,
        action_type=action_type,
        target=target,
        payload=payload,
        rationale=rationale,
        proposed_at=now_utc(),
        expires_at=now_utc() + timedelta(days=DEFAULT_EXPIRY_DAYS),
        run_id=run_id,
    )
    db.session.add(p)
    db.session.commit()
    return p


def list_pending() -> list[PendingAction]:
    return (
        PendingAction.query
        .filter(PendingAction.decision.is_(None))
        .order_by(PendingAction.proposed_at.desc())
        .all()
    )


def approve(pending_id: int, decided_by: str,
             edited_payload: dict | None = None) -> PendingAction:
    p = PendingAction.query.get_or_404(pending_id)
    if p.decision is not None:
        raise ValueError(f"action {pending_id} already decided: {p.decision}")

    payload = edited_payload if edited_payload is not None else p.payload
    _apply_action(p.action_type, p.agent_id, p.target or "", payload)

    p.decision = "edited-and-approved" if edited_payload is not None else "approved"
    p.decided_at = now_utc()
    p.decided_by = decided_by
    db.session.commit()
    return p


def reject(pending_id: int, decided_by: str,
            note: str | None = None) -> PendingAction:
    p = PendingAction.query.get_or_404(pending_id)
    if p.decision is not None:
        raise ValueError(f"action {pending_id} already decided: {p.decision}")
    p.decision = "rejected"
    p.decided_at = now_utc()
    p.decided_by = decided_by
    p.decision_note = note
    db.session.commit()
    return p


def expire_old() -> int:
    """Marks any pending action past its `expires_at` as decision='expired'.
    Returns the number expired. Called from the daily digest job."""
    now = now_utc()
    rows = (
        PendingAction.query
        .filter(PendingAction.decision.is_(None))
        .filter(PendingAction.expires_at < now)
        .all()
    )
    for r in rows:
        r.decision = "expired"
        r.decided_at = now
    db.session.commit()
    return len(rows)


def _apply_action(action_type: str, agent_id: str,
                   target: str, payload: dict) -> None:
    if action_type == "memory-write":
        write_memory(
            agent_id=agent_id,
            key=target,
            value=payload.get("value", {}),
            tags=payload.get("tags", []),
            source=payload.get("source", "user-told"),
            confidence=payload.get("confidence", 1.00),
            expires_at=payload.get("expires_at"),
        )
    elif action_type in ("external-output", "code-pr", "integration-write",
                          "nano-easm-write", "team-memory-write"):
        # Phase 1 walking skeleton: only memory-write is fully wired.
        # Other action types are accepted (queued) but their applier is
        # implemented in Plan 2. For now, raise so an attempted approve
        # of these types fails loudly until wired.
        raise NotImplementedError(
            f"action_type {action_type!r} applier wired in Plan 2"
        )
    else:
        raise ValueError(f"unknown action_type: {action_type!r}")
```

- [ ] **Step 4: Run the test — verify it passes**

Run: `cd backend && pytest tests/test_agents_approvals.py -v`
Expected: PASS for all five tests.

- [ ] **Step 5: Commit**

```bash
git add backend/app/agents/approvals.py backend/tests/test_agents_approvals.py
git commit -m "feat(agents): approval queue with memory-write applier"
```

---

## Stage H — Send service

### Task 18: Resend wrapper for digest emails

**Files:**
- Create: `backend/app/agents/send_service.py`
- Test: `backend/tests/test_agents_send.py`

- [ ] **Step 1: Find the existing Resend integration**

Run: `grep -rn "resend" backend/app/ --include="*.py" -l | head -5`
Expected: lists the existing modules that use Resend (likely `app/auth/emails.py` and `app/billing/emails.py`).

Open one and note the import + send pattern. Match it.

- [ ] **Step 2: Write the failing test**

Create `backend/tests/test_agents_send.py`:

```python
from app.agents.send_service import send_digest_email, FakeResendClient


def test_send_digest_uses_correct_from_address():
    fake = FakeResendClient()
    send_digest_email(
        to="founder@example.com",
        subject="Weekly Summary",
        markdown="# Hi\n\nNumbers go here.",
        client=fake,
    )
    assert len(fake.sent) == 1
    msg = fake.sent[0]
    assert msg["to"] == "founder@example.com"
    assert msg["subject"] == "Weekly Summary"
    assert "from" in msg
    assert "<h1>Hi</h1>" in msg["html"]
```

- [ ] **Step 3: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_send.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 4: Implement the send service**

Create `backend/app/agents/send_service.py`:

```python
"""Outbound email for the agent platform.

Two flows:
  1. send_digest_email — internal-only digests to the founder (auto-send,
     no approval gate; recipient is hard-coded to the configured founder
     email so a misconfigured agent cannot exfiltrate to anyone else).
  2. send_approved_draft — sends a draft post-approval to a customer-
     facing recipient. Implemented in Plan 2.

Sender domain is the agent platform's, separate from customer-facing
billing/auth emails. Token: RESEND_TOKEN_AGENTS env var.
"""
from __future__ import annotations
import os
import dataclasses
import markdown as md


def _markdown_to_html(text: str) -> str:
    return md.markdown(text, extensions=["fenced_code", "tables"])


@dataclasses.dataclass
class SentMessage:
    to: str
    subject: str
    html: str
    from_: str

    def __getitem__(self, k):
        return self.from_ if k == "from" else getattr(self, k)


class FakeResendClient:
    """Test stub — captures sent messages instead of dispatching."""
    def __init__(self):
        self.sent: list[dict] = []

    def send(self, *, to, subject, html, from_):
        self.sent.append({
            "to": to, "subject": subject, "html": html, "from": from_,
        })


class RealResendClient:
    def __init__(self, api_key: str | None = None):
        import resend
        resend.api_key = api_key or os.environ["RESEND_TOKEN_AGENTS"]
        self._resend = resend

    def send(self, *, to, subject, html, from_):
        self._resend.Emails.send({
            "from": from_,
            "to": [to] if isinstance(to, str) else to,
            "subject": subject,
            "html": html,
        })


FROM_AGENTS = os.environ.get("AGENTS_FROM_EMAIL",
                              "agents@nanoeasm.com")


def send_digest_email(to: str, subject: str, markdown: str,
                       client=None) -> None:
    html = _markdown_to_html(markdown)
    c = client or RealResendClient()
    c.send(to=to, subject=subject, html=html, from_=FROM_AGENTS)
```

If `markdown` isn't installed: `cd backend && pip install markdown && pip freeze | grep -i '^markdown==' >> requirements.txt`.

- [ ] **Step 5: Run the test — verify it passes**

Run: `cd backend && pytest tests/test_agents_send.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/app/agents/send_service.py backend/tests/test_agents_send.py backend/requirements.txt
git commit -m "feat(agents): Resend-backed send service for digests"
```

---

## Stage I — `weekly-summary` skill + Monday brief

### Task 19: Implement the `weekly-summary` skill

**Files:**
- Create: `backend/app/agents/profiles/founder-ops/skills/weekly-summary.md`
- Create: `backend/app/agents/skills/weekly_summary.py`
- Test: `backend/tests/test_agents_weekly_summary.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_agents_weekly_summary.py`:

```python
from app.agents.skills.weekly_summary import run_weekly_summary
from app.agents.anthropic_client import FakeAnthropicClient


def test_run_weekly_summary_persists_run_and_returns_text(db_session,
                                                          monkeypatch):
    # Stub the internal-API caller so the test doesn't depend on
    # /api/internal/stats/weekly being callable from in-process.
    fake_stats = {
        "window": {"from": "2026-05-04T00:00:00Z",
                    "to": "2026-05-11T00:00:00Z", "days": 7},
        "orgs_total": 42, "users_total": 75,
        "signups_in_window": 5, "scans_in_window": 130,
        "plan_mix": {"Free": 30, "Starter": 8, "Pro": 4},
    }
    monkeypatch.setattr(
        "app.agents.skills.weekly_summary._fetch_weekly_stats",
        lambda: fake_stats,
    )

    fake_llm = FakeAnthropicClient(
        canned_text="**This week:** 5 signups, 130 scans. Plan mix: 30/8/4.",
    )
    result = run_weekly_summary(client=fake_llm)
    assert result.text and "5 signups" in result.text
    assert result.run.skill == "weekly-summary"
    assert result.run.status == "success"
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cd backend && pytest tests/test_agents_weekly_summary.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Create the skill markdown**

Create `backend/app/agents/profiles/founder-ops/skills/weekly-summary.md`:

```markdown
# Skill: weekly-summary

**Owner agent:** founder-ops
**Trigger:** scheduled (Monday 08:00 founder timezone) or manual
**Output:** markdown email digest sent to the founder

## Inputs
- 7-day stats from `GET /api/internal/stats/weekly`

## Steps
1. Fetch weekly stats from the internal API.
2. Summarise in markdown: lead with signups + scans + plan mix.
3. Highlight changes vs. last week if memory has prior numbers.
4. Send the digest email to the founder via the platform send service.

## Voice
Terse. Lead with the punch line. Numbers prominent. No filler.
```

- [ ] **Step 4: Implement the skill module**

Create `backend/app/agents/skills/__init__.py` (empty).

Create `backend/app/agents/skills/weekly_summary.py`:

```python
"""Founder Ops :: weekly-summary skill.

Calls the internal stats API, asks the LLM to summarise in brand voice,
emails the digest to the founder. Writes a memory entry capturing this
week's headline numbers (proposed via approval queue).
"""
from __future__ import annotations
import os

import requests

from app.agents.runtime import run_agent, RunResult
from app.agents.send_service import send_digest_email
from app.agents.approvals import propose_action


SKILL_NAME = "weekly-summary"
SKILL_PROMPT_TEMPLATE = """\
Produce a weekly summary for the founder of Nano EASM in markdown.

Stats for the past 7 days:

{stats_block}

Format:
1. One-sentence punchline (the headline number).
2. Bulleted facts (signups, scans, plan mix).
3. One observation worth flagging (delta vs. last week if obvious).

Voice: terse, factual. No filler. The founder wants signal."""


def _fetch_weekly_stats() -> dict:
    """Calls /api/internal/stats/weekly. The agent platform is co-hosted,
    but goes through HTTP to preserve the seam."""
    base = os.environ.get("INTERNAL_API_BASE", "http://localhost:5000")
    key = os.environ["NANOEASM_API_KEY_AGENTS_FOUNDER_OPS"]
    resp = requests.get(
        f"{base}/api/internal/stats/weekly",
        headers={"Authorization": f"Bearer {key}"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def _format_stats_block(s: dict) -> str:
    return (
        f"- Window: {s['window']['from']} → {s['window']['to']} "
        f"({s['window']['days']}d)\n"
        f"- Orgs total: {s['orgs_total']}\n"
        f"- Users total: {s['users_total']}\n"
        f"- Signups in window: {s['signups_in_window']}\n"
        f"- Scans in window: {s['scans_in_window']}\n"
        f"- Plan mix: {s['plan_mix']}"
    )


def run_weekly_summary(client=None, send: bool = False) -> RunResult:
    stats = _fetch_weekly_stats()
    user_prompt = SKILL_PROMPT_TEMPLATE.format(
        stats_block=_format_stats_block(stats),
    )

    result = run_agent(
        agent_name="founder-ops",
        user_prompt=user_prompt,
        skill=SKILL_NAME,
        memory_tags=["topic:metrics", "skill:weekly-summary"],
        client=client,
    )

    if send and result.text:
        founder_email = os.environ.get("FOUNDER_EMAIL")
        if founder_email:
            send_digest_email(
                to=founder_email,
                subject=(
                    f"Weekly Summary — "
                    f"{stats['signups_in_window']} signups, "
                    f"{stats['scans_in_window']} scans"
                ),
                markdown=result.text,
            )

    if result.text and result.run.status == "success":
        propose_action(
            agent_id="founder-ops",
            action_type="memory-write",
            target=f"weekly:{stats['window']['to'][:10]}",
            payload={
                "value": {
                    "signups": stats["signups_in_window"],
                    "scans": stats["scans_in_window"],
                    "summary_excerpt": result.text[:500],
                },
                "tags": ["skill:weekly-summary", "topic:metrics"],
                "source": "skill-output",
            },
            rationale="weekly-summary headline numbers",
            skill=SKILL_NAME,
            run_id=result.run.id,
        )

    return result
```

- [ ] **Step 5: Run the test — verify it passes**

Run: `cd backend && pytest tests/test_agents_weekly_summary.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/app/agents/skills/ backend/app/agents/profiles/founder-ops/skills/weekly-summary.md backend/tests/test_agents_weekly_summary.py
git commit -m "feat(agents): weekly-summary skill (Founder Ops)"
```

---

### Task 20: Generate the Founder Ops API key

**Files:**
- Create: `backend/scripts/issue_agent_key.py`

- [ ] **Step 1: Write the issuing script**

Create `backend/scripts/issue_agent_key.py`:

```python
"""Issue (or rotate) an API key for one agent.

Usage:
    cd backend && python -m scripts.issue_agent_key founder-ops read:stats read:findings

Prints the raw key to stdout ONCE. Save it immediately — it will not be
shown again. The DB stores only the SHA-256 hash.
"""
from __future__ import annotations
import hashlib
import secrets
import sys

from app import create_app
from app.extensions import db
from app.models import ApiKey, Organization


def main():
    if len(sys.argv) < 3:
        print("usage: python -m scripts.issue_agent_key <agent-name> <scope> [<scope> ...]")
        sys.exit(1)

    agent = sys.argv[1]
    scopes = list(sys.argv[2:])

    app = create_app()
    with app.app_context():
        # Use the founder/superadmin's org as the holder. Adjust if your
        # schema requires a specific organization_id.
        org = Organization.query.first()
        if not org:
            print("no Organization rows; create one first")
            sys.exit(1)

        # Revoke any existing agent keys for this agent (idempotent rotate)
        existing = ApiKey.query.filter_by(name=agent, kind="agent").all()
        for k in existing:
            db.session.delete(k)
        db.session.flush()

        # Generate
        raw = "nk_agent_" + secrets.token_urlsafe(32)
        rec = ApiKey(
            organization_id=org.id,
            user_id=None,  # agent keys are not tied to a user
            name=agent,
            prefix=raw[:11],
            key_hash=hashlib.sha256(raw.encode()).hexdigest(),
            kind="agent",
            scopes=scopes,
        )
        db.session.add(rec)
        db.session.commit()

        print(f"\n  Agent: {agent}")
        print(f"  Scopes: {scopes}")
        print(f"  KEY (save now — shown only once):\n\n    {raw}\n")


if __name__ == "__main__":
    main()
```

If your `ApiKey` model requires `user_id NOT NULL`, change `user_id=None` to the founder user's id (you can hard-code it or look it up by email). Either way, document the choice in a comment.

- [ ] **Step 2: Issue the key**

Run from `backend/`:

```bash
python -m scripts.issue_agent_key founder-ops read:stats
```

Expected: prints a `nk_agent_...` key. Save it into `.env`:

```bash
echo "NANOEASM_API_KEY_AGENTS_FOUNDER_OPS=<paste-key-here>" >> backend/.env
```

(Or whichever env-management approach the project uses.)

- [ ] **Step 3: Smoke-test the key against the live endpoint**

In one terminal: `cd backend && python run.py`. In another:

```bash
curl -H "Authorization: Bearer <paste-key-here>" \
     http://localhost:5000/api/internal/stats/weekly
```

Expected: returns 200 with the weekly stats JSON.

- [ ] **Step 4: Commit**

```bash
git add backend/scripts/issue_agent_key.py
git commit -m "feat(agents): script to issue per-agent API keys"
```

(The actual key in `.env` is gitignored — do not commit it.)

---

### Task 21: APScheduler job for the Monday brief

**Files:**
- Modify: `backend/app/scheduler.py` (the existing scheduler module — add the new job)

- [ ] **Step 1: Find the existing scheduler file**

Run: `head -40 backend/app/scheduler.py`
Expected: an APScheduler initialisation block. Note the function used to register jobs (likely `scheduler.add_job(...)`).

- [ ] **Step 2: Add the Monday job**

In `backend/app/scheduler.py`, near the other registered jobs, add:

```python
def _run_monday_weekly_summary():
    """Phase-1 scheduled job: Founder Ops weekly summary, Monday 08:00."""
    from app.agents.skills.weekly_summary import run_weekly_summary
    try:
        run_weekly_summary(send=True)
    except Exception as e:
        # Never propagate — APScheduler should keep running. The failure
        # is captured in agent_run.status='failed' by run_agent itself.
        import logging
        logging.getLogger("agents").exception("weekly_summary failed: %s", e)


# At wherever jobs are registered (look for pattern matching existing jobs):
scheduler.add_job(
    _run_monday_weekly_summary,
    trigger="cron",
    day_of_week="mon",
    hour=8, minute=0,
    id="agents.founder_ops.weekly_summary",
    replace_existing=True,
)
```

The exact registration site may differ — match the pattern of the existing job registrations.

- [ ] **Step 3: Verify the job is registered**

Run from `backend/`:

```bash
python -c "
from app import create_app
from app.scheduler import scheduler
app = create_app()
with app.app_context():
    print([j.id for j in scheduler.get_jobs()])
"
```

Expected: list includes `agents.founder_ops.weekly_summary`.

- [ ] **Step 4: Commit**

```bash
git add backend/app/scheduler.py
git commit -m "feat(agents): schedule Monday Founder Ops weekly summary"
```

---

## Stage J — Admin UI

### Task 22: Admin backend — list, detail, run, approvals

**Files:**
- Modify: `backend/app/agents/routes.py`

- [ ] **Step 1: Implement the four endpoints**

Replace the body of `backend/app/agents/routes.py` with:

```python
"""Admin UI backend for the agent platform.

URL prefix: /admin/agents
Auth: existing require_superadmin decorator (404s for non-superadmins).
"""
from __future__ import annotations
from flask import Blueprint, jsonify, request

from app.auth.permissions import require_superadmin
from app.extensions import db
from app.models import AgentRun, AgentThread, AgentMessage, PendingAction

from .profile_loader import PROFILES_DIR, load_profile
from .runtime import run_agent
from .approvals import list_pending, approve, reject, expire_old


bp = Blueprint("agents_admin", __name__, url_prefix="/admin/agents")


def _list_profiles():
    out = []
    for child in PROFILES_DIR.iterdir():
        if not child.is_dir():
            continue
        f = child / "agent.md"
        if not f.exists():
            continue
        try:
            p = load_profile(f)
        except Exception:
            continue
        out.append({
            "name": p.name,
            "display_name": p.display_name,
            "external_writes": p.external_writes,
            "cost_cap_monthly_usd": p.cost_cap_monthly_usd,
            "default_model": p.default_model,
        })
    return sorted(out, key=lambda r: r["name"])


@bp.route("", methods=["GET"])
@require_superadmin
def list_agents():
    return jsonify({"agents": _list_profiles()})


@bp.route("/<agent_name>", methods=["GET"])
@require_superadmin
def agent_detail(agent_name: str):
    f = PROFILES_DIR / agent_name / "agent.md"
    if not f.exists():
        return jsonify({"error": "not_found"}), 404
    p = load_profile(f)

    runs = (
        AgentRun.query.filter_by(agent_id=agent_name)
        .order_by(AgentRun.started_at.desc())
        .limit(20).all()
    )
    threads = (
        AgentThread.query.filter_by(agent_id=agent_name)
        .order_by(AgentThread.created_at.desc())
        .limit(20).all()
    )

    return jsonify({
        "name": p.name,
        "display_name": p.display_name,
        "system_prompt": p.system_prompt,
        "allowed_tools": p.allowed_tools,
        "external_writes": p.external_writes,
        "cost_cap_monthly_usd": p.cost_cap_monthly_usd,
        "default_model": p.default_model,
        "runs": [
            {"id": r.id, "skill": r.skill, "status": r.status,
             "cost_usd": float(r.cost_usd) if r.cost_usd else None,
             "started_at": r.started_at.isoformat() + "Z",
             "duration_ms": r.duration_ms}
            for r in runs
        ],
        "threads": [
            {"id": t.id, "title": t.title,
             "created_at": t.created_at.isoformat() + "Z",
             "message_count": len(t.messages)}
            for t in threads
        ],
    })


@bp.route("/<agent_name>/run", methods=["POST"])
@require_superadmin
def trigger_run(agent_name: str):
    body = request.get_json(force=True) or {}
    prompt = body.get("prompt")
    skill = body.get("skill")
    memory_tags = body.get("memory_tags", [])
    thread_id = body.get("thread_id")
    if not prompt:
        return jsonify({"error": "prompt is required"}), 400

    result = run_agent(
        agent_name=agent_name,
        user_prompt=prompt,
        skill=skill,
        memory_tags=memory_tags,
        thread_id=thread_id,
    )
    return jsonify({
        "run_id": result.run.id,
        "thread_id": result.thread.id,
        "status": result.run.status,
        "text": result.text,
        "cost_usd": float(result.run.cost_usd) if result.run.cost_usd else None,
    })


@bp.route("/approvals", methods=["GET"])
@require_superadmin
def approvals_list():
    return jsonify({
        "pending": [
            {"id": p.id, "agent_id": p.agent_id, "action_type": p.action_type,
             "target": p.target, "payload": p.payload,
             "rationale": p.rationale, "skill": p.skill,
             "proposed_at": p.proposed_at.isoformat() + "Z",
             "expires_at": p.expires_at.isoformat() + "Z"}
            for p in list_pending()
        ]
    })


@bp.route("/approvals/<int:pending_id>/approve", methods=["POST"])
@require_superadmin
def approvals_approve(pending_id: int):
    body = request.get_json(silent=True) or {}
    edited = body.get("edited_payload")
    decided_by = body.get("decided_by", "founder")
    p = approve(pending_id, decided_by=decided_by, edited_payload=edited)
    return jsonify({"id": p.id, "decision": p.decision})


@bp.route("/approvals/<int:pending_id>/reject", methods=["POST"])
@require_superadmin
def approvals_reject(pending_id: int):
    body = request.get_json(silent=True) or {}
    note = body.get("note")
    decided_by = body.get("decided_by", "founder")
    p = reject(pending_id, decided_by=decided_by, note=note)
    return jsonify({"id": p.id, "decision": p.decision})
```

- [ ] **Step 2: Smoke test the admin endpoints**

Start the backend (`cd backend && python run.py`). Confirm `/admin/agents` returns 404 to a non-superadmin and 200 to a superadmin (use an existing superadmin's session cookie). Confirm `/admin/agents/founder-ops` returns the profile JSON.

- [ ] **Step 3: Commit**

```bash
git add backend/app/agents/routes.py
git commit -m "feat(agents): admin endpoints — list, detail, run, approvals"
```

---

### Task 23: Frontend — agent list page

**Files:**
- Create: `frontend/app/(authenticated)/admin/agents/page.tsx`
- Modify: `frontend/app/lib/api.ts` (add API client functions)

- [ ] **Step 1: Add the API client functions**

In `frontend/app/lib/api.ts`, add (alongside other API functions):

```typescript
export type AgentSummary = {
  name: string;
  display_name: string;
  external_writes: boolean;
  cost_cap_monthly_usd: number;
  default_model: string;
};

export async function getAgents(): Promise<AgentSummary[]> {
  const res = await apiFetch("/admin/agents");
  if (!res.ok) throw new Error(`getAgents: ${res.status}`);
  const j = await res.json();
  return j.agents;
}

export type AgentRunSummary = {
  id: number; skill: string | null; status: string;
  cost_usd: number | null; started_at: string; duration_ms: number | null;
};
export type AgentThreadSummary = {
  id: number; title: string | null; created_at: string; message_count: number;
};
export type AgentDetail = {
  name: string; display_name: string; system_prompt: string;
  allowed_tools: string[]; external_writes: boolean;
  cost_cap_monthly_usd: number; default_model: string;
  runs: AgentRunSummary[]; threads: AgentThreadSummary[];
};

export async function getAgent(name: string): Promise<AgentDetail> {
  const res = await apiFetch(`/admin/agents/${encodeURIComponent(name)}`);
  if (!res.ok) throw new Error(`getAgent: ${res.status}`);
  return res.json();
}

export async function runAgent(name: string, prompt: string,
                                opts: { skill?: string; memory_tags?: string[];
                                        thread_id?: number } = {}) {
  const res = await apiFetch(`/admin/agents/${encodeURIComponent(name)}/run`,
    { method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt, ...opts }) });
  if (!res.ok) throw new Error(`runAgent: ${res.status}`);
  return res.json();
}

export type PendingActionRow = {
  id: number; agent_id: string; action_type: string;
  target: string | null; payload: any; rationale: string | null;
  skill: string | null; proposed_at: string; expires_at: string;
};

export async function getPendingApprovals(): Promise<PendingActionRow[]> {
  const res = await apiFetch("/admin/agents/approvals");
  if (!res.ok) throw new Error(`getPendingApprovals: ${res.status}`);
  return (await res.json()).pending;
}

export async function approveAction(id: number, edited_payload?: any) {
  const res = await apiFetch(`/admin/agents/approvals/${id}/approve`,
    { method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ edited_payload }) });
  if (!res.ok) throw new Error(`approveAction: ${res.status}`);
  return res.json();
}

export async function rejectAction(id: number, note?: string) {
  const res = await apiFetch(`/admin/agents/approvals/${id}/reject`,
    { method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ note }) });
  if (!res.ok) throw new Error(`rejectAction: ${res.status}`);
  return res.json();
}
```

If `apiFetch` is named differently (e.g. `api`), match the existing convention.

- [ ] **Step 2: Create the agent list page**

Create `frontend/app/(authenticated)/admin/agents/page.tsx`:

```tsx
"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { AgentSummary, getAgents, getPendingApprovals } from "@/app/lib/api";

export default function AgentListPage() {
  const [agents, setAgents] = useState<AgentSummary[] | null>(null);
  const [pendingCount, setPendingCount] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const [a, p] = await Promise.all([getAgents(), getPendingApprovals()]);
        setAgents(a);
        setPendingCount(p.length);
      } catch (e: any) { setError(String(e)); }
    })();
  }, []);

  if (error) return <div className="p-6 text-red-400">Error: {error}</div>;
  if (!agents) return <div className="p-6 text-zinc-400">Loading…</div>;

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-semibold text-zinc-100">Agents</h1>
        <Link
          href="/admin/agents/approvals"
          className="px-3 py-2 rounded bg-teal-600 hover:bg-teal-500 text-white text-sm"
        >
          Approvals {pendingCount !== null ? `(${pendingCount})` : ""}
        </Link>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {agents.map(a => (
          <Link
            key={a.name}
            href={`/admin/agents/${a.name}`}
            className="block rounded-lg border border-zinc-800 bg-zinc-900/50
                       hover:bg-zinc-900 p-4 transition"
          >
            <div className="flex items-baseline justify-between">
              <h2 className="text-lg font-medium text-zinc-100">
                {a.display_name}
              </h2>
              <code className="text-xs text-zinc-500">{a.name}</code>
            </div>
            <dl className="mt-3 text-sm text-zinc-400 space-y-1">
              <div className="flex justify-between">
                <dt>Model</dt><dd className="text-zinc-200">{a.default_model}</dd>
              </div>
              <div className="flex justify-between">
                <dt>Cost cap / month</dt>
                <dd className="text-zinc-200">${a.cost_cap_monthly_usd}</dd>
              </div>
              <div className="flex justify-between">
                <dt>External writes</dt>
                <dd className="text-zinc-200">
                  {a.external_writes ? "yes" : "no"}
                </dd>
              </div>
            </dl>
          </Link>
        ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Smoke-test in the browser**

Start the frontend (`cd frontend && npm run dev`). Log in as a superadmin. Navigate to `http://localhost:3000/admin/agents`. Expected: six agent cards rendered. Approvals button shows `(0)` initially.

- [ ] **Step 4: Commit**

```bash
git add frontend/app/lib/api.ts frontend/app/\(authenticated\)/admin/agents/page.tsx
git commit -m "feat(agents): admin agent list page"
```

---

### Task 24: Frontend — agent detail page with run button

**Files:**
- Create: `frontend/app/(authenticated)/admin/agents/[name]/page.tsx`

- [ ] **Step 1: Create the page**

Create `frontend/app/(authenticated)/admin/agents/[name]/page.tsx`:

```tsx
"use client";
import { use, useEffect, useState } from "react";
import { AgentDetail, getAgent, runAgent } from "@/app/lib/api";

export default function AgentDetailPage(
  { params }: { params: Promise<{ name: string }> },
) {
  const { name } = use(params);
  const [agent, setAgent] = useState<AgentDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [prompt, setPrompt] = useState("");
  const [running, setRunning] = useState(false);
  const [lastResult, setLastResult] = useState<any>(null);

  async function reload() {
    try { setAgent(await getAgent(name)); }
    catch (e: any) { setError(String(e)); }
  }
  useEffect(() => { reload(); /* eslint-disable-next-line */ }, [name]);

  async function onRun() {
    if (!prompt.trim()) return;
    setRunning(true);
    setLastResult(null);
    try {
      const r = await runAgent(name, prompt);
      setLastResult(r);
      setPrompt("");
      await reload();
    } catch (e: any) { setLastResult({ error: String(e) }); }
    finally { setRunning(false); }
  }

  if (error) return <div className="p-6 text-red-400">{error}</div>;
  if (!agent) return <div className="p-6 text-zinc-400">Loading…</div>;

  return (
    <div className="p-6 max-w-4xl">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-zinc-100">
          {agent.display_name}
        </h1>
        <code className="text-sm text-zinc-500">{agent.name}</code>
      </div>

      <section className="mb-6">
        <h2 className="text-sm uppercase text-zinc-500 mb-2">System prompt</h2>
        <pre className="whitespace-pre-wrap rounded bg-zinc-900/50 border
                         border-zinc-800 p-4 text-sm text-zinc-300">
          {agent.system_prompt}
        </pre>
      </section>

      <section className="mb-6">
        <h2 className="text-sm uppercase text-zinc-500 mb-2">Run now</h2>
        <textarea
          className="w-full rounded bg-zinc-900 border border-zinc-800
                      p-3 text-sm text-zinc-100 font-mono"
          rows={4}
          placeholder={`Prompt for ${agent.display_name}…`}
          value={prompt}
          onChange={e => setPrompt(e.target.value)}
        />
        <button
          onClick={onRun}
          disabled={running || !prompt.trim()}
          className="mt-2 px-4 py-2 rounded bg-teal-600 hover:bg-teal-500
                     disabled:bg-zinc-700 text-white text-sm"
        >
          {running ? "Running…" : "Run"}
        </button>
        {lastResult && (
          <pre className="mt-3 whitespace-pre-wrap rounded bg-zinc-900/50
                           border border-zinc-800 p-3 text-sm text-zinc-200">
            {JSON.stringify(lastResult, null, 2)}
          </pre>
        )}
      </section>

      <section>
        <h2 className="text-sm uppercase text-zinc-500 mb-2">Recent runs</h2>
        {agent.runs.length === 0 ? (
          <p className="text-zinc-500 text-sm">No runs yet.</p>
        ) : (
          <table className="w-full text-sm border-collapse">
            <thead className="text-zinc-500 text-left">
              <tr>
                <th className="py-2">When</th>
                <th>Skill</th>
                <th>Status</th>
                <th>Cost</th>
                <th>Duration</th>
              </tr>
            </thead>
            <tbody className="text-zinc-300">
              {agent.runs.map(r => (
                <tr key={r.id} className="border-t border-zinc-800">
                  <td className="py-2">
                    {new Date(r.started_at).toLocaleString()}
                  </td>
                  <td>{r.skill || "—"}</td>
                  <td>{r.status}</td>
                  <td>{r.cost_usd ? `$${r.cost_usd.toFixed(4)}` : "—"}</td>
                  <td>{r.duration_ms ? `${r.duration_ms}ms` : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
```

- [ ] **Step 2: Smoke-test**

Navigate to `/admin/agents/founder-ops`. Type a prompt ("Run the weekly summary"). Click Run. Wait for the response. Expected: response text appears, recent runs list updates with a new row.

- [ ] **Step 3: Commit**

```bash
git add frontend/app/\(authenticated\)/admin/agents/\[name\]/page.tsx
git commit -m "feat(agents): admin agent detail page with run-now"
```

---

### Task 25: Frontend — approvals queue page

**Files:**
- Create: `frontend/app/(authenticated)/admin/agents/approvals/page.tsx`

- [ ] **Step 1: Create the approvals page**

Create `frontend/app/(authenticated)/admin/agents/approvals/page.tsx`:

```tsx
"use client";
import { useEffect, useState } from "react";
import {
  PendingActionRow, getPendingApprovals,
  approveAction, rejectAction,
} from "@/app/lib/api";

export default function ApprovalsPage() {
  const [items, setItems] = useState<PendingActionRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);

  async function reload() {
    try { setItems(await getPendingApprovals()); }
    catch (e: any) { setError(String(e)); }
  }
  useEffect(() => { reload(); }, []);

  async function onApprove(id: number) {
    setBusy(id);
    try { await approveAction(id); await reload(); }
    catch (e: any) { alert(String(e)); }
    finally { setBusy(null); }
  }
  async function onReject(id: number) {
    const note = prompt("Reason for rejection (visible to the agent):");
    if (note === null) return;
    setBusy(id);
    try { await rejectAction(id, note); await reload(); }
    catch (e: any) { alert(String(e)); }
    finally { setBusy(null); }
  }

  if (error) return <div className="p-6 text-red-400">{error}</div>;
  if (!items) return <div className="p-6 text-zinc-400">Loading…</div>;

  return (
    <div className="p-6 max-w-4xl">
      <h1 className="text-2xl font-semibold text-zinc-100 mb-6">
        Pending approvals ({items.length})
      </h1>
      {items.length === 0 ? (
        <p className="text-zinc-500">Nothing pending.</p>
      ) : (
        <ul className="space-y-3">
          {items.map(p => (
            <li key={p.id}
                className="rounded border border-zinc-800 bg-zinc-900/50 p-4">
              <div className="flex justify-between text-sm text-zinc-400">
                <span>
                  <strong className="text-zinc-200">{p.agent_id}</strong>
                  {" · "}{p.action_type}
                  {p.skill && <> · skill <code>{p.skill}</code></>}
                </span>
                <span>
                  proposed {new Date(p.proposed_at).toLocaleString()}
                </span>
              </div>
              <div className="mt-2 text-zinc-200">
                <div><strong>Target:</strong> {p.target || "—"}</div>
                {p.rationale && (
                  <div className="text-sm text-zinc-400 mt-1">
                    <strong>Rationale:</strong> {p.rationale}
                  </div>
                )}
              </div>
              <pre className="mt-2 text-xs bg-zinc-950 border border-zinc-800
                               rounded p-2 overflow-auto">
                {JSON.stringify(p.payload, null, 2)}
              </pre>
              <div className="mt-3 flex gap-2">
                <button
                  onClick={() => onApprove(p.id)}
                  disabled={busy === p.id}
                  className="px-3 py-1.5 rounded bg-teal-600 hover:bg-teal-500
                             disabled:bg-zinc-700 text-white text-sm"
                >Approve</button>
                <button
                  onClick={() => onReject(p.id)}
                  disabled={busy === p.id}
                  className="px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700
                             text-zinc-200 text-sm"
                >Reject</button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Smoke-test**

Navigate to `/admin/agents/approvals`. Empty state should render initially. After running Founder Ops weekly-summary (which proposes a memory write), refresh — one item appears. Test Approve and Reject flows.

- [ ] **Step 3: Commit**

```bash
git add frontend/app/\(authenticated\)/admin/agents/approvals/page.tsx
git commit -m "feat(agents): approvals queue page"
```

---

## Stage K — End-to-end smoke test + docs

### Task 26: Run the end-to-end smoke test

- [ ] **Step 1: Confirm env vars are set**

Required (in `backend/.env` or process env):
- `ANTHROPIC_API_KEY_AGENTS` — your Anthropic API key
- `RESEND_TOKEN_AGENTS` — Resend token used by the agents send service
- `NANOEASM_API_KEY_AGENTS_FOUNDER_OPS` — the key issued in Task 20
- `INTERNAL_API_BASE` — `http://localhost:5000` for local dev
- `FOUNDER_EMAIL` — your email (so the digest goes somewhere)
- `AGENTS_FROM_EMAIL` — e.g. `agents@nanoeasm.com` (must be in your Resend domain)

- [ ] **Step 2: Start backend and frontend**

Two terminals:
- `cd backend && python run.py`
- `cd frontend && npm run dev`

- [ ] **Step 3: Manual run path**

In the browser, log in as superadmin. Visit `/admin/agents/founder-ops`. Type: "Run the weekly summary now." Click Run. Expected: a real Anthropic call happens; the response text appears; a new row in "Recent runs"; the approval queue gains one item.

- [ ] **Step 4: Approve the proposed memory write**

Visit `/admin/agents/approvals`. Click Approve on the proposed weekly memory entry. Expected: item disappears.

Verify in psql:

```bash
psql -h localhost -U easm_user -d easm -c "SELECT key, value FROM agent_memory WHERE agent_id='founder-ops' ORDER BY created_at DESC LIMIT 3;"
```

Expected: a `weekly:YYYY-MM-DD` row.

- [ ] **Step 5: Trigger the scheduled job manually**

```bash
cd backend && python -c "
from app import create_app
from app.agents.skills.weekly_summary import run_weekly_summary
app = create_app()
with app.app_context():
    r = run_weekly_summary(send=True)
    print('STATUS:', r.run.status, 'COST:', r.run.cost_usd)
"
```

Expected: prints `STATUS: success COST: 0.00xx`. Check your inbox — the digest email should arrive within ~30s.

- [ ] **Step 6: Confirm audit-log entries**

```bash
psql -h localhost -U easm_user -d easm -c "SELECT created_at, actor, action FROM audit_log WHERE category='agent' ORDER BY id DESC LIMIT 5;"
```

Expected: at least one row matching `agent:founder-ops` and `GET /api/internal/stats/weekly`.

If any step fails, debug before moving on. Commit fixes as separate "fix(agents): …" commits.

---

### Task 27: Update CLAUDE.md with agent platform basics

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add a section after "Platform Admin Console"**

Append the following section. Place it after the existing `## Platform Admin Console` section, before `## Billing Feature Flag`:

```markdown
## Internal Agent Platform (Phase 1)

A co-hosted multi-agent ops module for the founder, gated behind the existing superadmin role at `/admin/agents`. See `docs/superpowers/specs/2026-05-10-internal-agent-platform-design.md` for the full design.

### Phase 1 (walking skeleton, shipped)

- 6 agent profiles in `backend/app/agents/profiles/<name>/agent.md` (Founder Ops fully wired; the other 5 are stubs until Plan 2)
- One scheduled brief: Monday 08:00 Founder Ops `weekly-summary` → email to `FOUNDER_EMAIL`
- Manual run: `/admin/agents/<name>` with a "Run now" button
- Approval queue: `/admin/agents/approvals` — gates every memory write

### Key conventions
- Agent secrets are namespaced (`*_AGENTS` env vars). Never reuse customer-facing keys.
- Agent code calls Nano EASM via `/api/internal/...` even though it lives in the same app — that seam is what prevents schema-coupling.
- Per-agent API key: `ApiKey.kind = 'agent'`. Issue with `python -m scripts.issue_agent_key <name> <scopes>`.
- Every agent API call writes to `audit_log` with `category = 'agent'`.

### CLI helpers
- `python -m scripts.seed_team_memory` — re-seed the universal `team_memory` facts (idempotent).
- `python -m scripts.issue_agent_key <agent> <scope> [<scope> ...]` — issue or rotate an agent's API key.

### Phase 2 (to be planned next)
- Other 5 agent profiles fleshed out (Engineer, QA, Security Analyst, Strategy, Voice)
- Tuesday + Wednesday briefs (Strategy `competitor-pulse`, Security Analyst `weekly-finding-brief`)
- Other internal-API endpoints (`findings/recent`, `contact-requests/recent`, `audit-log/recent`, `scans/recent`)
- Memory hygiene weekly job + low-confidence review
- Send service for approved customer-facing drafts
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document Phase 1 agent platform in CLAUDE.md"
```

---

## Self-review (run after writing the plan, fix inline)

**Spec coverage check:**
- ✅ Hosting/isolation discipline — Tasks 1, 4, 7, 20 (kind column, blueprint namespace, audit log, agent keys)
- ✅ `agent_*` tables — Task 2, 3
- ✅ `/api/internal/...` — Tasks 5, 6, 7
- ✅ Agent profile structure + Founder Ops + 5 stubs — Tasks 8, 9, 10
- ✅ Memory model — Tasks 11, 12
- ✅ Anthropic + cost cap — Tasks 13, 14
- ✅ Runtime — Tasks 15, 16
- ✅ Approval queue — Task 17
- ✅ Send service — Task 18
- ✅ `weekly-summary` skill — Task 19
- ✅ Scheduler — Task 21
- ✅ Admin UI — Tasks 22–25
- ✅ Smoke test + docs — Tasks 26, 27
- Deferred (Plan 2, explicit): other 5 agents fleshed out, Tuesday/Wednesday briefs, other internal endpoints, hygiene job, customer-facing send.

**Placeholder scan:** No "TBD" / "TODO" / "implement later". Every task has actual code where code is required.

**Type/method consistency:** `run_agent(...)` signature matches between `runtime.py` and its callers (`weekly_summary.py`, `routes.py`). `propose_action`, `approve`, `reject` signatures match between `approvals.py` and `routes.py`. `LlmCall`/`LlmResult` shapes match between `anthropic_client.py` and `runtime.py`. `RunResult` is consistently a dataclass with `.run`, `.thread`, `.text`. `ApiKey.scopes` assumed to be a JSON list — flagged in Task 5 to verify and add if missing.
