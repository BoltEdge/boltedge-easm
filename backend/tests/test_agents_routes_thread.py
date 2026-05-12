"""Tests for GET /admin/agents/threads/<thread_id>.

Auth pattern: create a real User with is_root_admin=True, issue a real
access token via create_access_token(), and pass it as Bearer.

The test database is the real local PostgreSQL instance; each test is
wrapped in a SAVEPOINT (see conftest.py) so no data persists.
"""
from __future__ import annotations

import pytest
from app.models import AgentThread, AgentMessage, AgentRun
from app.auth.tokens import create_access_token


# ── helpers ──────────────────────────────────────────────────────────────────


def _make_root_admin(db_session):
    """Create a root-admin user and return (user, bearer_token)."""
    import uuid
    from app.models import User

    user = User(
        email=f"rootadmin-{uuid.uuid4().hex[:8]}@example.com",
        name="Root Admin",
        email_verified=True,
        is_superadmin=True,
        is_root_admin=True,
    )
    db_session.add(user)
    db_session.flush()

    token = create_access_token(
        secret_key="local-dev-secret-key-tests",
        user_id=user.id,
    )
    return user, token


def _make_thread(db_session, agent_id: str = "founder-ops") -> AgentThread:
    thread = AgentThread(agent_id=agent_id, title="test thread")
    db_session.add(thread)
    db_session.flush()
    return thread


def _make_message(
    db_session, thread: AgentThread, role: str, content: dict, offset_secs: int = 0
) -> AgentMessage:
    from app.models import now_utc
    from datetime import timedelta

    msg = AgentMessage(
        thread_id=thread.id,
        role=role,
        content=content,
        created_at=now_utc() + timedelta(seconds=offset_secs),
    )
    db_session.add(msg)
    db_session.flush()
    return msg


# ── tests ─────────────────────────────────────────────────────────────────────


def test_get_thread_returns_404_for_missing(app, client, db_session):
    _, token = _make_root_admin(db_session)
    resp = client.get(
        "/admin/agents/threads/999999",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


def test_get_thread_returns_404_without_auth(app, client, db_session):
    thread = _make_thread(db_session)
    resp = client.get(f"/admin/agents/threads/{thread.id}")
    assert resp.status_code == 404


def test_get_thread_returns_messages_in_order(app, client, db_session):
    """Create a thread with 3 messages, fetch it, verify ordering."""
    _, token = _make_root_admin(db_session)
    thread = _make_thread(db_session)

    m1 = _make_message(
        db_session, thread, "user",
        {"text": "hello"}, offset_secs=0,
    )
    m2 = _make_message(
        db_session, thread, "tool",
        {"tool_name": "read_internal_api", "input": {}, "output": "ok", "is_error": False},
        offset_secs=1,
    )
    m3 = _make_message(
        db_session, thread, "assistant",
        {"text": "done"}, offset_secs=2,
    )

    resp = client.get(
        f"/admin/agents/threads/{thread.id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["thread"]["id"] == thread.id
    assert data["thread"]["title"] == "test thread"
    assert data["thread"]["agent_id"] == "founder-ops"

    ids = [m["id"] for m in data["messages"]]
    assert ids == [m1.id, m2.id, m3.id], "Messages must be oldest-first"

    roles = [m["role"] for m in data["messages"]]
    assert roles == ["user", "tool", "assistant"]


def test_get_thread_includes_runs(app, client, db_session):
    _, token = _make_root_admin(db_session)
    thread = _make_thread(db_session)
    _make_message(db_session, thread, "user", {"text": "go"})

    from app.models import now_utc
    from datetime import timedelta

    run = AgentRun(
        agent_id="founder-ops",
        skill="weekly-summary",
        thread_id=thread.id,
        input={"prompt": "go"},
        status="success",
        cost_usd="0.0123",
        duration_ms=1500,
        started_at=now_utc(),
        finished_at=now_utc() + timedelta(seconds=1),
    )
    db_session.add(run)
    db_session.flush()

    resp = client.get(
        f"/admin/agents/threads/{thread.id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.get_json()

    assert len(data["runs"]) == 1
    r = data["runs"][0]
    assert r["skill"] == "weekly-summary"
    assert r["status"] == "success"
    assert r["cost_usd"] == pytest.approx(0.0123, rel=1e-3)
    assert r["duration_ms"] == 1500


def test_get_thread_response_shape(app, client, db_session):
    """Verify the top-level keys and nested thread shape."""
    _, token = _make_root_admin(db_session)
    thread = _make_thread(db_session, agent_id="sam")

    resp = client.get(
        f"/admin/agents/threads/{thread.id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.get_json()

    assert set(data.keys()) == {"thread", "messages", "runs"}
    t = data["thread"]
    assert "id" in t
    assert "agent_id" in t
    assert "title" in t
    assert "created_at" in t
    assert t["created_at"].endswith("Z")
