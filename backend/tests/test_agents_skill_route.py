"""Tests for POST /admin/agents/<agent_name>/run-skill.

Auth pattern: create a real User with is_root_admin=True, issue a real
access token via create_access_token(), and pass it as Bearer.

The test database is the real local PostgreSQL instance; each test is
wrapped in a SAVEPOINT (see conftest.py) so no data persists.
"""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest
from app.auth.tokens import create_access_token
from app.models import AgentRun, AgentThread, User


# ── helpers ──────────────────────────────────────────────────────────────────


def _make_root_admin(db_session):
    """Create a root-admin user and return (user, bearer_token)."""
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


def _make_fake_run_result(db_session, agent_id: str = "founder-ops", skill: str = "weekly-summary"):
    """Create a real AgentThread + AgentRun and wrap them in a mock RunResult."""
    from app.models import now_utc

    thread = AgentThread(agent_id=agent_id, title=f"skill-run-{skill}")
    db_session.add(thread)
    db_session.flush()

    run = AgentRun(
        agent_id=agent_id,
        skill=skill,
        thread_id=thread.id,
        input={"prompt": "skill trigger"},
        status="success",
        cost_usd="0.0042",
        duration_ms=1200,
        started_at=now_utc(),
    )
    db_session.add(run)
    db_session.flush()

    result = MagicMock()
    result.run = run
    result.thread = thread
    result.text = "# Weekly Summary\n\nAll good."
    return result


# ── tests ─────────────────────────────────────────────────────────────────────


def test_run_skill_rejects_wrong_agent(app, client, db_session):
    """Skill weekly-summary belongs to founder-ops; calling it via
    /admin/agents/strategy/run-skill should return 400."""
    _, token = _make_root_admin(db_session)

    resp = client.post(
        "/admin/agents/strategy/run-skill",
        json={"skill": "weekly-summary", "send": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400
    data = resp.get_json()
    assert "error" in data
    assert "founder-ops" in data["error"]


def test_run_skill_unknown_returns_404(app, client, db_session):
    """A skill name that doesn't exist in the registry should return 404."""
    _, token = _make_root_admin(db_session)

    resp = client.post(
        "/admin/agents/founder-ops/run-skill",
        json={"skill": "does-not-exist", "send": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404
    data = resp.get_json()
    assert "error" in data
    assert "unknown skill" in data["error"]


def test_run_skill_missing_skill_field_returns_400(app, client, db_session):
    """Omitting the skill field entirely should return 400."""
    _, token = _make_root_admin(db_session)

    resp = client.post(
        "/admin/agents/founder-ops/run-skill",
        json={"send": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400
    data = resp.get_json()
    assert "error" in data
    assert "skill is required" in data["error"]


def test_run_skill_requires_auth(app, client, db_session):
    """Without a Bearer token the endpoint must not reveal itself (404)."""
    resp = client.post(
        "/admin/agents/founder-ops/run-skill",
        json={"skill": "weekly-summary", "send": False},
    )
    # require_root_admin returns 404 for unauthenticated callers
    assert resp.status_code == 404


def test_run_skill_invokes_function_and_returns_result(app, client, db_session):
    """With invoke_skill mocked to return a fake RunResult, the endpoint
    should return 200 with run_id / thread_id / status / cost_usd / skill."""
    _, token = _make_root_admin(db_session)
    fake_result = _make_fake_run_result(db_session, agent_id="founder-ops", skill="weekly-summary")

    with patch(
        "app.agents.routes.invoke_skill",
        return_value=fake_result,
    ) as mock_invoke:
        resp = client.post(
            "/admin/agents/founder-ops/run-skill",
            json={"skill": "weekly-summary", "send": False},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    mock_invoke.assert_called_once_with("weekly-summary", send=False)

    data = resp.get_json()
    assert data["skill"] == "weekly-summary"
    assert data["status"] == "success"
    assert data["run_id"] == fake_result.run.id
    assert data["thread_id"] == fake_result.thread.id
    assert data["cost_usd"] == pytest.approx(0.0042, rel=1e-3)
    assert "Weekly Summary" in (data["text"] or "")


def test_run_skill_propagates_send_false(app, client, db_session):
    """send=false in the request body should be forwarded to invoke_skill."""
    _, token = _make_root_admin(db_session)
    fake_result = _make_fake_run_result(db_session, agent_id="founder-ops", skill="weekly-summary")

    with patch(
        "app.agents.routes.invoke_skill",
        return_value=fake_result,
    ) as mock_invoke:
        resp = client.post(
            "/admin/agents/founder-ops/run-skill",
            json={"skill": "weekly-summary", "send": False},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    mock_invoke.assert_called_once_with("weekly-summary", send=False)


def test_run_skill_defaults_send_to_true(app, client, db_session):
    """When send is omitted, invoke_skill should be called with send=True."""
    _, token = _make_root_admin(db_session)
    fake_result = _make_fake_run_result(db_session, agent_id="founder-ops", skill="weekly-summary")

    with patch(
        "app.agents.routes.invoke_skill",
        return_value=fake_result,
    ) as mock_invoke:
        resp = client.post(
            "/admin/agents/founder-ops/run-skill",
            json={"skill": "weekly-summary"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200
    mock_invoke.assert_called_once_with("weekly-summary", send=True)


def test_agent_detail_includes_skills(app, client, db_session):
    """GET /admin/agents/founder-ops should include a 'skills' array
    with at least weekly-summary."""
    _, token = _make_root_admin(db_session)

    resp = client.get(
        "/admin/agents/founder-ops",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.get_json()

    assert "skills" in data
    skill_names = [s["name"] for s in data["skills"]]
    assert "weekly-summary" in skill_names

    # Verify the shape of the first skill entry
    skill = next(s for s in data["skills"] if s["name"] == "weekly-summary")
    assert "display_name" in skill
    assert "description" in skill
    assert "schedule" in skill
    assert skill["schedule"] == "Monday 08:00"
