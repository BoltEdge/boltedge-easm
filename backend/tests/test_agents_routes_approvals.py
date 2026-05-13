"""Tests for Phase 2B-1 changes to /admin/agents/approvals API.

Tests that the approvals_list and approvals_approve endpoints include
action_type and applied_result fields in their responses.
"""
from __future__ import annotations

import uuid
import pytest
from app.agents.approvals import propose_action
from app.models import User
from app.extensions import db
from app.auth.tokens import create_access_token


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


def test_approvals_list_includes_action_type_and_applied_result(
    client, db_session,
):
    """GET /admin/agents/approvals should include action_type and applied_result."""
    _, token = _make_root_admin(db_session)
    p = propose_action(
        agent_id="engineer",
        action_type="code-pr",
        target="Test PR",
        payload={"pr_title": "Test PR",
                  "files": [{"path": "a.py", "content": "x"}]},
        rationale="from test",
    )

    resp = client.get(
        "/admin/agents/approvals",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    row = next(r for r in data["pending"] if r["id"] == p.id)
    assert row["action_type"] == "code-pr"
    assert "applied_result" in row  # null is fine while pending


def test_approvals_list_includes_action_type_memory_write(
    client, db_session,
):
    """GET /admin/agents/approvals should include action_type for memory-write."""
    _, token = _make_root_admin(db_session)
    p = propose_action(
        agent_id="founder-ops",
        action_type="memory-write",
        target="customer:acme:tier",
        payload={"value": {"tier": "Pro"}, "tags": ["customer:acme"]},
        rationale="from test",
    )

    resp = client.get(
        "/admin/agents/approvals",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    row = next(r for r in data["pending"] if r["id"] == p.id)
    assert row["action_type"] == "memory-write"
    assert "applied_result" in row


def test_approvals_approve_includes_applied_result_on_success(
    client, db_session, monkeypatch,
):
    """POST /admin/agents/approvals/<id>/approve should include applied_result."""
    from unittest.mock import patch

    _, token = _make_root_admin(db_session)
    p = propose_action(
        agent_id="engineer",
        action_type="code-pr",
        target="Test PR",
        payload={
            "branch_name": "rob/test-fix",
            "base": "master",
            "commit_message": "test",
            "files": [{"path": "a.py", "content": "x"}],
            "pr_title": "Test PR",
            "pr_body": "Body",
        },
        rationale="from test",
    )

    fake_result = {
        "pr_url": "https://github.com/BoltEdge/boltedge-easm/pull/99",
        "pr_number": 99,
        "branch": "rob/test-fix",
    }

    with patch(
        "app.agents.tools.github_writer.create_pr",
        return_value=fake_result,
    ):
        resp = client.post(
            f"/admin/agents/approvals/{p.id}/approve",
            headers={"Authorization": f"Bearer {token}"},
            json={"decided_by": "founder@test"},
        )

    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert "applied_result" in data
    assert data["applied_result"] == fake_result


def test_approvals_approve_includes_applied_result_null_for_memory(
    client, db_session,
):
    """POST /admin/agents/approvals/<id>/approve should include applied_result (null) for memory-write."""
    _, token = _make_root_admin(db_session)
    p = propose_action(
        agent_id="founder-ops",
        action_type="memory-write",
        target="customer:acme:tier",
        payload={"value": {"tier": "Pro"}, "tags": ["customer:acme"]},
        rationale="from test",
    )

    resp = client.post(
        f"/admin/agents/approvals/{p.id}/approve",
        headers={"Authorization": f"Bearer {token}"},
        json={"decided_by": "founder@test"},
    )

    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert "applied_result" in data
    # applied_result can be None for memory-write (only code-pr uses it for now)
    assert data["applied_result"] is None


def test_approvals_reject_includes_applied_result(
    client, db_session,
):
    """POST /admin/agents/approvals/<id>/reject should include applied_result."""
    _, token = _make_root_admin(db_session)
    p = propose_action(
        agent_id="founder-ops",
        action_type="memory-write",
        target="customer:acme:tier",
        payload={"value": {"tier": "Pro"}, "tags": ["customer:acme"]},
        rationale="from test",
    )

    resp = client.post(
        f"/admin/agents/approvals/{p.id}/reject",
        headers={"Authorization": f"Bearer {token}"},
        json={"decided_by": "founder@test", "note": "not accurate"},
    )

    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert "applied_result" in data
