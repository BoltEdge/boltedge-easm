"""Tests for GET /admin/agents/approvals/history."""
import uuid
from app.agents.approvals import propose_action, approve, reject
from app.models import User
from app.auth.tokens import create_access_token


def _make_root_admin(db_session):
    u = User(
        email=f"rootadmin-{uuid.uuid4().hex[:8]}@example.com",
        name="Test Admin",
        email_verified=True,
        is_superadmin=True,
        is_root_admin=True,
    )
    db_session.add(u)
    db_session.flush()
    return u, create_access_token(
        secret_key="local-dev-secret-key-tests",
        user_id=u.id,
    )


def test_history_returns_decided_excludes_pending(client, db_session):
    _, token = _make_root_admin(db_session)
    aid = f"test-agent-{uuid.uuid4().hex[:8]}"
    p_pending = propose_action(agent_id=aid, action_type="memory-write",
                                target="fact:pending", payload={},
                                rationale="")
    p_approved = propose_action(agent_id=aid, action_type="memory-write",
                                 target="fact:approved", payload={},
                                 rationale="")
    approve(p_approved.id, decided_by="founder")
    p_rejected = propose_action(agent_id=aid, action_type="code-pr",
                                 target="bad PR", payload={}, rationale="")
    reject(p_rejected.id, decided_by="founder", note="not safe")

    resp = client.get(
        "/admin/agents/approvals/history?limit=200",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    ids = {row["id"] for row in data["history"]}
    assert p_approved.id in ids
    assert p_rejected.id in ids
    assert p_pending.id not in ids


def test_history_includes_decision_note(client, db_session):
    _, token = _make_root_admin(db_session)
    aid = f"test-agent-{uuid.uuid4().hex[:8]}"
    p = propose_action(agent_id=aid, action_type="memory-write",
                       target="fact:x", payload={}, rationale="")
    reject(p.id, decided_by="founder", note="wrong vibe")

    resp = client.get(
        "/admin/agents/approvals/history?limit=200",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = resp.get_json()
    row = next(r for r in data["history"] if r["id"] == p.id)
    assert row["decision"] == "rejected"
    assert row["decision_note"] == "wrong vibe"


def test_history_respects_limit_param(client, db_session):
    _, token = _make_root_admin(db_session)
    aid = f"test-agent-{uuid.uuid4().hex[:8]}"
    for i in range(5):
        p = propose_action(agent_id=aid, action_type="memory-write",
                            target=f"fact:{i}", payload={}, rationale="")
        approve(p.id, decided_by="founder")

    resp = client.get(
        "/admin/agents/approvals/history?limit=3",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = resp.get_json()
    assert len(data["history"]) <= 3
