"""Tests for GET /admin/agents/<agent_id>/approvals."""
import uuid
from app.agents.approvals import propose_action, approve, reject
from app.models import User
from app.extensions import db
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


def test_agent_proposals_returns_all_statuses(client, db_session):
    _, token = _make_root_admin(db_session)
    aid = f"test-agent-{uuid.uuid4().hex[:8]}"

    p1 = propose_action(agent_id=aid, action_type="memory-write",
                        target="fact:pending", payload={"value": {"x": 1}},
                        rationale="")
    p2 = propose_action(agent_id=aid, action_type="memory-write",
                        target="fact:approved", payload={"value": {"x": 2}},
                        rationale="")
    approve(p2.id, decided_by="founder")
    p3 = propose_action(agent_id=aid, action_type="memory-write",
                        target="fact:rejected", payload={"value": {"x": 3}},
                        rationale="")
    reject(p3.id, decided_by="founder", note="bad fact")

    resp = client.get(
        f"/admin/agents/{aid}/approvals",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert data["agent_id"] == aid
    assert data["summary"] == {"pending": 1, "approved": 1, "rejected": 1}
    ids = {row["id"] for row in data["proposals"]}
    assert {p1.id, p2.id, p3.id} <= ids


def test_agent_proposals_excludes_other_agents(client, db_session):
    _, token = _make_root_admin(db_session)
    aid = f"test-agent-{uuid.uuid4().hex[:8]}"
    aid_other = f"test-other-{uuid.uuid4().hex[:8]}"
    propose_action(agent_id=aid, action_type="memory-write",
                   target="fact:ours", payload={}, rationale="")
    p_other = propose_action(agent_id=aid_other, action_type="memory-write",
                              target="fact:theirs", payload={}, rationale="")

    resp = client.get(
        f"/admin/agents/{aid}/approvals",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = resp.get_json()
    ids = {row["id"] for row in data["proposals"]}
    assert p_other.id not in ids


def test_agent_proposals_includes_decision_note_for_rejected(client, db_session):
    _, token = _make_root_admin(db_session)
    aid = f"test-agent-{uuid.uuid4().hex[:8]}"
    p = propose_action(agent_id=aid, action_type="memory-write",
                      target="fact:r", payload={}, rationale="")
    reject(p.id, decided_by="founder", note="speculation, not fact")

    resp = client.get(
        f"/admin/agents/{aid}/approvals",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = resp.get_json()
    row = next(r for r in data["proposals"] if r["id"] == p.id)
    assert row["decision"] == "rejected"
    assert row["decision_note"] == "speculation, not fact"
