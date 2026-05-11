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
    keys = [p.target for p in pending]
    assert "k1" in keys
    assert "k2" not in keys


def test_expire_old_marks_past_due(db_session):
    p = propose_action(
        agent_id="founder-ops", action_type="memory-write",
        target="old", payload={}, rationale="r",
    )
    p.expires_at = now_utc() - timedelta(days=1)
    db_session.flush()

    expire_old()

    p2 = PendingAction.query.get(p.id)
    assert p2.decision == "expired"
