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


def test_approve_code_pr_calls_github_writer_and_stores_result(
    db_session, monkeypatch,
):
    """Approving a code-pr pending_action must call create_pr and store
    the {pr_url, pr_number, branch} dict in pending_action.applied_result."""
    from unittest.mock import patch
    from app.agents.approvals import propose_action, approve
    from app.models import PendingAction

    p = propose_action(
        agent_id="engineer",
        action_type="code-pr",
        target="test PR title",
        payload={
            "branch_name": "rob/test-fix",
            "base": "master",
            "commit_message": "test",
            "files": [{"path": "a.py", "content": "x"}],
            "pr_title": "test PR title",
            "pr_body": "Body referencing test_a.py",
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
    ) as mock_create:
        approve(p.id, decided_by="founder@test")

    mock_create.assert_called_once()
    refreshed = PendingAction.query.get(p.id)
    assert refreshed.decision == "approved"
    assert refreshed.applied_result == fake_result


def test_approve_code_pr_captures_writer_error_in_applied_result(
    db_session, monkeypatch,
):
    """If create_pr raises, the approval should still mark the row as
    decided but applied_result should carry the error string."""
    from unittest.mock import patch
    from app.agents.approvals import propose_action, approve
    from app.models import PendingAction

    p = propose_action(
        agent_id="engineer",
        action_type="code-pr",
        target="bad PR",
        payload={
            "branch_name": "rob/bad",
            "base": "master",
            "commit_message": "x",
            "files": [{"path": "a.py", "content": "x"}],
            "pr_title": "bad PR",
            "pr_body": "body covering test_a.py",
        },
        rationale="from test",
    )

    with patch(
        "app.agents.tools.github_writer.create_pr",
        side_effect=RuntimeError("422 Reference already exists"),
    ):
        approve(p.id, decided_by="founder@test")

    refreshed = PendingAction.query.get(p.id)
    assert refreshed.decision == "approved"
    assert refreshed.applied_result is not None
    assert "422" in (refreshed.applied_result.get("error") or "")


def test_approve_memory_delete_removes_row(db_session):
    """Approving a memory-delete action removes the row and records
    {deleted: True, key: <key>} in applied_result."""
    from app.agents.memory import write_memory

    write_memory(
        agent_id="founder-ops",
        key="fact:to_be_deleted",
        value={"rule": "old fact"},
        tags=["topic:test"],
        source="test",
    )
    assert AgentMemory.query.filter_by(
        agent_id="founder-ops", key="fact:to_be_deleted"
    ).first() is not None

    p = propose_action(
        agent_id="founder-ops",
        action_type="memory-delete",
        target="fact:to_be_deleted",
        payload={},
        rationale="no longer accurate",
    )
    approve(p.id, decided_by="founder@test")

    assert AgentMemory.query.filter_by(
        agent_id="founder-ops", key="fact:to_be_deleted"
    ).first() is None

    refreshed = PendingAction.query.get(p.id)
    assert refreshed.applied_result == {
        "deleted": True, "key": "fact:to_be_deleted"
    }
    assert refreshed.decision == "approved"


def test_approve_memory_delete_records_not_found_without_raising(db_session):
    """Approving a memory-delete for a non-existent key records
    {deleted: False, reason: 'not found'} and still marks decided."""
    p = propose_action(
        agent_id="founder-ops",
        action_type="memory-delete",
        target="fact:does_not_exist",
        payload={},
        rationale="testing miss path",
    )
    approve(p.id, decided_by="founder@test")

    refreshed = PendingAction.query.get(p.id)
    assert refreshed.decision == "approved"
    assert refreshed.applied_result == {
        "deleted": False, "reason": "not found"
    }
