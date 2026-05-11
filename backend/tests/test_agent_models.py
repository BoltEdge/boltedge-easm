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
