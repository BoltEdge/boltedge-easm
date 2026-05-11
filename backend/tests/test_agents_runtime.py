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
    db_session.flush()

    fake = FakeAnthropicClient(canned_text="x")
    result = run_agent("founder-ops", "any prompt", None, [], fake)
    assert result.run.status == "over-budget"
    assert result.run.error and "over_budget" in result.run.error
