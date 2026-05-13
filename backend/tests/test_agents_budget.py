import uuid
from datetime import timedelta
from decimal import Decimal
import pytest

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
    db_session.flush()


def test_current_month_spend_sums_only_this_agent(db_session):
    agent = f"budget-test-{uuid.uuid4().hex[:8]}"
    other = f"budget-other-{uuid.uuid4().hex[:8]}"
    _make_run(db_session, agent, 1.50)
    _make_run(db_session, agent, 2.50)
    _make_run(db_session, other, 5.00)
    assert float(current_month_spend(agent)) == 4.00


def test_current_month_spend_ignores_old_runs(db_session):
    agent = f"budget-test-{uuid.uuid4().hex[:8]}"
    old = AgentRun(
        agent_id=agent, skill="test",
        input={}, status="success", cost_usd=Decimal("99"),
        started_at=now_utc() - timedelta(days=40),
        finished_at=now_utc() - timedelta(days=40),
    )
    db_session.add(old)
    _make_run(db_session, agent, 1.00)
    db_session.flush()
    assert float(current_month_spend(agent)) == 1.00


def test_check_within_cap_passes_when_under(db_session):
    agent = f"budget-test-{uuid.uuid4().hex[:8]}"
    _make_run(db_session, agent, 10.00)
    check_within_cap(agent, monthly_cap_usd=50)


def test_check_within_cap_raises_when_over(db_session):
    agent = f"budget-test-{uuid.uuid4().hex[:8]}"
    _make_run(db_session, agent, 60.00)
    with pytest.raises(RuntimeError, match="over_budget"):
        check_within_cap(agent, monthly_cap_usd=50)
