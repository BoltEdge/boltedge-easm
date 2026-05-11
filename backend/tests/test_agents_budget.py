from datetime import timedelta
from decimal import Decimal
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
    _make_run(db_session, "founder-ops", 1.50)
    _make_run(db_session, "founder-ops", 2.50)
    _make_run(db_session, "engineer", 5.00)
    assert float(current_month_spend("founder-ops")) == 4.00


def test_current_month_spend_ignores_old_runs(db_session):
    old = AgentRun(
        agent_id="founder-ops", skill="test",
        input={}, status="success", cost_usd=Decimal("99"),
        started_at=now_utc() - timedelta(days=40),
        finished_at=now_utc() - timedelta(days=40),
    )
    db_session.add(old)
    _make_run(db_session, "founder-ops", 1.00)
    db_session.flush()
    assert float(current_month_spend("founder-ops")) == 1.00


def test_check_within_cap_passes_when_under(db_session):
    _make_run(db_session, "founder-ops", 10.00)
    # Under the $50 monthly cap → no exception
    check_within_cap("founder-ops", monthly_cap_usd=50)


def test_check_within_cap_raises_when_over(db_session):
    _make_run(db_session, "founder-ops", 60.00)
    import pytest
    with pytest.raises(RuntimeError, match="over_budget"):
        check_within_cap("founder-ops", monthly_cap_usd=50)
