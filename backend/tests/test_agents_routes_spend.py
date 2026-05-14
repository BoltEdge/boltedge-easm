"""Tests for GET /admin/agents/spend."""
import uuid
from decimal import Decimal
from app.models import User, AgentRun, now_utc
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


def _add_run(db_session, agent_id, cost):
    db_session.add(AgentRun(
        agent_id=agent_id, skill="test",
        input={"x": 1}, status="success",
        cost_usd=Decimal(str(cost)),
        started_at=now_utc(), finished_at=now_utc(),
    ))
    db_session.flush()


def test_spend_returns_all_known_agents(client, db_session):
    _, token = _make_root_admin(db_session)
    resp = client.get(
        "/admin/agents/spend",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    agent_ids = {a["agent_id"] for a in data["agents"]}
    assert {"founder-ops", "engineer", "qa",
            "security-analyst", "strategy", "voice"} <= agent_ids


def test_spend_sums_current_month_cost(client, db_session):
    _, token = _make_root_admin(db_session)
    # Use a unique agent_id so this test isn't polluted by prior runs.
    # But to test the response shape we need a known-real agent (one
    # of the 6 profiles). Use the existing current_month_spend logic
    # via a profile name — pollution check is done by adding a fixed
    # delta and verifying the delta lands.
    before_resp = client.get(
        "/admin/agents/spend",
        headers={"Authorization": f"Bearer {token}"},
    )
    before = {a["agent_id"]: a["spend_usd"] for a in before_resp.get_json()["agents"]}

    _add_run(db_session, "founder-ops", 0.50)
    _add_run(db_session, "founder-ops", 0.25)

    after_resp = client.get(
        "/admin/agents/spend",
        headers={"Authorization": f"Bearer {token}"},
    )
    after = {a["agent_id"]: a["spend_usd"] for a in after_resp.get_json()["agents"]}
    assert round(after["founder-ops"] - before["founder-ops"], 2) == 0.75


def test_spend_includes_cap_and_pct(client, db_session):
    _, token = _make_root_admin(db_session)
    resp = client.get(
        "/admin/agents/spend",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = resp.get_json()
    sam = next(a for a in data["agents"] if a["agent_id"] == "founder-ops")
    assert sam["cap_usd"] > 0
    # pct should be round(spend/cap*100, 2) per the endpoint impl
    if sam["cap_usd"] > 0:
        expected = round(sam["spend_usd"] / sam["cap_usd"] * 100, 2)
        assert sam["pct"] == expected
