from datetime import datetime, timedelta
from app.agents.memory import (
    write_memory, retrieve_for_agent, retrieve_team_memory,
    write_team_memory,
)
from app.models import AgentMemory, TeamMemory, now_utc
from app.extensions import db


def test_write_and_retrieve_isolated_per_agent(db_session):
    write_memory(agent_id="founder-ops",
                  key="customer:acme:tier",
                  value={"tier": "Pro"},
                  tags=["customer:acme", "topic:plan"],
                  source="user-told")
    write_memory(agent_id="strategy",
                  key="competitor:foo:price",
                  value={"price": "$99"},
                  tags=["competitor:foo"],
                  source="api-fetched")

    fo = retrieve_for_agent(agent_id="founder-ops", tags=["customer:acme"])
    assert len(fo) == 1
    assert fo[0].key == "customer:acme:tier"

    fo_strategy_tag = retrieve_for_agent(agent_id="founder-ops",
                                          tags=["competitor:foo"])
    assert fo_strategy_tag == []


def test_retrieve_orders_recent_first(db_session):
    write_memory("founder-ops", "k1", {"v": 1}, ["t"], "user-told")
    write_memory("founder-ops", "k2", {"v": 2}, ["t"], "user-told")
    write_memory("founder-ops", "k3", {"v": 3}, ["t"], "user-told")
    rs = retrieve_for_agent("founder-ops", tags=["t"])
    assert [r.key for r in rs] == ["k3", "k2", "k1"]


def test_retrieve_skips_expired(db_session):
    past = now_utc() - timedelta(days=1)
    write_memory("founder-ops", "old", {"v": 1}, ["t"],
                  "user-told", expires_at=past)
    write_memory("founder-ops", "new", {"v": 2}, ["t"], "user-told")
    rs = retrieve_for_agent("founder-ops", tags=["t"])
    assert [r.key for r in rs] == ["new"]


def test_team_memory_visible_to_all(db_session):
    write_team_memory("test:visible_to_all",
                       value={"rule": "test fact"},
                       tags=["test"])
    rs = retrieve_team_memory()
    keys = [r.key for r in rs]
    assert "test:visible_to_all" in keys


def test_retrieve_caps_at_top_n(db_session):
    for i in range(50):
        write_memory("founder-ops", f"k{i:02d}", {"i": i},
                      ["bulk"], "user-told")
    rs = retrieve_for_agent("founder-ops", tags=["bulk"], top_n=10)
    assert len(rs) == 10
