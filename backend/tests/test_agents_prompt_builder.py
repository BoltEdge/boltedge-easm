from app.agents.prompt_builder import build_messages_and_system
from app.agents.profile_loader import load_profile_by_name
from app.agents.memory import write_memory, write_team_memory
from app.models import AgentThread, AgentMessage
from app.extensions import db


def test_build_minimal_no_memory_no_thread(db_session):
    prof = load_profile_by_name("founder-ops")
    sys, msgs = build_messages_and_system(
        profile=prof,
        user_prompt="Run weekly summary please.",
        thread=None,
        memory_tags=[],
    )
    assert "Founder Ops" in sys
    assert msgs == [{"role": "user", "content": "Run weekly summary please."}]


def test_build_includes_team_memory(db_session):
    write_team_memory("brand:test_rule_pb", {"rule": "be terse"}, ["brand"])
    prof = load_profile_by_name("founder-ops")
    sys, _ = build_messages_and_system(
        profile=prof,
        user_prompt="hi",
        thread=None,
        memory_tags=[],
    )
    assert "TEAM MEMORY" in sys or "team memory" in sys.lower()
    assert "be terse" in sys


def test_build_includes_agent_memory_by_tag(db_session):
    write_memory("founder-ops", "fact:vol_q2",
                  {"signups_q2": 120}, ["topic:metrics"], "user-told")
    prof = load_profile_by_name("founder-ops")
    sys, _ = build_messages_and_system(
        profile=prof,
        user_prompt="weekly summary",
        thread=None,
        memory_tags=["topic:metrics"],
    )
    assert "120" in sys


def test_build_includes_thread_history(db_session):
    t = AgentThread(agent_id="founder-ops", title="t")
    t.messages.append(AgentMessage(role="user",
                                    content={"text": "first"}))
    t.messages.append(AgentMessage(role="assistant",
                                    content={"text": "reply"}))
    db_session.add(t)
    db_session.flush()

    prof = load_profile_by_name("founder-ops")
    _, msgs = build_messages_and_system(
        profile=prof,
        user_prompt="next thing",
        thread=t,
        memory_tags=[],
    )
    assert len(msgs) == 3
    assert msgs[0] == {"role": "user", "content": "first"}
    assert msgs[1] == {"role": "assistant", "content": "reply"}
    assert msgs[-1] == {"role": "user", "content": "next thing"}
