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


# ---------------------------------------------------------------- #
# Regression tests for _rebuild_anthropic_messages — continuing a    #
# thread with tool calls used to send role='tool' rows directly to   #
# Anthropic, which rejects with 400 'Unexpected role "tool"'.        #
# The rebuild must synthesize the assistant tool_use turn and        #
# convert tool rows into user-role tool_result content blocks.       #
# ---------------------------------------------------------------- #
from app.agents.prompt_builder import _rebuild_anthropic_messages


class _Msg:
    """Lightweight stand-in for AgentMessage (avoids DB setup)."""
    def __init__(self, role, content):
        self.role = role
        self.content = content


def test_rebuild_text_only_thread_passes_through():
    msgs = [
        _Msg("user", {"text": "hi"}),
        _Msg("assistant", {"text": "hello back"}),
    ]
    out = _rebuild_anthropic_messages(msgs)
    assert out == [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello back"},
    ]


def test_rebuild_single_tool_call_synthesizes_assistant_and_user_turns():
    msgs = [
        _Msg("user", {"text": "use a tool"}),
        _Msg("tool", {
            "tool_use_id": "toolu_abc",
            "tool_name": "read_repo_file",
            "input": {"path": "x.py"},
            "output": "file contents",
            "is_error": False,
        }),
        _Msg("assistant", {"text": "done"}),
    ]
    out = _rebuild_anthropic_messages(msgs)
    assert out == [
        {"role": "user", "content": "use a tool"},
        {"role": "assistant", "content": [
            {"type": "tool_use", "id": "toolu_abc",
             "name": "read_repo_file", "input": {"path": "x.py"}},
        ]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_abc",
             "content": "file contents", "is_error": False},
        ]},
        {"role": "assistant", "content": "done"},
    ]


def test_rebuild_consecutive_tool_calls_grouped_into_one_turn_pair():
    msgs = [
        _Msg("user", {"text": "use two tools"}),
        _Msg("tool", {
            "tool_use_id": "toolu_1",
            "tool_name": "web_fetch",
            "input": {"url": "https://x"},
            "output": "page one",
            "is_error": False,
        }),
        _Msg("tool", {
            "tool_use_id": "toolu_2",
            "tool_name": "web_search",
            "input": {"query": "y"},
            "output": "results",
            "is_error": False,
        }),
    ]
    out = _rebuild_anthropic_messages(msgs)
    assert len(out) == 3
    assert out[0] == {"role": "user", "content": "use two tools"}
    assert out[1]["role"] == "assistant"
    assert len(out[1]["content"]) == 2
    assert out[1]["content"][0]["id"] == "toolu_1"
    assert out[1]["content"][1]["id"] == "toolu_2"
    assert out[2]["role"] == "user"
    assert len(out[2]["content"]) == 2
    assert out[2]["content"][0]["tool_use_id"] == "toolu_1"
    assert out[2]["content"][1]["tool_use_id"] == "toolu_2"


def test_rebuild_empty_assistant_text_skipped():
    msgs = [
        _Msg("user", {"text": "hi"}),
        _Msg("tool", {
            "tool_use_id": "toolu_x",
            "tool_name": "web_fetch",
            "input": {"url": "u"},
            "output": "ok",
            "is_error": False,
        }),
        _Msg("assistant", {"text": ""}),
    ]
    out = _rebuild_anthropic_messages(msgs)
    assert all(
        not (m["role"] == "assistant" and m["content"] == "")
        for m in out
    )
    assert any(
        m["role"] == "assistant"
        and isinstance(m["content"], list)
        and m["content"][0].get("type") == "tool_use"
        for m in out
    )


def test_rebuild_no_role_tool_ever_passed_through():
    """The whole point: no message in the output should have role='tool'."""
    msgs = [
        _Msg("user", {"text": "go"}),
        _Msg("tool", {
            "tool_use_id": "toolu_q",
            "tool_name": "web_fetch",
            "input": {"url": "z"},
            "output": "ok",
            "is_error": False,
        }),
        _Msg("assistant", {"text": "done"}),
    ]
    out = _rebuild_anthropic_messages(msgs)
    roles = {m["role"] for m in out}
    assert roles == {"user", "assistant"}, (
        f"Anthropic only accepts user/assistant roles; got {roles}"
    )


def test_rebuild_empty_thread_returns_empty_list():
    assert _rebuild_anthropic_messages([]) == []
