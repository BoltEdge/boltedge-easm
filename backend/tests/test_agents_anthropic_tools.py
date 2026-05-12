from app.agents.anthropic_client import LlmCall, FakeAnthropicClient


def test_llmcall_accepts_tools_field():
    call = LlmCall(
        model="claude-opus-4-7",
        system="be helpful",
        messages=[{"role": "user", "content": "hi"}],
        max_tokens=100,
        tools=[{"name": "x_t", "description": "d", "input_schema": {}}],
    )
    assert call.tools[0]["name"] == "x_t"


def test_fake_client_default_returns_end_turn():
    fc = FakeAnthropicClient(canned_text="hello")
    call = LlmCall(
        model="claude-opus-4-7", system="s",
        messages=[{"role": "user", "content": "hi"}],
        max_tokens=100,
    )
    result = fc.call(call)
    assert result.stop_reason == "end_turn"
    assert result.text == "hello"
    assert result.tool_uses == []


def test_fake_client_scripted_tool_use_then_end_turn():
    fc = FakeAnthropicClient(scripted_responses=[
        {"stop_reason": "tool_use",
         "tool_uses": [{"id": "t1", "name": "x_t",
                         "input": {"q": "hello"}}]},
        {"stop_reason": "end_turn",
         "text": "done"},
    ])
    call = LlmCall(model="claude-opus-4-7", system="s",
                    messages=[{"role": "user", "content": "go"}],
                    max_tokens=100,
                    tools=[{"name": "x_t", "description": "d",
                             "input_schema": {}}])
    # First turn -> tool_use
    r1 = fc.call(call)
    assert r1.stop_reason == "tool_use"
    assert r1.tool_uses[0]["name"] == "x_t"
    # Second turn -> end_turn
    r2 = fc.call(call)
    assert r2.stop_reason == "end_turn"
    assert r2.text == "done"
