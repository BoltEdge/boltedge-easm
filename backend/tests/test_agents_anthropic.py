from app.agents.anthropic_client import (
    LlmCall, FakeAnthropicClient, compute_cost_usd,
)


def test_compute_cost_opus_4_7():
    # Opus 4.7 pricing as of 2026: $15/MTok input, $75/MTok output.
    # 1,000 input + 500 output tokens.
    cost = compute_cost_usd(model="claude-opus-4-7",
                             input_tokens=1000, output_tokens=500)
    # 1000 * 15/1_000_000 + 500 * 75/1_000_000 = 0.015 + 0.0375
    assert round(cost, 4) == 0.0525


def test_compute_cost_unknown_model_returns_none():
    assert compute_cost_usd(model="random-model",
                             input_tokens=100, output_tokens=10) is None


def test_fake_client_returns_canned_response():
    fc = FakeAnthropicClient(canned_text="hello world")
    call = LlmCall(
        model="claude-opus-4-7",
        system="be helpful",
        messages=[{"role": "user", "content": "hi"}],
        max_tokens=100,
    )
    out = fc.call(call)
    assert out.text == "hello world"
    assert out.input_tokens > 0
    assert out.output_tokens > 0
    assert out.stop_reason == "end_turn"
