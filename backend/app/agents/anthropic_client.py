"""Anthropic API client wrapper with cost tracking and a fake for tests.

Production code uses `RealAnthropicClient`. Tests use `FakeAnthropicClient`
injected via the `client` parameter on `runtime.run_agent`. There is one
manual smoke test (later) that exercises the real client end-to-end.
"""
from __future__ import annotations
import dataclasses
import os
import time

# Prices in USD per 1M tokens. Update when Anthropic pricing changes.
PRICING = {
    "claude-opus-4-7":   {"input": 15.00, "output": 75.00},
    "claude-sonnet-4-6": {"input":  3.00, "output": 15.00},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.00},
}


@dataclasses.dataclass(frozen=True)
class LlmCall:
    model: str
    system: str
    messages: list[dict]
    max_tokens: int = 4096
    tools: list[dict] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(frozen=True)
class LlmResult:
    text: str
    input_tokens: int
    output_tokens: int
    cost_usd: float | None
    stop_reason: str
    duration_ms: int
    tool_uses: list[dict] = dataclasses.field(default_factory=list)


def compute_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float | None:
    p = PRICING.get(model)
    if not p:
        return None
    return (input_tokens * p["input"] + output_tokens * p["output"]) / 1_000_000


class RealAnthropicClient:
    def __init__(self, api_key: str | None = None):
        import anthropic  # local import — keeps test imports cheap
        self._client = anthropic.Anthropic(
            api_key=api_key or os.environ["ANTHROPIC_API_KEY_AGENTS"],
        )

    def call(self, call: LlmCall) -> LlmResult:
        start = time.monotonic()
        kwargs = dict(
            model=call.model,
            system=call.system,
            messages=call.messages,
            max_tokens=call.max_tokens,
        )
        if call.tools:
            kwargs["tools"] = call.tools
        msg = self._client.messages.create(**kwargs)
        dur = int((time.monotonic() - start) * 1000)
        text_parts: list[str] = []
        tool_uses: list[dict] = []
        for block in msg.content:
            btype = getattr(block, "type", "")
            if btype == "text":
                text_parts.append(block.text)
            elif btype == "tool_use":
                tool_uses.append({
                    "id": block.id,
                    "name": block.name,
                    "input": dict(block.input),
                })
        cost = compute_cost_usd(
            call.model, msg.usage.input_tokens, msg.usage.output_tokens,
        )
        return LlmResult(
            text="".join(text_parts),
            input_tokens=msg.usage.input_tokens,
            output_tokens=msg.usage.output_tokens,
            cost_usd=cost,
            stop_reason=msg.stop_reason or "unknown",
            duration_ms=dur,
            tool_uses=tool_uses,
        )


class FakeAnthropicClient:
    """Deterministic stub for tests.

    Two modes:
    - `canned_text="..."` — every call() returns a single end_turn with that text.
    - `scripted_responses=[...]` — each call() returns the next entry from the list.
      Each entry is a dict with keys: stop_reason, text (optional), tool_uses (optional).
    """

    def __init__(self, canned_text: str = "ok",
                  scripted_responses: list[dict] | None = None):
        self._text = canned_text
        self._scripted = list(scripted_responses) if scripted_responses else None
        self._idx = 0

    def call(self, call: LlmCall) -> LlmResult:
        if self._scripted is not None:
            if self._idx >= len(self._scripted):
                raise RuntimeError("FakeAnthropicClient: ran out of scripted responses")
            entry = self._scripted[self._idx]
            self._idx += 1
            text = entry.get("text", "")
            tool_uses = list(entry.get("tool_uses", []))
            in_tok = max(1, sum(len(m.get("content", "")) if isinstance(m.get("content"), str) else 32
                                  for m in call.messages) // 4 + len(call.system) // 4)
            out_tok = max(1, (len(text) + sum(len(str(tu)) for tu in tool_uses)) // 4)
            cost = compute_cost_usd(call.model, in_tok, out_tok)
            return LlmResult(
                text=text,
                input_tokens=in_tok, output_tokens=out_tok,
                cost_usd=cost,
                stop_reason=entry["stop_reason"],
                duration_ms=1,
                tool_uses=tool_uses,
            )

        # canned_text mode — rough token estimate: 1 token ≈ 4 chars.
        in_tok = max(1, sum(len(m.get("content", "")) if isinstance(m.get("content"), str) else 32
                              for m in call.messages) // 4 + len(call.system) // 4)
        out_tok = max(1, len(self._text) // 4)
        cost = compute_cost_usd(call.model, in_tok, out_tok)
        return LlmResult(
            text=self._text,
            input_tokens=in_tok, output_tokens=out_tok,
            cost_usd=cost,
            stop_reason="end_turn", duration_ms=1, tool_uses=[],
        )
