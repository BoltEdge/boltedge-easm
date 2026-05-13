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
    # 16384 lets github_pr_create emit a tool_use block containing the
    # full new file content for non-trivial files. 4096 was too small —
    # when Rob tried to propose a PR that included runtime.py (~8k tokens),
    # the model couldn't fit the tool_use payload and silently fell back
    # to text, end_turning without emitting the tool call. Symptom looked
    # like agent refusal; root cause was a max_tokens cap.
    max_tokens: int = 16384
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


def compute_cost_usd(
    model: str,
    input_tokens: int,
    output_tokens: int,
    cache_creation_input_tokens: int = 0,
    cache_read_input_tokens: int = 0,
) -> float | None:
    """Compute USD cost for a single Anthropic call.

    Anthropic's prompt caching billing:
    - `input_tokens`: uncached input, billed at the model's input price.
    - `cache_creation_input_tokens`: tokens used to write to the cache,
      billed at 1.25× the input price (a one-time premium).
    - `cache_read_input_tokens`: tokens read FROM the cache, billed at
      0.1× the input price (the savings).
    """
    p = PRICING.get(model)
    if not p:
        return None
    base_in = input_tokens * p["input"]
    base_out = output_tokens * p["output"]
    cache_create = cache_creation_input_tokens * p["input"] * 1.25
    cache_read = cache_read_input_tokens * p["input"] * 0.10
    return (base_in + base_out + cache_create + cache_read) / 1_000_000


class RealAnthropicClient:
    def __init__(self, api_key: str | None = None):
        import anthropic  # local import — keeps test imports cheap
        self._client = anthropic.Anthropic(
            api_key=api_key or os.environ["ANTHROPIC_API_KEY_AGENTS"],
        )

    def call(self, call: LlmCall) -> LlmResult:
        start = time.monotonic()

        # Wrap the system prompt in a content block with cache_control so
        # Anthropic caches it for 5 minutes. Multi-turn tool loops benefit
        # most: turns 2+ skip re-billing the system prompt (cache_read is
        # 10% of input price). For single-turn calls there's no win — the
        # cache is created but never read — but the marginal premium is
        # tiny (1.25× one time on the system block only).
        if call.system:
            system_blocks: list[dict] = [{
                "type": "text",
                "text": call.system,
                "cache_control": {"type": "ephemeral"},
            }]
        else:
            system_blocks = []

        kwargs = dict(
            model=call.model,
            system=system_blocks,
            messages=call.messages,
            max_tokens=call.max_tokens,
        )

        if call.tools:
            # Also cache the tool definitions (they're static + large).
            # Anthropic caches everything up to and including the
            # last `cache_control` marker, so adding it to the final
            # tool covers the whole tools array.
            tools_list = [dict(t) for t in call.tools]
            tools_list[-1] = {
                **tools_list[-1],
                "cache_control": {"type": "ephemeral"},
            }
            kwargs["tools"] = tools_list

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
        # Pull cache stats off the usage object if present (fields are
        # optional in older SDK versions — fall back to 0).
        cache_create = getattr(msg.usage, "cache_creation_input_tokens", 0) or 0
        cache_read = getattr(msg.usage, "cache_read_input_tokens", 0) or 0
        cost = compute_cost_usd(
            call.model,
            msg.usage.input_tokens,
            msg.usage.output_tokens,
            cache_create,
            cache_read,
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
