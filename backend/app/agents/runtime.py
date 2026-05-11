"""Run-an-agent — the central runtime.

Loads the agent's profile, assembles prompt context (identity + memory +
thread), enforces the cost cap, calls the Anthropic client, persists
both the run trace and the new thread messages.

Message-ordering contract
--------------------------
``build_messages_and_system`` reads ``thread.messages`` (existing DB rows)
and then appends the current ``user_prompt`` as the final turn.  Therefore
the user message for the *current* turn must be persisted to the DB
**after** ``build_messages_and_system`` is called — if it were written
before, the builder would include it from thread history AND append it
again, producing a duplicate.

Ordering:
  1. build_messages_and_system(thread)   ← reads only prior messages
  2. call Anthropic
  3. flush user message                  ← now committed to thread history
  4. flush assistant message
"""
from __future__ import annotations
import dataclasses
from typing import Iterable

from app.extensions import db
from app.models import AgentRun, AgentThread, AgentMessage, now_utc

from .profile_loader import load_profile_by_name, AgentProfile
from .anthropic_client import LlmCall, RealAnthropicClient, LlmResult
from .prompt_builder import build_messages_and_system
from .budget import check_within_cap


@dataclasses.dataclass
class RunResult:
    run: AgentRun
    thread: AgentThread
    text: str | None


def _get_or_create_thread(agent_id: str, thread_id: int | None,
                           user_prompt: str) -> AgentThread:
    if thread_id is not None:
        t = db.session.get(AgentThread, thread_id)
        if not t:
            raise ValueError(f"thread {thread_id} not found")
        return t
    title = (user_prompt[:80] + "…") if len(user_prompt) > 80 else user_prompt
    t = AgentThread(agent_id=agent_id, title=title)
    db.session.add(t)
    db.session.flush()
    return t


def run_agent(
    agent_name: str,
    user_prompt: str,
    skill: str | None,
    memory_tags: Iterable[str],
    client=None,
    thread_id: int | None = None,
) -> RunResult:
    """Execute one agent turn.

    Parameters
    ----------
    agent_name:
        Slug matching a directory under ``app/agents/profiles/``.
    user_prompt:
        The human turn text.
    skill:
        Optional skill label recorded on the run trace (for routing /
        reporting only — the runtime does not enforce skill boundaries).
    memory_tags:
        Tags used to retrieve relevant ``agent_memory`` rows for context.
    client:
        Anthropic client instance.  Pass a ``FakeAnthropicClient`` in
        tests; omit (or pass ``None``) in production to use
        ``RealAnthropicClient``.
    thread_id:
        Continue an existing ``AgentThread`` by ID.  When ``None`` a new
        thread is created.

    Returns
    -------
    RunResult
        Dataclass with ``run``, ``thread``, and ``text``.  All three
        fields are always present; ``text`` is ``None`` on failure or
        budget overrun.
    """
    profile = load_profile_by_name(agent_name)
    thread = _get_or_create_thread(profile.name, thread_id, user_prompt)
    started = now_utc()

    run = AgentRun(
        agent_id=profile.name,
        skill=skill,
        thread_id=thread.id,
        input={"prompt": user_prompt, "memory_tags": list(memory_tags)},
        status="running",
        started_at=started,
    )
    db.session.add(run)
    db.session.flush()

    # ------------------------------------------------------------------ #
    # Cost-cap check — before we spend anything.                           #
    # The check queries cost_usd of prior *completed* runs this month.     #
    # The current run is already flushed with status="running" and         #
    # cost_usd=NULL so it does not inflate the aggregate.                  #
    # ------------------------------------------------------------------ #
    try:
        check_within_cap(profile.name, profile.cost_cap_monthly_usd)
    except RuntimeError as e:
        run.status = "over-budget"
        run.error = str(e)
        run.finished_at = now_utc()
        db.session.flush()
        return RunResult(run=run, thread=thread, text=None)

    # ------------------------------------------------------------------ #
    # Build the prompt.                                                    #
    #                                                                      #
    # Reads thread.messages (prior turns only) and appends user_prompt.   #
    # The user message for this turn is NOT yet in the DB — persisting it  #
    # before this call would cause it to appear twice in the message list. #
    # ------------------------------------------------------------------ #
    system, messages = build_messages_and_system(
        profile=profile,
        user_prompt=user_prompt,
        thread=thread,
        memory_tags=memory_tags,
    )

    # ------------------------------------------------------------------ #
    # Call the LLM.                                                        #
    # ------------------------------------------------------------------ #
    try:
        c = client or RealAnthropicClient()
        result: LlmResult = c.call(LlmCall(
            model=profile.default_model,
            system=system,
            messages=messages,
            max_tokens=4096,
        ))
    except Exception as e:
        run.status = "failed"
        run.error = repr(e)[:1000]
        run.finished_at = now_utc()
        db.session.flush()
        return RunResult(run=run, thread=thread, text=None)

    # ------------------------------------------------------------------ #
    # Persist messages — user first (chronological order), then assistant. #
    # Done AFTER build_messages_and_system to avoid double-appearance.     #
    #                                                                      #
    # Append to thread.messages (not db.session.add) so SQLAlchemy's      #
    # in-memory relationship collection stays in sync.  The relationship   #
    # is already loaded on the thread object; calling db.session.add on    #
    # a bare AgentMessage would leave the collection stale (empty) until   #
    # the next DB round-trip.                                               #
    # ------------------------------------------------------------------ #
    user_msg = AgentMessage(
        role="user",
        content={"text": user_prompt},
    )
    thread.messages.append(user_msg)

    assistant_msg = AgentMessage(
        role="assistant",
        content={"text": result.text},
        tokens_used=result.input_tokens + result.output_tokens,
    )
    thread.messages.append(assistant_msg)

    run.status = "success"
    run.output = {"text": result.text}
    run.cost_usd = result.cost_usd
    run.duration_ms = result.duration_ms
    run.finished_at = now_utc()
    db.session.flush()

    return RunResult(run=run, thread=thread, text=result.text)
