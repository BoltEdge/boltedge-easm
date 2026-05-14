"""Run-an-agent — the central runtime.

Single-shot mode (no tools in profile.allowed_tools): Phase 1 behaviour.
Multi-turn tool-use mode (allowed_tools non-empty): the runtime calls
Anthropic, executes any tool_use blocks the model emits, appends results
to the message history, and loops until end_turn or the per-run cap fires.

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
  2. multi-turn LLM loop (tool messages persisted DURING the loop)
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
from .tools import TOOL_REGISTRY, expose_tools_for


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


def _truncate(s: str, cap_bytes: int) -> str:
    b = s.encode("utf-8")
    if len(b) <= cap_bytes:
        return s
    return b[:cap_bytes].decode("utf-8", errors="ignore") + (
        f"\n\n…[truncated at {cap_bytes} bytes]"
    )


def _execute_tool(name: str, args: dict) -> tuple[str, bool]:
    """Look up the tool, run its handler, truncate to cap.
    Returns (output_string, is_error)."""
    if name not in TOOL_REGISTRY:
        return (f"[tool '{name}' is not available to this agent]", True)
    tool = TOOL_REGISTRY[name]
    try:
        result = tool.handler(**args)
        if not isinstance(result, str):
            result = str(result)
        return (_truncate(result, tool.result_cap_bytes), False)
    except Exception as e:
        return (f"[tool '{name}' error: {type(e).__name__}: {e}]", True)


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

    tools_spec = expose_tools_for(profile.allowed_tools)
    c = client or RealAnthropicClient()

    tool_calls_made = 0
    final_text: str | None = None
    last_result: LlmResult | None = None

    # ------------------------------------------------------------------ #
    # Persist the user message NOW — after build_messages_and_system so   #
    # the builder didn't see it twice, but before the loop so the user    #
    # message lands at index 0 in thread.messages ahead of any tool msgs. #
    # ------------------------------------------------------------------ #
    user_msg = AgentMessage(
        role="user",
        content={"text": user_prompt},
    )
    thread.messages.append(user_msg)
    db.session.flush()

    # ------------------------------------------------------------------ #
    # Multi-turn tool-use loop.                                            #
    #                                                                      #
    # Each iteration: call LLM → if tool_use, execute tools, append       #
    # tool_result blocks, persist tool messages to DB, loop.               #
    # On end_turn (or max_tokens / stop_sequence), break.                  #
    #                                                                      #
    # Tool messages are persisted DURING the loop via db.session.add()    #
    # (not thread.messages.append()) so they sit behind the already-       #
    # appended user message in the in-memory collection.                   #
    # The assistant message is appended AT THE END via thread.messages.    #
    # ------------------------------------------------------------------ #
    try:
        while True:
            result = c.call(LlmCall(
                model=profile.default_model,
                system=system,
                messages=messages,
                max_tokens=4096,
                tools=tools_spec,
            ))
            last_result = result

            if result.stop_reason == "tool_use" and result.tool_uses:
                # Append the assistant tool_use turn to the in-memory
                # messages list (NOT to the DB — only tool messages are
                # persisted mid-loop; the assistant final message is
                # saved at the end along with the user message).
                assistant_blocks = []
                if result.text:
                    assistant_blocks.append({"type": "text",
                                              "text": result.text})
                for tu in result.tool_uses:
                    assistant_blocks.append({
                        "type": "tool_use",
                        "id": tu["id"],
                        "name": tu["name"],
                        "input": tu["input"],
                    })
                messages.append({"role": "assistant",
                                  "content": assistant_blocks})

                # Execute each tool and build the tool_result block list.
                tool_result_blocks = []
                for tu in result.tool_uses:
                    if tool_calls_made >= profile.tool_call_cap_per_run:
                        tool_result_blocks.append({
                            "type": "tool_result",
                            "tool_use_id": tu["id"],
                            "content": "[tool_call_cap_per_run reached; "
                                       "no further tool calls allowed this run]",
                            "is_error": True,
                        })
                        continue

                    # Check whether this tool requires approval (write-class).
                    tool_def = TOOL_REGISTRY.get(tu["name"])
                    if tool_def is not None and tool_def.requires_approval:
                        # Capture-and-queue: don't execute the handler.
                        from .approvals import propose_action
                        pending = propose_action(
                            agent_id=profile.name,
                            action_type=tool_def.action_type or "unknown-action",
                            target=(tu["input"].get("pr_title")
                                    or tu["input"].get("subject")
                                    or tu["name"]),
                            payload=tu["input"],
                            rationale=f"Tool call from run #{run.id}",
                            skill=skill,
                            run_id=run.id,
                        )
                        output = (
                            f"[queued for approval as pending_action #{pending.id}; "
                            f"agent should wrap up its response without expecting "
                            f"this to fire during the current run]"
                        )
                        is_error = False
                    else:
                        # Inject caller's agent_id for tools that need
                        # server-side scope binding. The model never
                        # sees agent_id in the tool's input_schema.
                        tool_input = dict(tu["input"])
                        if tu["name"] == "read_agent_memory":
                            tool_input["agent_id"] = profile.name
                        output, is_error = _execute_tool(tu["name"], tool_input)
                    tool_result_blocks.append({
                        "type": "tool_result",
                        "tool_use_id": tu["id"],
                        "content": output,
                        "is_error": is_error,
                    })

                    # Persist the tool call + result as a thread message.
                    # Use db.session.add() (not thread.messages.append())
                    # so the tool message is inserted into the DB after the
                    # already-flushed user message but does not shift the
                    # in-memory list position of user ahead of tool.
                    db.session.add(AgentMessage(
                        thread_id=thread.id, role="tool",
                        content={
                            "tool_use_id": tu["id"],
                            "tool_name": tu["name"],
                            "input": tu["input"],
                            "output": output,
                            "is_error": is_error,
                        },
                    ))
                    tool_calls_made += 1

                messages.append({"role": "user",
                                  "content": tool_result_blocks})
                db.session.flush()

                if tool_calls_made >= profile.tool_call_cap_per_run:
                    run.status = "tool-cap-exceeded"
                    run.error = (f"tool_call_cap_per_run "
                                  f"({profile.tool_call_cap_per_run}) reached")
                    run.finished_at = now_utc()
                    db.session.flush()
                    return RunResult(run=run, thread=thread, text=None)

                continue  # next turn

            # end_turn / max_tokens / stop_sequence — exit the loop.
            final_text = result.text or ""
            break

    except Exception as e:
        run.status = "failed"
        run.error = repr(e)[:1000]
        run.finished_at = now_utc()
        db.session.flush()
        return RunResult(run=run, thread=thread, text=None)

    # ------------------------------------------------------------------ #
    # Persist the assistant message at the end.  User message was already  #
    # appended to thread.messages before the loop (after                   #
    # build_messages_and_system, so no duplicate in the prompt context).   #
    # Tool messages were persisted via db.session.add() mid-loop.          #
    # ------------------------------------------------------------------ #
    assistant_msg = AgentMessage(
        role="assistant",
        content={"text": final_text},
        tokens_used=(last_result.input_tokens + last_result.output_tokens)
                     if last_result else None,
    )
    thread.messages.append(assistant_msg)

    run.status = "success"
    run.output = {"text": final_text}
    if last_result:
        run.cost_usd = last_result.cost_usd
        run.duration_ms = last_result.duration_ms
    run.finished_at = now_utc()
    db.session.flush()

    # Expire the in-memory messages collection so the next access re-queries
    # the DB and includes any tool messages that were added via db.session.add()
    # (which bypass the in-memory relationship list).
    db.session.expire(thread, ["messages"])

    return RunResult(run=run, thread=thread, text=final_text)
