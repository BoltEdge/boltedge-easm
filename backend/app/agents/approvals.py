"""Approval queue for agent actions.

Every memory write, every externally-visible output, every code PR,
every integration write proposes a `PendingAction`. The founder
approves/rejects from the admin UI. Approval applies the underlying
write; rejection captures the reason as feedback.
"""
from __future__ import annotations
from datetime import timedelta

from app.extensions import db
from app.models import PendingAction, now_utc

from .memory import write_memory


DEFAULT_EXPIRY_DAYS = 7


def propose_action(
    agent_id: str,
    action_type: str,
    target: str | None,
    payload: dict,
    rationale: str | None = None,
    skill: str | None = None,
    run_id: int | None = None,
) -> PendingAction:
    p = PendingAction(
        agent_id=agent_id,
        skill=skill,
        action_type=action_type,
        target=target,
        payload=payload,
        rationale=rationale,
        proposed_at=now_utc(),
        expires_at=now_utc() + timedelta(days=DEFAULT_EXPIRY_DAYS),
        run_id=run_id,
    )
    db.session.add(p)
    db.session.flush()
    return p


def list_pending() -> list[PendingAction]:
    return (
        PendingAction.query
        .filter(PendingAction.decision.is_(None))
        .order_by(PendingAction.proposed_at.desc())
        .all()
    )


def approve(pending_id: int, decided_by: str,
             edited_payload: dict | None = None) -> PendingAction:
    p = PendingAction.query.get_or_404(pending_id)
    if p.decision is not None:
        raise ValueError(f"action {pending_id} already decided: {p.decision}")

    payload = edited_payload if edited_payload is not None else p.payload
    try:
        result = _apply_action(p.action_type, p.agent_id, p.target or "", payload)
    except Exception as e:
        # Executor failed — record the error in applied_result but still
        # mark the action decided so it doesn't get re-tried accidentally.
        # Founder can re-propose if they want to retry.
        result = {"error": f"{type(e).__name__}: {e}"}

    p.applied_result = result
    p.decision = "edited-and-approved" if edited_payload is not None else "approved"
    p.decided_at = now_utc()
    p.decided_by = decided_by
    db.session.flush()
    return p


def reject(pending_id: int, decided_by: str,
            note: str | None = None) -> PendingAction:
    p = PendingAction.query.get_or_404(pending_id)
    if p.decision is not None:
        raise ValueError(f"action {pending_id} already decided: {p.decision}")
    p.decision = "rejected"
    p.decided_at = now_utc()
    p.decided_by = decided_by
    p.decision_note = note
    db.session.flush()
    return p


def expire_old() -> int:
    """Marks any pending action past its `expires_at` as decision='expired'.
    Returns the number expired."""
    now = now_utc()
    rows = (
        PendingAction.query
        .filter(PendingAction.decision.is_(None))
        .filter(PendingAction.expires_at < now)
        .all()
    )
    for r in rows:
        r.decision = "expired"
        r.decided_at = now
    db.session.flush()
    return len(rows)


def _apply_action(action_type: str, agent_id: str,
                   target: str, payload: dict):
    """Executes the proposed action. Returns whatever the executor
    returns (or None for actions that don't produce a result)."""
    if action_type == "memory-write":
        write_memory(
            agent_id=agent_id,
            key=target,
            value=payload.get("value", {}),
            tags=payload.get("tags", []),
            source=payload.get("source", "user-told"),
            confidence=payload.get("confidence", 1.00),
            expires_at=payload.get("expires_at"),
        )
        return None
    elif action_type == "code-pr":
        from .tools.github_writer import create_pr
        return create_pr(payload)
    elif action_type in ("external-output", "integration-write",
                          "nano-easm-write", "team-memory-write"):
        # Walking skeleton: these action types are accepted (queued) but
        # their applier is not yet implemented.
        raise NotImplementedError(
            f"action_type {action_type!r} applier not yet wired"
        )
    else:
        raise ValueError(f"unknown action_type: {action_type!r}")
