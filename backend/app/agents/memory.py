"""Agent memory CRUD + retrieval.

`agent_memory` is per-agent isolated. `team_memory` is universal (all
agents read; only the founder writes — agents may *propose* via the
approval queue but never auto-write).

Note on flush() vs commit()
----------------------------
All mutating helpers use ``db.session.flush()`` instead of
``db.session.commit()``.  In a Flask request context both behave the
same for callers (the row gets a PK and is visible within the session),
but ``flush()`` stays inside the current transaction so:

1. Test isolation — the ``db_session`` fixture wraps each test in a
   SAVEPOINT-backed transaction and rolls it back afterwards.  A bare
   ``commit()`` would commit the *outer* transaction, leaking data
   between tests.
2. Request-level atomicity — callers (routes, skills) own the commit
   boundary.  A helper that commits mid-request silently breaks any
   multi-step write that relies on all-or-nothing rollback on error.

Production callers (routes) already commit via Flask-SQLAlchemy's
after-request teardown or an explicit ``db.session.commit()`` at the
end of the route handler.
"""
from __future__ import annotations

from datetime import datetime
from typing import Iterable

from sqlalchemy import or_, cast
from sqlalchemy.dialects.postgresql import JSONB

from app.extensions import db
from app.models import AgentMemory, TeamMemory, now_utc


def write_memory(
    agent_id: str,
    key: str,
    value: dict,
    tags: Iterable[str],
    source: str,
    confidence: float = 1.00,
    expires_at: datetime | None = None,
) -> AgentMemory:
    """Upsert a memory entry for *agent_id*.

    If a row with the same ``(agent_id, key)`` already exists it is
    updated in-place; otherwise a new row is inserted.

    This is a direct write — it bypasses the approval queue.  Use only
    for the founder's manual seeds and runtime-authorised writes.
    Agent-proposed writes go through
    ``app.agents.approvals.propose_memory_write`` instead.
    """
    existing = (
        AgentMemory.query
        .filter_by(agent_id=agent_id, key=key)
        .first()
    )
    if existing:
        existing.value = value
        existing.tags = list(tags)
        existing.source = source
        existing.confidence = confidence
        existing.updated_at = now_utc()
        existing.expires_at = expires_at
        db.session.flush()
        return existing

    m = AgentMemory(
        agent_id=agent_id,
        key=key,
        value=value,
        tags=list(tags),
        source=source,
        confidence=confidence,
        expires_at=expires_at,
    )
    db.session.add(m)
    db.session.flush()
    return m


def write_team_memory(
    key: str,
    value: dict,
    tags: Iterable[str],
) -> TeamMemory:
    """Upsert a universal fact visible to every agent.

    Only the founder agent (or a human admin) should call this directly.
    Other agents must go through the approval queue.
    """
    existing = TeamMemory.query.filter_by(key=key).first()
    if existing:
        existing.value = value
        existing.tags = list(tags)
        existing.updated_at = now_utc()
        db.session.flush()
        return existing

    m = TeamMemory(key=key, value=value, tags=list(tags))
    db.session.add(m)
    db.session.flush()
    return m


def retrieve_for_agent(
    agent_id: str,
    tags: Iterable[str] | None = None,
    top_n: int = 30,
) -> list[AgentMemory]:
    """Return at most *top_n* of this agent's non-expired memories, most
    recent first.

    If *tags* is provided, only memories whose ``tags`` array intersects
    with the requested set are returned (OR semantics — any match
    qualifies).
    """
    q = AgentMemory.query.filter(AgentMemory.agent_id == agent_id)

    # Exclude expired entries.
    q = q.filter(
        or_(
            AgentMemory.expires_at.is_(None),
            AgentMemory.expires_at > now_utc(),
        )
    )

    if tags:
        tag_list = list(tags)
        # PostgreSQL JSONB containment: does the stored array contain the
        # single-element array [t]?  This is the idiomatic way to check
        # whether a JSONB array includes a specific scalar.
        q = q.filter(
            or_(*[
                cast(AgentMemory.tags, JSONB).contains(cast([t], JSONB))
                for t in tag_list
            ])
        )

    q = q.order_by(
        AgentMemory.updated_at.desc(),
        AgentMemory.confidence.desc(),
    )
    return q.limit(top_n).all()


def retrieve_team_memory() -> list[TeamMemory]:
    """Return all team-memory entries, most recently updated first."""
    return (
        TeamMemory.query
        .order_by(TeamMemory.updated_at.desc())
        .all()
    )
