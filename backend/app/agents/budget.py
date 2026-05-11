"""Per-agent monthly cost caps. Enforced before every Anthropic call."""
from __future__ import annotations
from datetime import datetime
from decimal import Decimal

from sqlalchemy import func

from app.extensions import db
from app.models import AgentRun, now_utc


def _month_start(t: datetime) -> datetime:
    return t.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def current_month_spend(agent_id: str) -> Decimal:
    start = _month_start(now_utc())
    total = (
        db.session.query(func.coalesce(func.sum(AgentRun.cost_usd), 0))
        .filter(AgentRun.agent_id == agent_id)
        .filter(AgentRun.started_at >= start)
        .scalar()
    )
    return Decimal(str(total))


def check_within_cap(agent_id: str, monthly_cap_usd: int) -> None:
    """Raises RuntimeError('over_budget: ...') if over the cap.
    Returns None if within. Call this before starting a new run."""
    spend = current_month_spend(agent_id)
    if spend >= monthly_cap_usd:
        raise RuntimeError(
            f"over_budget: {agent_id} has spent ${spend:.2f} this month, "
            f"monthly cap is ${monthly_cap_usd}"
        )
