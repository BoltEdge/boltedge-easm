"""
Scheduler heartbeats.

Each APScheduler job calls heartbeat() at the END of every cycle —
after the work succeeds (or fails). The /admin/health endpoint and
flask health CLI flag a scheduler as `down` if its last heartbeat is
older than 2x its expected interval.

This is a separate concern from `runner.py` because schedulers know
their own state better than an external prober ever could (e.g. "did
this cycle do any work, or was the queue empty"). We just record what
they tell us.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.health.framework import HealthResult, HealthStatus, record
from app.extensions import db

logger = logging.getLogger(__name__)


# Expected interval for each scheduler — used by the read path
# (/admin/health) to decide if a heartbeat is "overdue". Stored here
# so a UI bug or a scheduler-rename can't mask a stuck job.
SCHEDULER_INTERVALS_SECONDS: Dict[str, int] = {
    "scan_schedule": 60,
    "monitor_scheduler": 60,
    "trial_expiry": 3600,
    "health_probes": 6 * 3600,
}


def heartbeat(
    scheduler_name: str,
    *,
    success: bool = True,
    message: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Record a scheduler cycle. `success=False` flips the status to
    `degraded` (one failure, scheduler still alive) — only the read
    path turns this into `down` based on staleness, since a missed
    cycle is qualitatively different from a failed cycle.
    """
    interval = SCHEDULER_INTERVALS_SECONDS.get(scheduler_name)
    md: Dict[str, Any] = dict(metadata or {})
    if interval is not None:
        md["intervalSeconds"] = interval

    status = HealthStatus.HEALTHY if success else HealthStatus.DEGRADED

    try:
        record(HealthResult(
            name=scheduler_name,
            kind="scheduler",
            status=status,
            message=message[:500] if message else "",
            metadata=md,
        ))
        db.session.commit()
    except Exception:
        # Heartbeats are best-effort. Never let the framework break a
        # scheduler that was about to do real work.
        logger.exception("health: heartbeat for %s failed", scheduler_name)
        try:
            db.session.rollback()
        except Exception:
            pass
