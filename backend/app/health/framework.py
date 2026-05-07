"""
HealthCheck framework primitives.

Probes return HealthResult, the framework upserts into
health_check_result, dashboards & CLI read back via fetch_*().

Design notes:
  - Single row per (kind, name). New runs overwrite. We don't store
    history here — if you want trend lines later, add a sibling
    history table; this one stays small (~50 rows) and fast.
  - last_healthy_at advances only on healthy results. The UI computes
    "down for N minutes" as now - last_healthy_at when status != healthy.
  - record() / record_many() are safe under concurrent calls because
    they go through SQLAlchemy and the (kind, name) unique constraint —
    racing inserts collapse to one row, and updates are atomic.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import HealthCheckResult

logger = logging.getLogger(__name__)


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"
    UNKNOWN = "unknown"


@dataclass
class HealthResult:
    """
    Output of a single probe.

    name:        The probe's identifier within its kind. e.g. "shodan"
                 (engine), "ct_logs" (discovery), "monitor_scheduler"
                 (scheduler).
    kind:        engine | analyzer | discovery | scheduler |
                 external_api | system.
    status:      HealthStatus.
    message:     Short human-readable summary. Goes into the dashboard
                 tooltip and CLI output. Keep < 200 chars.
    duration_ms: How long the probe took. Useful for spotting slow
                 upstream APIs even when they're "healthy".
    metadata:    Probe-specific data: shodan credits remaining,
                 nuclei version, github rate-limit reset epoch, etc.
    """
    name: str
    kind: str
    status: HealthStatus = HealthStatus.UNKNOWN
    message: str = ""
    duration_ms: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def record(result: HealthResult) -> None:
    """
    Upsert a single probe result. Caller is responsible for the
    surrounding session/commit — we add+flush, the caller commits.
    """
    row = (
        HealthCheckResult.query
        .filter_by(kind=result.kind, name=result.name)
        .first()
    )
    now = _now()
    is_healthy = result.status == HealthStatus.HEALTHY

    if row is None:
        row = HealthCheckResult(
            kind=result.kind,
            name=result.name,
            status=result.status.value,
            message=result.message[:8000] if result.message else None,
            check_metadata=result.metadata or None,
            duration_ms=result.duration_ms,
            last_checked_at=now,
            last_healthy_at=now if is_healthy else None,
        )
        db.session.add(row)
        try:
            db.session.flush()
        except IntegrityError:
            # Concurrent insert won — re-read and update instead.
            db.session.rollback()
            row = (
                HealthCheckResult.query
                .filter_by(kind=result.kind, name=result.name)
                .first()
            )
            if row is None:
                # Vanishingly unlikely, just log and move on.
                logger.warning(
                    "health: lost race twice on (%s, %s)", result.kind, result.name
                )
                return
            _update(row, result, now, is_healthy)
    else:
        _update(row, result, now, is_healthy)


def _update(row: HealthCheckResult, result: HealthResult, now: datetime, is_healthy: bool) -> None:
    row.status = result.status.value
    row.message = result.message[:8000] if result.message else None
    row.check_metadata = result.metadata or None
    row.duration_ms = result.duration_ms
    row.last_checked_at = now
    if is_healthy:
        row.last_healthy_at = now


def record_many(results: List[HealthResult]) -> None:
    """Convenience: record a batch in one transaction."""
    for r in results:
        record(r)
    db.session.commit()


def fetch_all() -> List[HealthCheckResult]:
    return HealthCheckResult.query.order_by(
        HealthCheckResult.kind.asc(),
        HealthCheckResult.name.asc(),
    ).all()


def fetch_by_kind(kind: str) -> List[HealthCheckResult]:
    return (
        HealthCheckResult.query
        .filter_by(kind=kind)
        .order_by(HealthCheckResult.name.asc())
        .all()
    )


def serialize(row: HealthCheckResult) -> Dict[str, Any]:
    """Standard dict shape for /admin/health and CLI --json output."""
    last_healthy = row.last_healthy_at.isoformat() if row.last_healthy_at else None
    return {
        "kind": row.kind,
        "name": row.name,
        "status": row.status,
        "message": row.message,
        "metadata": row.check_metadata or {},
        "durationMs": row.duration_ms,
        "lastCheckedAt": row.last_checked_at.isoformat() if row.last_checked_at else None,
        "lastHealthyAt": last_healthy,
    }
