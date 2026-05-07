"""
System probes — cheap checks read live by /admin/health.

These never write to health_check_result. They run in-line on every
admin-health request (or every CLI invocation). Anything expensive
(>50ms) belongs in the periodic probe runner, not here.

Probes covered:
  - DB ping + SQLAlchemy pool state.
  - Alembic migration drift (current revision vs head).
  - Scheduler heartbeats (reads from health_check_result, decides
    healthy/overdue based on SCHEDULER_INTERVALS_SECONDS).
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from app.extensions import db
from app.health.framework import HealthResult, HealthStatus, fetch_by_kind
from app.health.heartbeat import SCHEDULER_INTERVALS_SECONDS

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def db_ping() -> HealthResult:
    """Lightweight DB connectivity test + pool snapshot."""
    started = time.monotonic()
    try:
        from sqlalchemy import text
        db.session.execute(text("SELECT 1"))
        elapsed_ms = int((time.monotonic() - started) * 1000)

        try:
            engine = db.engine
            pool = engine.pool
            pool_meta: Dict[str, Any] = {
                "size": pool.size() if hasattr(pool, "size") else None,
                "checkedOut": pool.checkedout() if hasattr(pool, "checkedout") else None,
                "overflow": pool.overflow() if hasattr(pool, "overflow") else None,
                "checkedIn": pool.checkedin() if hasattr(pool, "checkedin") else None,
            }
        except Exception:
            pool_meta = {}

        # Overflow > 0 means we've exceeded pool_size and are using overflow
        # connections — usually a sign the pool is undersized for the load.
        overflow = pool_meta.get("overflow") or 0
        if overflow and overflow > 0:
            status = HealthStatus.DEGRADED
            msg = f"DB pool using {overflow} overflow connection(s)"
        else:
            status = HealthStatus.HEALTHY
            msg = f"DB ping {elapsed_ms}ms"

        return HealthResult(
            name="postgres",
            kind="system",
            status=status,
            message=msg,
            duration_ms=elapsed_ms,
            metadata=pool_meta,
        )
    except Exception as e:
        return HealthResult(
            name="postgres",
            kind="system",
            status=HealthStatus.DOWN,
            message=f"DB ping failed: {e}",
            duration_ms=int((time.monotonic() - started) * 1000),
        )


def migration_drift() -> HealthResult:
    """
    Compare alembic_version (DB state) to script head (codebase state).
    Drift = a deploy half-completed; new code is running against an
    old schema, or migrations are pending.
    """
    started = time.monotonic()
    try:
        from sqlalchemy import text
        row = db.session.execute(
            text("SELECT version_num FROM alembic_version LIMIT 1")
        ).fetchone()
        current = row[0] if row else None

        # Resolve the head revision from the migration script directory
        # without bringing up Flask-Migrate's CLI machinery.
        from alembic.config import Config
        from alembic.script import ScriptDirectory
        import os

        migrations_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "..", "migrations",
        )
        migrations_dir = os.path.abspath(migrations_dir)
        cfg = Config()
        cfg.set_main_option("script_location", migrations_dir)
        script = ScriptDirectory.from_config(cfg)
        head = script.get_current_head()

        elapsed_ms = int((time.monotonic() - started) * 1000)

        if current is None:
            return HealthResult(
                name="migrations",
                kind="system",
                status=HealthStatus.DOWN,
                message="alembic_version table is empty — DB never initialised",
                duration_ms=elapsed_ms,
                metadata={"current": None, "head": head},
            )

        if current != head:
            return HealthResult(
                name="migrations",
                kind="system",
                status=HealthStatus.DOWN,
                message=f"DB at {current[:8]}, code at {head[:8] if head else '?'} — run flask db upgrade",
                duration_ms=elapsed_ms,
                metadata={"current": current, "head": head},
            )

        return HealthResult(
            name="migrations",
            kind="system",
            status=HealthStatus.HEALTHY,
            message=f"At head ({current[:8]})",
            duration_ms=elapsed_ms,
            metadata={"current": current, "head": head},
        )
    except Exception as e:
        return HealthResult(
            name="migrations",
            kind="system",
            status=HealthStatus.UNKNOWN,
            message=f"Drift check failed: {e}",
            duration_ms=int((time.monotonic() - started) * 1000),
        )


def scheduler_status() -> List[HealthResult]:
    """
    Read scheduler heartbeats from health_check_result. Flag any
    scheduler whose last heartbeat is older than 2x its interval as
    `down` — that's the silent-crash detector.
    """
    rows = fetch_by_kind("scheduler")
    by_name = {r.name: r for r in rows}
    results: List[HealthResult] = []
    now = _now()

    for name, interval in SCHEDULER_INTERVALS_SECONDS.items():
        row = by_name.get(name)
        if row is None or row.last_checked_at is None:
            results.append(HealthResult(
                name=name,
                kind="scheduler",
                status=HealthStatus.UNKNOWN,
                message="No heartbeat recorded yet",
                metadata={"intervalSeconds": interval},
            ))
            continue

        age_seconds = int((now - row.last_checked_at).total_seconds())
        threshold = max(interval * 2, 120)  # at least 2 min grace

        md = dict(row.check_metadata or {})
        md["intervalSeconds"] = interval
        md["lastHeartbeatAgeSeconds"] = age_seconds

        if age_seconds > threshold:
            results.append(HealthResult(
                name=name,
                kind="scheduler",
                status=HealthStatus.DOWN,
                message=f"No heartbeat for {age_seconds}s (interval {interval}s)",
                metadata=md,
            ))
        else:
            # Trust the heartbeat-recorded status (it knows if the last
            # cycle errored), but never upgrade staleness to healthy.
            stored_status = row.status
            try:
                status = HealthStatus(stored_status)
            except ValueError:
                status = HealthStatus.UNKNOWN
            results.append(HealthResult(
                name=name,
                kind="scheduler",
                status=status,
                message=row.message or f"Last heartbeat {age_seconds}s ago",
                metadata=md,
            ))

    return results


def run_system_probes() -> List[HealthResult]:
    """All system probes — called in-line by /admin/health and CLI."""
    results: List[HealthResult] = [db_ping(), migration_drift()]
    results.extend(scheduler_status())
    return results
