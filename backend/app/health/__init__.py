"""
Health-monitoring framework.

Three concerns live here:

  1. **Framework** (`framework.py`) — the HealthStatus enum, HealthResult
     dataclass, and the `record()` upsert helper. Probe authors return
     HealthResult; the framework persists.

  2. **Probes** (`probes/`) — one file per probe class. Each module
     exposes a `run()` callable that produces one or more HealthResults.
     Probes never raise: a thrown exception becomes a `down` result with
     the traceback in `message`.

  3. **Runner** (`runner.py`) — orchestrates probe execution, both for
     the 6-hourly background scheduler and for the `flask health
     --probe` CLI flag. Catches per-probe failures so one broken probe
     never poisons the rest.

Read paths (the `/admin/health` endpoint, the dashboard, the default
`flask health` CLI) read directly from `health_check_result` rows —
never from live probes. Probe latency must never block the dashboard.
"""

from app.health.framework import (
    HealthStatus,
    HealthResult,
    record,
    record_many,
    fetch_all,
    fetch_by_kind,
)

__all__ = [
    "HealthStatus",
    "HealthResult",
    "record",
    "record_many",
    "fetch_all",
    "fetch_by_kind",
]
