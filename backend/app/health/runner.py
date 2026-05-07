"""
Probe runner — executes all probes, persists results.

Two entry points:
  - `run_periodic_probes()` — what the 6h APScheduler job calls. Runs
    every probe (engines, analyzers, discovery, external APIs), persists,
    returns a summary. Doesn't block on errors — one bad probe never
    poisons the rest.
  - `run_subset(kinds)` — for the `flask health --probe` CLI flag,
    where the user wants to refresh only one category without waiting
    for all of them.

What this runner does NOT do:
  - It does not heartbeat schedulers. Schedulers heartbeat themselves
    at the end of each cycle (see app.health.heartbeat).
  - It does not run system probes (DB pool, migration drift). Those
    are read live by /admin/health since they're cheap.
"""

from __future__ import annotations

import logging
import time
import traceback
from typing import Callable, Dict, List, Optional

from app.health.framework import HealthResult, HealthStatus, record_many

logger = logging.getLogger(__name__)


# Probe kinds the runner orchestrates. Each maps to a module that
# exposes `run() -> List[HealthResult]`.
PROBE_KINDS = ["engine", "analyzer", "discovery", "external_api"]


def _probe_runner(kind: str) -> Optional[Callable[[], List[HealthResult]]]:
    """Lazy-import the per-kind probe module so the framework can
    import without dragging every engine + every external SDK at
    Flask boot."""
    try:
        if kind == "engine":
            from app.health.probes.engine_probe import run
            return run
        if kind == "analyzer":
            from app.health.probes.analyzer_probe import run
            return run
        if kind == "discovery":
            from app.health.probes.discovery_probe import run
            return run
        if kind == "external_api":
            from app.health.probes.external_api_probe import run
            return run
    except ImportError as e:
        logger.exception("health: cannot import %s probe: %s", kind, e)
    return None


def run_periodic_probes() -> Dict[str, int]:
    """
    Called from the 6h scheduler. Runs every probe, persists results,
    returns counts by status for logging.
    """
    return run_subset(PROBE_KINDS)


def run_subset(kinds: List[str]) -> Dict[str, int]:
    """Run probes for the given kinds. Persists, returns status counts."""
    started = time.monotonic()
    all_results: List[HealthResult] = []

    for kind in kinds:
        runner = _probe_runner(kind)
        if runner is None:
            continue
        try:
            kind_started = time.monotonic()
            results = runner()
            elapsed_ms = int((time.monotonic() - kind_started) * 1000)
            logger.info(
                "health: %s probes finished in %dms (%d results)",
                kind, elapsed_ms, len(results),
            )
            all_results.extend(results)
        except Exception:
            logger.exception("health: %s probe set crashed", kind)
            # Record a synthetic "down" entry so the failure is visible
            # in the dashboard — otherwise a runner-level bug becomes
            # silent stale data.
            all_results.append(HealthResult(
                name=f"{kind}_runner",
                kind="system",
                status=HealthStatus.DOWN,
                message=f"Probe runner crashed: {traceback.format_exc()[:500]}",
            ))

    record_many(all_results)

    summary: Dict[str, int] = {
        "healthy": 0, "degraded": 0, "down": 0, "unknown": 0, "total": len(all_results)
    }
    for r in all_results:
        summary[r.status.value] = summary.get(r.status.value, 0) + 1
    summary["elapsedMs"] = int((time.monotonic() - started) * 1000)
    logger.info("health: periodic probe run summary: %s", summary)
    return summary
