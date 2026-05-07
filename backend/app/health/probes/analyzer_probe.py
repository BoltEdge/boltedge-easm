"""
Analyzer probes.

Analyzers don't talk to anything external — they consume engine output
and emit FindingDrafts. The only failure modes are:
  - Module import broken (syntax error after refactor, missing
    optional dep, circular import).
  - Class instantiation broken.

So each probe is just an import + instantiate test. Cheap; no reason
to skip any of the 13.
"""

from __future__ import annotations

import logging
import time
from typing import List

from app.health.framework import HealthResult, HealthStatus

logger = logging.getLogger(__name__)


def run() -> List[HealthResult]:
    results: List[HealthResult] = []

    try:
        from app.scanner.analyzers import ALL_ANALYZERS
    except Exception as e:
        return [HealthResult(
            name="analyzer_registry",
            kind="analyzer",
            status=HealthStatus.DOWN,
            message=f"Cannot import analyzer registry: {e}",
        )]

    for name, cls in ALL_ANALYZERS.items():
        started = time.monotonic()
        try:
            instance = cls()
            # Touch the abstract `name` property to make sure subclasses
            # implement it.
            _ = instance.name
            elapsed_ms = int((time.monotonic() - started) * 1000)
            results.append(HealthResult(
                name=name,
                kind="analyzer",
                status=HealthStatus.HEALTHY,
                message="Importable + instantiable",
                duration_ms=elapsed_ms,
            ))
        except Exception as e:
            results.append(HealthResult(
                name=name,
                kind="analyzer",
                status=HealthStatus.DOWN,
                message=f"{type(e).__name__}: {e}",
                duration_ms=int((time.monotonic() - started) * 1000),
            ))

    return results
