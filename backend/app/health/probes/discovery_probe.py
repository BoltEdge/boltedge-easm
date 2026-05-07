"""
Discovery-module probes.

Most discovery sources are public HTTP scrapers — we don't ping the
upstream because (a) burns rate-limit budget and (b) the modules
already retry/fall back internally. Probe checks:

  - Module imports + instantiates.
  - `is_available()` returns True (the module's own readiness
    self-report — eg shodan_search returns False when no key).
  - For API-keyed sources (Shodan), we mark degraded if the key is
    missing rather than blocking.

Upstream-reachability checks live in the external_api probe instead,
where they belong.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List

from app.health.framework import HealthResult, HealthStatus

logger = logging.getLogger(__name__)


# Modules whose health is gated on an env var being set. Empty string =
# module is import-only, no key gate.
_MODULE_API_KEY: Dict[str, str] = {
    "shodan_search": "SHODAN_API_KEY",
}


def run() -> List[HealthResult]:
    results: List[HealthResult] = []

    try:
        from app.discovery.modules import REGISTRY
    except Exception as e:
        return [HealthResult(
            name="discovery_registry",
            kind="discovery",
            status=HealthStatus.DOWN,
            message=f"Cannot import discovery registry: {e}",
        )]

    for cls in REGISTRY:
        started = time.monotonic()
        try:
            instance = cls()
        except Exception as e:
            results.append(HealthResult(
                name=getattr(cls, "name", cls.__name__),
                kind="discovery",
                status=HealthStatus.DOWN,
                message=f"Cannot instantiate: {type(e).__name__}: {e}",
                duration_ms=int((time.monotonic() - started) * 1000),
            ))
            continue

        name = instance.name or cls.__name__.lower()
        md: Dict[str, Any] = {
            "moduleType": getattr(instance.module_type, "value", str(instance.module_type)),
            "minPlan": instance.min_plan,
            "requiresApiKey": instance.requires_api_key,
        }

        # Check for required env var, if any.
        env_var = _MODULE_API_KEY.get(name)
        if env_var and not os.getenv(env_var, "").strip():
            md["missingEnvVar"] = env_var
            results.append(HealthResult(
                name=name,
                kind="discovery",
                status=HealthStatus.DEGRADED,
                message=f"{env_var} not set — module disabled",
                duration_ms=int((time.monotonic() - started) * 1000),
                metadata=md,
            ))
            continue

        try:
            available = bool(instance.is_available())
        except Exception as e:
            results.append(HealthResult(
                name=name,
                kind="discovery",
                status=HealthStatus.DOWN,
                message=f"is_available() raised: {e}",
                duration_ms=int((time.monotonic() - started) * 1000),
                metadata=md,
            ))
            continue

        # Pull rate-limit hint if the module exposes one.
        try:
            rate = instance.get_rate_limit_status() or {}
            if rate.get("remaining") is not None:
                md["rateLimitRemaining"] = rate.get("remaining")
                md["rateLimitTotal"] = rate.get("limit")
        except Exception:
            pass

        elapsed_ms = int((time.monotonic() - started) * 1000)

        if not available:
            results.append(HealthResult(
                name=name,
                kind="discovery",
                status=HealthStatus.DEGRADED,
                message="is_available() returned False",
                duration_ms=elapsed_ms,
                metadata=md,
            ))
        else:
            results.append(HealthResult(
                name=name,
                kind="discovery",
                status=HealthStatus.HEALTHY,
                message="Available",
                duration_ms=elapsed_ms,
                metadata=md,
            ))

    return results
