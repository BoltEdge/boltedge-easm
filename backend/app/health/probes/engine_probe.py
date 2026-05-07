"""
Scan-engine probes.

We probe each engine without modifying its module — the probe knows
what each engine needs (env var, binary on PATH, upstream API), and
runs the cheapest check that confirms "this engine could run a scan
right now".

What each probe does NOT do:
  - Run an actual scan. That'd burn API quota and take minutes per
    probe. We confirm the engine *could* run, not that a specific scan
    *would* succeed.
  - Touch the network beyond a single API metadata call (Shodan
    api.info(), GitHub /rate_limit) — keeps each probe under a few
    hundred milliseconds.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.health.framework import HealthResult, HealthStatus

logger = logging.getLogger(__name__)


def _timed(fn: Callable[[], Tuple[HealthStatus, str, Dict[str, Any]]]) -> Tuple[HealthStatus, str, Dict[str, Any], int]:
    """Run a probe callable, capture timing, never let it raise."""
    started = time.monotonic()
    try:
        status, msg, md = fn()
    except Exception as e:
        logger.exception("engine probe crashed")
        return (HealthStatus.DOWN, f"Probe crashed: {e}", {}, int((time.monotonic() - started) * 1000))
    return (status, msg, md, int((time.monotonic() - started) * 1000))


# ── Per-engine probe functions ──────────────────────────────────────

def _probe_shodan_engine() -> Tuple[HealthStatus, str, Dict[str, Any]]:
    key = os.getenv("SHODAN_API_KEY", "").strip()
    if not key:
        return (HealthStatus.DEGRADED, "SHODAN_API_KEY not set — engine inactive", {"hasKey": False})
    try:
        import shodan
    except ImportError:
        return (HealthStatus.DOWN, "shodan package not installed", {})
    try:
        api = shodan.Shodan(key)
        info = api.info()
        credits = info.get("query_credits", 0) + info.get("scan_credits", 0)
        plan = info.get("plan", "unknown")
        md = {
            "hasKey": True,
            "queryCredits": info.get("query_credits"),
            "scanCredits": info.get("scan_credits"),
            "monitoredIps": info.get("monitored_ips"),
            "plan": plan,
        }
        if credits is not None and credits < 50:
            return (HealthStatus.DEGRADED, f"Shodan: low credits ({credits}) on {plan}", md)
        return (HealthStatus.HEALTHY, f"Shodan: {credits} credits on {plan}", md)
    except Exception as e:
        return (HealthStatus.DOWN, f"Shodan API error: {e}", {"hasKey": True})


def _probe_dns_engine() -> Tuple[HealthStatus, str, Dict[str, Any]]:
    try:
        import dns.resolver  # noqa: F401
    except ImportError:
        return (HealthStatus.DEGRADED, "dnspython not installed (falls back to socket)", {})
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        resolver.timeout = 3.0
        # Use a stable, well-known domain that we don't own (avoids
        # accidentally exercising our own DNS infra).
        answers = resolver.resolve("cloudflare.com", "A")
        if not list(answers):
            return (HealthStatus.DEGRADED, "DNS resolver returned no answers", {})
        return (HealthStatus.HEALTHY, "DNS resolver OK", {})
    except Exception as e:
        return (HealthStatus.DOWN, f"DNS resolution failed: {e}", {})


def _probe_ssl_engine() -> Tuple[HealthStatus, str, Dict[str, Any]]:
    # SSL engine uses stdlib ssl — always available. Smoke-test the
    # import path only.
    try:
        from app.scanner.engines.ssl_engine import SSLEngine  # noqa: F401
        import ssl  # noqa: F401
        return (HealthStatus.HEALTHY, "stdlib ssl available", {})
    except Exception as e:
        return (HealthStatus.DOWN, f"SSL engine import failed: {e}", {})


def _probe_http_engine() -> Tuple[HealthStatus, str, Dict[str, Any]]:
    try:
        from app.scanner.engines.http_engine import HTTPEngine  # noqa: F401
        import requests  # noqa: F401
        return (HealthStatus.HEALTHY, "requests available", {})
    except ImportError as e:
        return (HealthStatus.DOWN, f"HTTP engine missing dependency: {e}", {})


def _probe_db_probe_engine() -> Tuple[HealthStatus, str, Dict[str, Any]]:
    try:
        from app.scanner.engines.db_probe_engine import DBProbeEngine  # noqa: F401
        return (HealthStatus.HEALTHY, "DB probe engine importable", {})
    except Exception as e:
        return (HealthStatus.DOWN, f"DB probe engine import failed: {e}", {})


def _probe_cloud_asset_engine() -> Tuple[HealthStatus, str, Dict[str, Any]]:
    try:
        from app.scanner.engines.cloud_asset_engine import CloudAssetEngine  # noqa: F401
        return (HealthStatus.HEALTHY, "Cloud asset engine importable", {})
    except Exception as e:
        return (HealthStatus.DOWN, f"Cloud asset engine import failed: {e}", {})


def _probe_nmap_engine() -> Tuple[HealthStatus, str, Dict[str, Any]]:
    try:
        import nmap  # noqa: F401
    except ImportError:
        return (HealthStatus.DOWN, "python-nmap package not installed", {})
    binary = shutil.which("nmap")
    if not binary:
        return (HealthStatus.DOWN, "nmap binary not on PATH", {})
    try:
        out = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=5
        )
        first_line = (out.stdout or "").split("\n", 1)[0].strip()
        return (HealthStatus.HEALTHY, first_line or "nmap available", {"binaryPath": binary})
    except Exception as e:
        return (HealthStatus.DEGRADED, f"nmap version check failed: {e}", {"binaryPath": binary})


def _probe_nuclei_engine() -> Tuple[HealthStatus, str, Dict[str, Any]]:
    binary = shutil.which("nuclei")
    if not binary:
        return (HealthStatus.DOWN, "nuclei binary not on PATH", {})
    try:
        out = subprocess.run(
            [binary, "-version"], capture_output=True, text=True, timeout=5
        )
        # Nuclei prints version to stderr, not stdout.
        text = (out.stdout or "") + (out.stderr or "")
        version = "?"
        for line in text.splitlines():
            if "Current Version" in line or line.strip().lower().startswith("v"):
                version = line.strip().rsplit(" ", 1)[-1]
                break
        return (HealthStatus.HEALTHY, f"nuclei {version}", {"binaryPath": binary, "version": version})
    except Exception as e:
        return (HealthStatus.DEGRADED, f"nuclei version check failed: {e}", {"binaryPath": binary})


def _probe_leak_engine() -> Tuple[HealthStatus, str, Dict[str, Any]]:
    has_github = bool(os.getenv("GITHUB_TOKEN", "").strip())
    has_gitlab = bool(os.getenv("GITLAB_TOKEN", "").strip())
    md = {"hasGithubToken": has_github, "hasGitlabToken": has_gitlab}
    try:
        from app.scanner.engines.leak_engine import LeakEngine  # noqa: F401
    except Exception as e:
        return (HealthStatus.DOWN, f"Leak engine import failed: {e}", md)

    # Sensitive-path scanning works without any token — engine is
    # never fully "down" purely because of missing tokens.
    if not has_github and not has_gitlab:
        return (HealthStatus.DEGRADED, "No GitHub/GitLab token — only path scanning enabled", md)
    if not has_github:
        return (HealthStatus.DEGRADED, "No GITHUB_TOKEN — GitLab + paths only", md)
    if not has_gitlab:
        return (HealthStatus.DEGRADED, "No GITLAB_TOKEN — GitHub + paths only", md)
    return (HealthStatus.HEALTHY, "Sensitive paths + GitHub + GitLab", md)


# Map: engine name (matches ALL_ENGINES key) → probe function.
_ENGINE_PROBES: Dict[str, Callable[[], Tuple[HealthStatus, str, Dict[str, Any]]]] = {
    "shodan": _probe_shodan_engine,
    "ssl": _probe_ssl_engine,
    "http": _probe_http_engine,
    "dns": _probe_dns_engine,
    "nmap": _probe_nmap_engine,
    "nuclei": _probe_nuclei_engine,
    "db_probe": _probe_db_probe_engine,
    "cloud_asset": _probe_cloud_asset_engine,
    "leak": _probe_leak_engine,
}


def run() -> List[HealthResult]:
    """Run every engine probe; emit a HealthResult for each."""
    results: List[HealthResult] = []

    # Cross-check: ALL_ENGINES is the authoritative registry; if it
    # gains an engine without a probe, surface that as `unknown` so
    # we don't silently lose visibility.
    try:
        from app.scanner.engines import ALL_ENGINES
        registered = set(ALL_ENGINES.keys())
    except Exception:
        registered = set(_ENGINE_PROBES.keys())

    for name in sorted(registered | set(_ENGINE_PROBES.keys())):
        probe = _ENGINE_PROBES.get(name)
        if probe is None:
            results.append(HealthResult(
                name=name,
                kind="engine",
                status=HealthStatus.UNKNOWN,
                message="No health probe defined for this engine",
            ))
            continue
        status, msg, md, dur = _timed(probe)
        results.append(HealthResult(
            name=name,
            kind="engine",
            status=status,
            message=msg,
            duration_ms=dur,
            metadata=md,
        ))
    return results
