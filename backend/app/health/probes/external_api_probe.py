"""
External-API probes.

Cheapest possible round-trip per upstream — we want to know "is the
key valid + service reachable", not exercise scan-side functionality.

  - Shodan         api.info() — returns plan + credits in one call.
  - GitHub         /rate_limit — token-validating, doesn't consume rate.
  - GitLab         /api/v4/user — token-validating.
  - Resend         /domains — verifies key + lists configured domains.
  - Stripe         Account.retrieve() — only when ENABLE_BILLING=true.
  - Anthropic      /v1/messages with 1 token — only if ANTHROPIC_API_KEY set.

Probes that find a missing API key return DEGRADED, not DOWN — a
service we never configured isn't "down", it just isn't enabled.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Callable, Dict, List, Tuple

from app.health.framework import HealthResult, HealthStatus

logger = logging.getLogger(__name__)


def _timed_call(fn: Callable[[], Tuple[HealthStatus, str, Dict[str, Any]]]) -> Tuple[HealthStatus, str, Dict[str, Any], int]:
    started = time.monotonic()
    try:
        s, m, md = fn()
    except Exception as e:
        logger.exception("external_api probe crashed")
        return (HealthStatus.DOWN, f"Probe crashed: {e}", {}, int((time.monotonic() - started) * 1000))
    return (s, m, md, int((time.monotonic() - started) * 1000))


def _probe_shodan() -> Tuple[HealthStatus, str, Dict[str, Any]]:
    key = os.getenv("SHODAN_API_KEY", "").strip()
    if not key:
        return (HealthStatus.DEGRADED, "SHODAN_API_KEY not set", {"hasKey": False})
    try:
        import shodan
        info = shodan.Shodan(key).info()
        credits = (info.get("query_credits") or 0) + (info.get("scan_credits") or 0)
        md = {
            "hasKey": True,
            "plan": info.get("plan"),
            "queryCredits": info.get("query_credits"),
            "scanCredits": info.get("scan_credits"),
            "monitoredIps": info.get("monitored_ips"),
        }
        if credits is not None and credits < 50:
            return (HealthStatus.DEGRADED, f"Low credits: {credits}", md)
        return (HealthStatus.HEALTHY, f"OK ({credits} credits)", md)
    except Exception as e:
        return (HealthStatus.DOWN, f"Shodan API error: {e}", {"hasKey": True})


def _probe_github() -> Tuple[HealthStatus, str, Dict[str, Any]]:
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        return (HealthStatus.DEGRADED, "GITHUB_TOKEN not set — leak engine GitHub search disabled", {"hasKey": False})
    import requests
    r = requests.get(
        "https://api.github.com/rate_limit",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=5,
    )
    if r.status_code == 401:
        return (HealthStatus.DOWN, "GITHUB_TOKEN rejected (401) — invalid or revoked", {"hasKey": True})
    if r.status_code != 200:
        return (HealthStatus.DOWN, f"GitHub /rate_limit returned {r.status_code}", {"hasKey": True})
    data = r.json()
    search = (data.get("resources") or {}).get("search") or {}
    core = (data.get("resources") or {}).get("core") or {}
    md = {
        "hasKey": True,
        "searchRemaining": search.get("remaining"),
        "searchLimit": search.get("limit"),
        "coreRemaining": core.get("remaining"),
        "coreLimit": core.get("limit"),
    }
    # Code-search is the leak engine's bottleneck.
    if search.get("remaining") is not None and search.get("remaining") < 5:
        return (HealthStatus.DEGRADED, f"GitHub search rate-limit low ({search.get('remaining')}/{search.get('limit')})", md)
    return (HealthStatus.HEALTHY, f"GitHub OK (search {search.get('remaining')}/{search.get('limit')})", md)


def _probe_gitlab() -> Tuple[HealthStatus, str, Dict[str, Any]]:
    token = os.getenv("GITLAB_TOKEN", "").strip()
    if not token:
        return (HealthStatus.DEGRADED, "GITLAB_TOKEN not set — leak engine GitLab search disabled", {"hasKey": False})
    import requests
    r = requests.get(
        "https://gitlab.com/api/v4/user",
        headers={"PRIVATE-TOKEN": token},
        timeout=5,
    )
    if r.status_code == 401:
        return (HealthStatus.DOWN, "GITLAB_TOKEN rejected (401)", {"hasKey": True})
    if r.status_code != 200:
        return (HealthStatus.DOWN, f"GitLab /user returned {r.status_code}", {"hasKey": True})
    data = r.json()
    md = {
        "hasKey": True,
        "username": data.get("username"),
        "scopes": r.headers.get("x-gitlab-meta"),
    }
    return (HealthStatus.HEALTHY, f"GitLab OK (user {data.get('username')})", md)


def _probe_resend() -> Tuple[HealthStatus, str, Dict[str, Any]]:
    key = os.getenv("RESEND_API_KEY", "").strip()
    if not key:
        return (HealthStatus.DEGRADED, "RESEND_API_KEY not set — emails will be skipped", {"hasKey": False})
    import requests
    r = requests.get(
        "https://api.resend.com/domains",
        headers={"Authorization": f"Bearer {key}"},
        timeout=5,
    )
    if r.status_code == 401:
        return (HealthStatus.DOWN, "RESEND_API_KEY rejected (401)", {"hasKey": True})
    if r.status_code != 200:
        return (HealthStatus.DOWN, f"Resend /domains returned {r.status_code}", {"hasKey": True})
    body = r.json() or {}
    domains = body.get("data") or body.get("domains") or []
    verified = [d for d in domains if (d.get("status") or "").lower() == "verified"]
    md = {
        "hasKey": True,
        "domainCount": len(domains),
        "verifiedDomainCount": len(verified),
    }
    if not verified:
        return (HealthStatus.DEGRADED, "No verified domains in Resend", md)
    return (HealthStatus.HEALTHY, f"Resend OK ({len(verified)} verified domain(s))", md)


def _probe_stripe() -> Tuple[HealthStatus, str, Dict[str, Any]]:
    enable_billing = os.getenv("ENABLE_BILLING", "false").lower() == "true"
    if not enable_billing:
        return (HealthStatus.HEALTHY, "Billing disabled — Stripe probe skipped", {"enabled": False})
    key = os.getenv("STRIPE_SECRET_KEY", "").strip()
    if not key:
        return (HealthStatus.DOWN, "ENABLE_BILLING=true but STRIPE_SECRET_KEY not set", {"enabled": True})
    try:
        import stripe
        stripe.api_key = key
        account = stripe.Account.retrieve()
        md = {
            "enabled": True,
            "accountId": account.get("id"),
            "country": account.get("country"),
            "chargesEnabled": account.get("charges_enabled"),
        }
        return (HealthStatus.HEALTHY, "Stripe account reachable", md)
    except Exception as e:
        return (HealthStatus.DOWN, f"Stripe API error: {e}", {"enabled": True})


def _probe_anthropic() -> Tuple[HealthStatus, str, Dict[str, Any]]:
    key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not key:
        return (HealthStatus.DEGRADED, "ANTHROPIC_API_KEY not set — assistant disabled", {"hasKey": False})
    import requests
    # Cheapest possible call: list models.
    r = requests.get(
        "https://api.anthropic.com/v1/models",
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        },
        timeout=5,
    )
    if r.status_code == 401:
        return (HealthStatus.DOWN, "ANTHROPIC_API_KEY rejected (401)", {"hasKey": True})
    if r.status_code != 200:
        return (HealthStatus.DOWN, f"Anthropic /models returned {r.status_code}", {"hasKey": True})
    return (HealthStatus.HEALTHY, "Anthropic OK", {"hasKey": True})


_PROBES: Dict[str, Callable[[], Tuple[HealthStatus, str, Dict[str, Any]]]] = {
    "shodan": _probe_shodan,
    "github": _probe_github,
    "gitlab": _probe_gitlab,
    "resend": _probe_resend,
    "stripe": _probe_stripe,
    "anthropic": _probe_anthropic,
}


def run() -> List[HealthResult]:
    results: List[HealthResult] = []
    for name, probe in _PROBES.items():
        status, msg, md, dur = _timed_call(probe)
        results.append(HealthResult(
            name=name,
            kind="external_api",
            status=status,
            message=msg,
            duration_ms=dur,
            metadata=md,
        ))
    return results
