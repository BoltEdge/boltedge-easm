"""read_internal_api tool — agents call /api/internal/* endpoints via HTTPS.

Calls go through the network layer (not direct DB access) so they appear
in audit_log with the agent's identity, matching the seam the Phase 1
spec established.
"""
from __future__ import annotations
import os

import requests

from . import ToolDef, register_tool


ALLOWED_ENDPOINTS = {
    "stats/weekly",
    "findings/recent",
    "contact-requests/recent",
    "audit-log/recent",
    "scans/recent",
}

TIMEOUT_SECONDS = 10


def read_internal_api_handler(endpoint: str, params: dict | None = None) -> str:
    """Issues a GET against /api/internal/<endpoint>. Uses the founder-ops
    bearer key (NANOEASM_API_KEY_AGENTS_FOUNDER_OPS) by default — Phase 2A
    has one shared key per agent platform. Phase 2B will route per-agent
    keys."""
    if endpoint not in ALLOWED_ENDPOINTS:
        return (f"[unknown endpoint '{endpoint}'. Allowed: "
                f"{', '.join(sorted(ALLOWED_ENDPOINTS))}]")

    base = os.environ.get("INTERNAL_API_BASE", "http://easm-backend:5000")
    key = os.environ.get("NANOEASM_API_KEY_AGENTS_FOUNDER_OPS", "")
    if not key:
        return "[NANOEASM_API_KEY_AGENTS_FOUNDER_OPS env var is not set]"

    url = f"{base.rstrip('/')}/api/internal/{endpoint}"
    try:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {key}"},
            params=params or {},
            timeout=TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        return resp.text
    except requests.exceptions.HTTPError as e:
        status = getattr(e.response, "status_code", "?")
        body = (e.response.text or "")[:500] if e.response is not None else ""
        return f"[HTTP {status} from /api/internal/{endpoint}: {body}]"
    except requests.exceptions.RequestException as e:
        return f"[request failed: {type(e).__name__}: {e}]"


register_tool(ToolDef(
    name="read_internal_api",
    description=(
        "Call Nano EASM's read-only internal API. Allowed endpoints: "
        "'stats/weekly' (org count, signups, scans, plan mix for last 7d), "
        "'findings/recent' (recent vulnerability findings — accepts severity, "
        "since, limit params), 'contact-requests/recent' (trial requests, "
        "sales enquiries), 'audit-log/recent' (recent platform audit events — "
        "accepts category, since, limit), 'scans/recent' (recent scan jobs). "
        "Returns a JSON string."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "endpoint": {
                "type": "string",
                "enum": sorted(ALLOWED_ENDPOINTS),
                "description": "Which internal endpoint to call.",
            },
            "params": {
                "type": "object",
                "description": "Optional query string parameters.",
                "additionalProperties": True,
            },
        },
        "required": ["endpoint"],
    },
    handler=read_internal_api_handler,
    idempotent=True,
    result_cap_bytes=50_000,
))
