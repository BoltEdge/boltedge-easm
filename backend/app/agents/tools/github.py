"""github_query tool — read-only GitHub REST API access."""
from __future__ import annotations
import os

import requests

from . import ToolDef, register_tool


GITHUB_API_BASE = "https://api.github.com"
GITHUB_QUERY_TIMEOUT_SECONDS = 10
GITHUB_QUERY_RESULT_CAP_BYTES = 50_000


def _truncate(s: str, cap_bytes: int) -> str:
    b = s.encode("utf-8")
    if len(b) <= cap_bytes:
        return s
    return b[:cap_bytes].decode("utf-8", errors="ignore") + (
        f"\n\n…[truncated at {cap_bytes} bytes]"
    )


def github_query_handler(endpoint: str, params: dict | None = None) -> str:
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        return ("[rejected: pass a relative path like "
                "'repos/OWNER/REPO/commits', not a full URL]")

    token = os.environ.get("GITHUB_TOKEN_AGENTS")
    if not token:
        return ("[GITHUB_TOKEN_AGENTS env var is not set; "
                "github_query is unavailable]")

    url = f"{GITHUB_API_BASE}/{endpoint.lstrip('/')}"
    try:
        resp = requests.get(
            url,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            params=params or {},
            timeout=GITHUB_QUERY_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        return _truncate(resp.text, GITHUB_QUERY_RESULT_CAP_BYTES)
    except requests.exceptions.HTTPError as e:
        resp = e.response
        status = resp.status_code if resp is not None else "?"
        if status == 403 and resp is not None and resp.headers.get(
            "X-RateLimit-Remaining", "1"
        ) == "0":
            reset = resp.headers.get("X-RateLimit-Reset", "?")
            return (f"[GitHub rate limit hit. Remaining: 0. "
                    f"Reset (epoch): {reset}. "
                    f"Try git_read instead, or wait until reset.]")
        body = (resp.text or "")[:500] if resp is not None else ""
        return f"[GitHub HTTP {status}: {body}]"
    except requests.exceptions.RequestException as e:
        return f"[github_query error: {type(e).__name__}: {e}]"


register_tool(ToolDef(
    name="github_query",
    description=(
        "Read-only GitHub REST API. Pass a relative endpoint path: e.g. "
        "'repos/OWNER/REPO/commits', 'repos/OWNER/REPO/pulls?state=merged', "
        "'repos/OWNER/REPO/contents/path/to/file'. Returns the JSON "
        "response as a string. Only GET; no POST/PUT/PATCH/DELETE."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "endpoint": {
                "type": "string",
                "description": "Relative endpoint path (no leading https://).",
            },
            "params": {
                "type": "object",
                "description": "Optional query string parameters.",
                "additionalProperties": True,
            },
        },
        "required": ["endpoint"],
    },
    handler=github_query_handler,
    idempotent=False,
    result_cap_bytes=GITHUB_QUERY_RESULT_CAP_BYTES,
))
