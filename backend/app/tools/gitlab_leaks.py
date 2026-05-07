# app/tools/gitlab_leaks.py
"""
GitLab Code Search Leak Scanner.

Mirror of github_leaks.py but for GitLab.com's public code search API.
Searches public projects on GitLab for exposed secrets, API keys,
credentials, and sensitive files associated with a domain.

GitLab API specifics:
  - Endpoint:  GET /api/v4/search?scope=blobs&search=<query>
  - Auth:      NOT required for public-project blob search, but
               unauthenticated requests share a punitive global pool.
               With a personal access token (read_api scope), the
               per-token rate limit is ~2,000 requests/min — generous.
  - Pagination: Link header (RFC 5988); we fetch the first page only
               for each query to keep latency bounded.
  - Token env: GITLAB_TOKEN (optional)

Pattern set is intentionally a subset of GitHub's — GitLab's index is
smaller, so over-querying just burns rate limit without finding new
leaks. The per-query response is fed through the shared
`secret_patterns.detect_secrets()` detector to upgrade keyword hits
to high-confidence pattern matches when the snippet contains an
actual recognisable secret format.

Public mode:  summary only (counts, query suggestions)
Full mode:    all details including matched files and snippets
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from app.tools.secret_patterns import detect_secrets

logger = logging.getLogger(__name__)

GITLAB_API = "https://gitlab.com/api/v4"


# ─────────────────────────────────────────────────────────────────────────────
# Search patterns — keep narrower than github_leaks so we don't burn
# rate-limit budget on duplicate/zero-result queries.
# ─────────────────────────────────────────────────────────────────────────────

GITLAB_SEARCH_PATTERNS: List[Dict[str, Any]] = [
    {
        "query": '"{domain}" password',
        "category": "credentials",
        "severity": "critical",
        "title": "Passwords referencing domain on GitLab",
        "description": "Public GitLab code containing passwords associated with this domain.",
    },
    {
        "query": '"{domain}" api_key',
        "category": "api_key",
        "severity": "critical",
        "title": "API keys referencing domain on GitLab",
        "description": "Public GitLab code containing API keys for this domain.",
    },
    {
        "query": '"{domain}" secret',
        "category": "secrets",
        "severity": "high",
        "title": "Secrets referencing domain on GitLab",
        "description": "Public GitLab code containing secrets associated with this domain.",
    },
    {
        "query": '"{domain}" token',
        "category": "api_key",
        "severity": "high",
        "title": "Tokens referencing domain on GitLab",
        "description": "Public GitLab code containing authentication tokens for this domain.",
    },
    {
        "query": '"{domain}" AWS_SECRET_ACCESS_KEY',
        "category": "cloud_creds",
        "severity": "critical",
        "title": "AWS credentials referencing domain on GitLab",
        "description": "Public GitLab code containing AWS secret access keys associated with this domain.",
    },
    {
        "query": '"{domain}" DB_PASSWORD',
        "category": "credentials",
        "severity": "critical",
        "title": "Database passwords for domain on GitLab",
        "description": "Public GitLab code containing database passwords associated with this domain.",
    },
    {
        "query": '"{domain}" filename:.env',
        "category": "env_file",
        "severity": "high",
        "title": "Environment files mentioning domain on GitLab",
        "description": "Public GitLab .env files referencing this domain.",
    },
    {
        "query": '"{domain}" filename:config',
        "category": "config",
        "severity": "medium",
        "title": "Config files mentioning domain on GitLab",
        "description": "Public GitLab configuration files referencing this domain.",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# HTTP helper
# ─────────────────────────────────────────────────────────────────────────────


def _gitlab_search(
    query: str,
    token: Optional[str] = None,
    per_page: int = 20,
    timeout: int = 10,
) -> Dict[str, Any]:
    """Hit GitLab's blob-scope search and normalise the response shape."""
    url = (
        f"{GITLAB_API}/search"
        f"?scope=blobs&search={quote(query)}&per_page={per_page}"
    )
    headers: Dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": "Nano-EASM-Leak-Scanner/1.0",
    }
    if token:
        headers["PRIVATE-TOKEN"] = token

    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
            items = json.loads(payload) if payload else []
            # GitLab returns a JSON array of blob records, not an object.
            return {
                "items": items if isinstance(items, list) else [],
                "total_count": len(items) if isinstance(items, list) else 0,
            }
    except HTTPError as e:
        if e.code == 429 or e.code == 403:
            return {"total_count": 0, "items": [], "error": "GitLab rate limit reached. Set GITLAB_TOKEN for higher limits."}
        if e.code == 401:
            return {"total_count": 0, "items": [], "error": "GitLab token invalid or insufficient scope (need read_api)."}
        return {"total_count": 0, "items": [], "error": f"GitLab HTTP {e.code}"}
    except URLError as e:
        return {"total_count": 0, "items": [], "error": f"GitLab network error: {e.reason}"}
    except json.JSONDecodeError:
        return {"total_count": 0, "items": [], "error": "GitLab returned non-JSON response"}


# ─────────────────────────────────────────────────────────────────────────────
# Per-blob enrichment with shared secret-pattern detector
# ─────────────────────────────────────────────────────────────────────────────


def _enrich_blob_with_secret_matches(blob: Dict[str, Any]) -> Dict[str, Any]:
    """Run the regex secret detectors over the blob's snippet `data`
    field. Adds a `secret_matches` key with the high-confidence hits,
    if any. Cheap — pure regex over a short snippet."""
    snippet = blob.get("data") or blob.get("content") or ""
    if not snippet:
        return blob
    matches = detect_secrets(snippet)
    if matches:
        blob["secret_matches"] = [
            {
                "pattern_id": m.pattern_id,
                "pattern_name": m.pattern_name,
                "severity": m.severity,
                "redacted": m.redacted,
            }
            for m in matches
        ]
    return blob


# ─────────────────────────────────────────────────────────────────────────────
# Public entrypoint
# ─────────────────────────────────────────────────────────────────────────────


def run_gitlab_leak_scan(
    domain: str,
    *,
    full: bool = False,
    max_searches: int = 8,
    per_query_results: int = 10,
) -> Dict[str, Any]:
    """Run the leak scan against GitLab's public blob search.

    Args:
        domain: Target domain (used to template each query).
        full:   Include matched-file detail and snippets in the
                response (callers running in lookup-tool mode set this
                to False to keep payloads small in the public UI).
        max_searches:        Cap on number of queries dispatched.
        per_query_results:   Max blobs fetched per query.

    Returns:
        ``{"totalLeaks", "searches": [...], "rateLimited", "dorks": [...]}``
        — same shape as ``github_leaks.run_github_leak_scan`` so the
        leak engine and analyzer can consume both transparently.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return {"totalLeaks": 0, "searches": [], "rateLimited": False, "dorks": []}

    token = os.environ.get("GITLAB_TOKEN")
    rate_limited = False
    searches_out: List[Dict[str, Any]] = []
    total_leaks = 0

    patterns = GITLAB_SEARCH_PATTERNS[:max_searches]

    for i, pat in enumerate(patterns):
        if i > 0:
            # Gentle pacing — even authenticated GitLab tolerates this
            # better than burst calls, and we rarely need to rush.
            time.sleep(0.5)

        query = pat["query"].replace("{domain}", domain)
        result = _gitlab_search(query, token=token, per_page=per_query_results)

        if "rate limit" in (result.get("error") or "").lower():
            rate_limited = True
            logger.info("GitLab rate limit hit on query: %s", query)
            break

        items = result.get("items") or []
        enriched_items = [_enrich_blob_with_secret_matches(b) for b in items]
        leak_count = len(enriched_items)
        total_leaks += leak_count

        entry: Dict[str, Any] = {
            "query": query,
            "category": pat["category"],
            "severity": pat["severity"],
            "title": pat["title"],
            "description": pat["description"],
            "total_count": result.get("total_count", leak_count),
            "leak_count": leak_count,
        }
        if full and enriched_items:
            entry["matches"] = [
                {
                    "project_id":  b.get("project_id"),
                    "path":        b.get("path") or b.get("filename"),
                    "ref":         b.get("ref"),
                    "startline":   b.get("startline"),
                    "snippet":     (b.get("data") or "")[:240],
                    "secret_matches": b.get("secret_matches") or [],
                }
                for b in enriched_items
            ]
        searches_out.append(entry)

    return {
        "totalLeaks": total_leaks,
        "searches": searches_out,
        "rateLimited": rate_limited,
        "tokenAvailable": bool(token),
        # Manual-investigation dorks generated by github_leaks already
        # cover Google + Censys; GitLab-specific dorks are mostly the
        # same `site:gitlab.com` queries Google itself indexes.
        "dorks": [],
    }
