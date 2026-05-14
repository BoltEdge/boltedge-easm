# app/tools/github_leaks.py
"""
GitHub Code Search Leak Scanner.

Searches GitHub's public code search API for exposed secrets,
API keys, credentials, and sensitive files associated with a domain.

Uses GitHub's code search API (requires GITHUB_TOKEN env var for
higher rate limits, but works without for limited searches).

Also generates Google dork queries for manual follow-up.

Public mode:  summary only (counts, dork suggestions)
Full mode:    all details including matched files and snippets
"""

from __future__ import annotations

import logging
import os
import re
import time
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import json

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Search patterns
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

GITHUB_SEARCH_PATTERNS: List[Dict[str, Any]] = [
    {
        "query": '"{domain}" password',
        "category": "credentials",
        "severity": "critical",
        "title": "Passwords referencing domain",
        "description": "Code containing passwords associated with this domain.",
    },
    {
        "query": '"{domain}" api_key',
        "category": "api_key",
        "severity": "critical",
        "title": "API keys referencing domain",
        "description": "Code containing API keys for this domain.",
    },
    {
        "query": '"{domain}" secret_key',
        "category": "api_key",
        "severity": "critical",
        "title": "Secret keys referencing domain",
        "description": "Code containing secret keys associated with this domain.",
    },
    {
        "query": '"{domain}" token',
        "category": "api_key",
        "severity": "high",
        "title": "Tokens referencing domain",
        "description": "Code containing authentication tokens for this domain.",
    },
    {
        "query": '"{domain}" DB_PASSWORD',
        "category": "credentials",
        "severity": "critical",
        "title": "Database passwords for domain",
        "description": "Code containing database passwords associated with this domain.",
    },
    {
        "query": '"{domain}" AWS_SECRET_ACCESS_KEY',
        "category": "cloud_creds",
        "severity": "critical",
        "title": "AWS credentials referencing domain",
        "description": "Code containing AWS secret access keys associated with this domain.",
    },
    {
        "query": '"{domain}" PRIVATE KEY',
        "category": "secrets",
        "severity": "critical",
        "title": "Private keys referencing domain",
        "description": "Code containing private keys associated with this domain.",
    },
    {
        "query": '"{domain}" filename:.env',
        "category": "env_file",
        "severity": "critical",
        "title": ".env files referencing domain",
        "description": "Environment files containing references to this domain.",
    },
    {
        "query": '"{domain}" filename:credentials',
        "category": "credentials",
        "severity": "high",
        "title": "Credential files referencing domain",
        "description": "Credential configuration files for this domain.",
    },
    {
        "query": '"{domain}" filename:config',
        "category": "config",
        "severity": "medium",
        "title": "Config files referencing domain",
        "description": "Configuration files containing references to this domain.",
    },
    {
        "query": '"{domain}" smtp',
        "category": "credentials",
        "severity": "high",
        "title": "SMTP configuration for domain",
        "description": "Code containing SMTP/email configuration for this domain.",
    },
    {
        "query": '"{domain}" jdbc:',
        "category": "credentials",
        "severity": "critical",
        "title": "JDBC connection strings for domain",
        "description": "Database connection strings referencing this domain.",
    },
]

# Google dork queries for manual investigation
GOOGLE_DORKS: List[Dict[str, str]] = [
    {
        "query": 'site:github.com "{domain}" password',
        "title": "GitHub: passwords",
        "description": "Search GitHub for password references to this domain.",
    },
    {
        "query": 'site:github.com "{domain}" filename:.env',
        "title": "GitHub: .env files",
        "description": "Search GitHub for .env files referencing this domain.",
    },
    {
        "query": 'site:gitlab.com "{domain}" password OR secret',
        "title": "GitLab: secrets",
        "description": "Search GitLab for secrets referencing this domain.",
    },
    {
        "query": 'site:pastebin.com "{domain}"',
        "title": "Pastebin: domain mentions",
        "description": "Search Pastebin for pastes mentioning this domain.",
    },
    {
        "query": '"{domain}" filetype:sql',
        "title": "SQL dumps",
        "description": "Search for SQL dumps containing this domain.",
    },
    {
        "query": '"{domain}" filetype:log',
        "title": "Log files",
        "description": "Search for log files mentioning this domain.",
    },
    {
        "query": 'site:trello.com "{domain}"',
        "title": "Trello: domain mentions",
        "description": "Search Trello boards mentioning this domain.",
    },
    {
        "query": '"{domain}" inurl:swagger',
        "title": "Exposed Swagger docs",
        "description": "Search for Swagger/API documentation for this domain.",
    },
]


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# GitHub API search
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _github_code_search(
    query: str,
    token: Optional[str] = None,
    per_page: int = 5,
) -> Dict[str, Any]:
    """Search GitHub code API."""
    import urllib.parse

    url = f"{GITHUB_API}/search/code?q={urllib.parse.quote(query)}&per_page={per_page}"

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "NanoASM-Scanner",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        req = Request(url, headers=headers)
        resp = urlopen(req, timeout=10)
        data = json.loads(resp.read().decode("utf-8"))

        items = []
        for item in data.get("items", [])[:per_page]:
            items.append({
                "name": item.get("name", ""),
                "path": item.get("path", ""),
                "repository": item.get("repository", {}).get("full_name", ""),
                "htmlUrl": item.get("html_url", ""),
                "score": item.get("score", 0),
            })

        return {
            "total_count": data.get("total_count", 0),
            "items": items,
            "error": None,
        }
    except HTTPError as e:
        if e.code == 403:
            return {"total_count": 0, "items": [], "error": "GitHub API rate limit exceeded. Set GITHUB_TOKEN for higher limits."}
        elif e.code == 422:
            return {"total_count": 0, "items": [], "error": "GitHub search query validation failed."}
        return {"total_count": 0, "items": [], "error": f"GitHub API error: {e.code}"}
    except (URLError, OSError) as e:
        return {"total_count": 0, "items": [], "error": f"Connection error: {str(e)}"}
    except Exception as e:
        return {"total_count": 0, "items": [], "error": f"{type(e).__name__}: {str(e)}"}


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Main tool
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def run_github_leak_scan(domain: str, full: bool = True) -> dict:
    """Scan GitHub for leaked secrets associated with a domain."""
    token = os.environ.get("GITHUB_TOKEN")

    results: List[Dict[str, Any]] = []
    total_leaks = 0
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    issues: List[Dict[str, Any]] = []
    rate_limited = False

    for pattern in GITHUB_SEARCH_PATTERNS:
        query = pattern["query"].replace("{domain}", domain)

        search_result = _github_code_search(query, token=token)

        if search_result.get("error") and "rate limit" in search_result["error"].lower():
            rate_limited = True
            break

        count = search_result["total_count"]

        entry: Dict[str, Any] = {
            "query": query,
            "category": pattern["category"],
            "severity": pattern["severity"],
            "title": pattern["title"],
            "description": pattern["description"],
            "totalResults": count,
        }

        if count > 0:
            total_leaks += count
            sev_counts[pattern["severity"]] = sev_counts.get(pattern["severity"], 0) + 1

            issues.append({
                "severity": pattern["severity"],
                "title": f"{pattern['title']}: {count} result(s)",
                "description": pattern["description"],
                "recommendation": "Review the GitHub results and rotate any exposed credentials immediately.",
            })

            if full and search_result["items"]:
                entry["files"] = search_result["items"]

        if search_result.get("error"):
            entry["error"] = search_result["error"]

        results.append(entry)

        if not token:
            time.sleep(6)
        else:
            time.sleep(1)

    dorks = []
    for dork in GOOGLE_DORKS:
        dorks.append({
            "query": dork["query"].replace("{domain}", domain),
            "title": dork["title"],
            "description": dork["description"],
            "searchUrl": f"https://www.google.com/search?q={dork['query'].replace('{domain}', domain).replace(' ', '+')}",
        })

    response: dict = {
        "domain": domain,
        "totalLeaks": total_leaks,
        "searchesCompleted": len(results),
        "severityCounts": sev_counts,
        "hasGitHubToken": token is not None,
        "rateLimited": rate_limited,
        "issues": issues,
        "dorks": dorks,
    }

    if full:
        response["searches"] = results


# ─────────────────────────────────────────────────────────────────────
# Issues / PRs / Commit-message search
#
# These extend the public-source coverage beyond code files. Same auth
# (GITHUB_TOKEN, same rate-limit envelope) but different endpoints:
#   /search/issues    — covers both Issues and Pull Requests
#   /search/commits   — commit messages across public repos
#
# Each helper returns the same shape as _github_code_search so the
# engine and analyzer can iterate uniformly.
# ─────────────────────────────────────────────────────────────────────

# Lightweight query set for the broader-surface searches. Fewer patterns
# than GITHUB_SEARCH_PATTERNS because issues / PR descriptions / commit
# messages have lower signal density than code, so we don't want to
# burn the rate-limit envelope on speculative queries.
GITHUB_EXTRA_PATTERNS: List[Dict[str, Any]] = [
    {
        "query": '"{domain}" password',
        "category": "credentials",
        "severity": "high",
        "title": "Credential mention",
        "description": "A public message or commit contains both your domain and the word 'password'.",
    },
    {
        "query": '"{domain}" secret',
        "category": "secrets",
        "severity": "high",
        "title": "Secret keyword mention",
        "description": "A public message or commit contains both your domain and the word 'secret'.",
    },
    {
        "query": '"{domain}" token',
        "category": "api_key",
        "severity": "high",
        "title": "Token mention",
        "description": "A public message or commit contains both your domain and the word 'token'.",
    },
    {
        "query": '"{domain}" api_key',
        "category": "api_key",
        "severity": "high",
        "title": "API key mention",
        "description": "A public message or commit contains both your domain and 'api_key'.",
    },
    {
        "query": '"{domain}" aws_access_key',
        "category": "cloud_creds",
        "severity": "critical",
        "title": "AWS key mention",
        "description": "A public message or commit contains both your domain and 'aws_access_key'.",
    },
]


def _github_issues_search(
    query: str,
    token: Optional[str] = None,
    per_page: int = 5,
) -> Dict[str, Any]:
    """Search GitHub /search/issues for issues + pull requests.

    Returns the same shape as _github_code_search but each item carries
    issue/PR-specific fields (number, type, htmlUrl, repository)."""
    import urllib.parse
    url = (
        f"{GITHUB_API}/search/issues?q={urllib.parse.quote(query)}"
        f"&per_page={per_page}"
    )
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "NanoASM-Scanner",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        resp = urlopen(Request(url, headers=headers), timeout=10)
        data = json.loads(resp.read().decode("utf-8"))
        items = []
        for it in data.get("items", [])[:per_page]:
            # GitHub returns PRs through this endpoint too; pull_request
            # presence is the canonical PR signal.
            is_pr = "pull_request" in it
            # Repository name is encoded in the html_url path.
            repo = ""
            html_url = it.get("html_url") or ""
            if html_url:
                m = re.search(r"github\.com/([^/]+/[^/]+)/", html_url)
                if m:
                    repo = m.group(1)
            items.append({
                "type": "pr" if is_pr else "issue",
                "number": it.get("number"),
                "title": it.get("title", "")[:255],
                "htmlUrl": html_url,
                "repository": repo,
                "state": it.get("state"),
                "createdAt": it.get("created_at"),
            })
        return {
            "total_count": data.get("total_count", 0),
            "items": items,
            "error": None,
        }
    except HTTPError as e:
        if e.code == 403:
            return {"total_count": 0, "items": [], "error": "GitHub API rate limit exceeded."}
        if e.code == 422:
            return {"total_count": 0, "items": [], "error": "GitHub issues search query validation failed."}
        return {"total_count": 0, "items": [], "error": f"GitHub API error: {e.code}"}
    except (URLError, OSError) as e:
        return {"total_count": 0, "items": [], "error": f"Connection error: {str(e)}"}
    except Exception as e:
        return {"total_count": 0, "items": [], "error": f"{type(e).__name__}: {str(e)}"}


def _github_commits_search(
    query: str,
    token: Optional[str] = None,
    per_page: int = 5,
) -> Dict[str, Any]:
    """Search GitHub /search/commits for matching commit messages.

    The commit-search endpoint requires the 'cloak-preview' Accept media
    type on older API versions; the current production API supports it
    natively but we send both for safety."""
    import urllib.parse
    url = (
        f"{GITHUB_API}/search/commits?q={urllib.parse.quote(query)}"
        f"&per_page={per_page}"
    )
    headers = {
        "Accept": "application/vnd.github.cloak-preview+json",
        "User-Agent": "NanoASM-Scanner",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        resp = urlopen(Request(url, headers=headers), timeout=10)
        data = json.loads(resp.read().decode("utf-8"))
        items = []
        for it in data.get("items", [])[:per_page]:
            commit = it.get("commit") or {}
            repository = it.get("repository") or {}
            items.append({
                "sha": it.get("sha"),
                "message": (commit.get("message") or "")[:500],
                "htmlUrl": it.get("html_url") or "",
                "repository": repository.get("full_name") or "",
                "author": (commit.get("author") or {}).get("name"),
                "date": (commit.get("author") or {}).get("date"),
            })
        return {
            "total_count": data.get("total_count", 0),
            "items": items,
            "error": None,
        }
    except HTTPError as e:
        if e.code == 403:
            return {"total_count": 0, "items": [], "error": "GitHub API rate limit exceeded."}
        if e.code == 422:
            return {"total_count": 0, "items": [], "error": "GitHub commit search query validation failed."}
        return {"total_count": 0, "items": [], "error": f"GitHub API error: {e.code}"}
    except (URLError, OSError) as e:
        return {"total_count": 0, "items": [], "error": f"Connection error: {str(e)}"}
    except Exception as e:
        return {"total_count": 0, "items": [], "error": f"{type(e).__name__}: {str(e)}"}


def _run_github_extra_scan(
    domain: str,
    *,
    full: bool,
    max_searches: int,
    search_fn,
) -> Dict[str, Any]:
    """Shared orchestrator for the two new search surfaces.

    `search_fn` is `_github_issues_search` or `_github_commits_search`.
    Wraps each pattern in a per-iteration try/except so one bad query
    doesn't abort the others."""
    token = os.environ.get("GITHUB_TOKEN")
    results: List[Dict[str, Any]] = []
    total = 0
    rate_limited = False
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    patterns = GITHUB_EXTRA_PATTERNS[:max_searches]
    for pattern in patterns:
        query = pattern["query"].replace("{domain}", domain)
        try:
            sr = search_fn(query, token=token)
        except Exception as e:
            results.append({
                "query": query,
                "category": pattern["category"],
                "severity": pattern["severity"],
                "title": pattern["title"],
                "description": pattern["description"],
                "totalResults": 0,
                "error": f"{type(e).__name__}: {str(e)}",
            })
            continue

        if sr.get("error") and "rate limit" in sr["error"].lower():
            rate_limited = True
            break

        count = sr.get("total_count", 0)
        entry: Dict[str, Any] = {
            "query": query,
            "category": pattern["category"],
            "severity": pattern["severity"],
            "title": pattern["title"],
            "description": pattern["description"],
            "totalResults": count,
        }
        if count > 0:
            total += count
            sev_counts[pattern["severity"]] = sev_counts.get(pattern["severity"], 0) + 1
            if full:
                entry["items"] = sr.get("items", [])
        if sr.get("error"):
            entry["error"] = sr["error"]
        results.append(entry)
        # Light pacing — GitHub search API allows 30 req/min authenticated,
        # 10/min anonymous. Sleeping a couple seconds between patterns
        # keeps us comfortably under either ceiling.
        time.sleep(2.0 if not token else 1.0)

    response: Dict[str, Any] = {
        "domain": domain,
        "totalLeaks": total,
        "searchesCompleted": len(results),
        "severityCounts": sev_counts,
        "hasGitHubToken": token is not None,
        "rateLimited": rate_limited,
    }
    if full:
        response["searches"] = results
    return response


def run_github_issue_pr_scan(
    domain: str, *, full: bool = True, max_searches: int = 5,
) -> Dict[str, Any]:
    """Scan public GitHub issues + pull requests for credential mentions
    associated with the given domain. Same shape as run_github_leak_scan."""
    return _run_github_extra_scan(
        domain, full=full, max_searches=max_searches,
        search_fn=_github_issues_search,
    )


def run_github_commits_scan(
    domain: str, *, full: bool = True, max_searches: int = 5,
) -> Dict[str, Any]:
    """Scan public GitHub commit messages for credential mentions
    associated with the given domain. Same shape as run_github_leak_scan."""
    return _run_github_extra_scan(
        domain, full=full, max_searches=max_searches,
        search_fn=_github_commits_search,
    )

    return response