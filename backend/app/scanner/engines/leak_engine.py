# app/scanner/engines/leak_engine.py
"""
Leak Detection engine.

Combines multiple leak detection methods during scan jobs:
    1. Sensitive path scanning - checks for exposed files (.env, .git, etc.)
    2. GitHub code search - searches public repos for leaked credentials
    3. GitLab code search - searches public projects for leaked credentials
    4. Google dork generation - produces manual investigation queries

Each public-source search additionally runs the matched snippets through
the shared secret-pattern detector (`tools.secret_patterns`) so keyword
hits are upgraded to high-confidence pattern matches when an actual
recognisable secret format (AWS key, GitHub PAT, Stripe key, etc.) is
present in the snippet.

This engine collects raw data. The LeakAnalyzer interprets findings.

Profile config options:
    check_sensitive_paths:    bool  (default: True)
    check_github_leaks:       bool  (default: False for Quick, True for Deep)
    check_gitlab_leaks:       bool  (default: same as github)
    check_github_issues_prs:  bool  (default: same as github)
    check_github_commits:     bool  (default: same as github)
    check_pastebin:           bool  (default: True if PASTEBIN_FETCHER_ENABLED)
    max_github_searches:      int   (default: 12)
    max_gitlab_searches:      int   (default: 8)
    max_github_issue_searches: int  (default: 5)
    max_github_commit_searches: int (default: 5)
    max_pastebin_matches:     int   (default: 50)
    path_timeout:             int   (default: 5)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List

from app.scanner.base import BaseEngine, EngineResult, ScanContext

logger = logging.getLogger(__name__)


class LeakEngine(BaseEngine):
    """
    Detects leaked secrets, exposed files, and public code references.
    """

    @property
    def name(self) -> str:
        return "leak"

    @property
    def supported_asset_types(self) -> List[str]:
        return ["domain"]

    def execute(self, ctx: ScanContext, config: Dict[str, Any]) -> EngineResult:
        result = EngineResult(engine_name=self.name)

        domain = ctx.asset_value.strip().lower()
        if domain.startswith("*."):
            domain = domain[2:]

        if not domain:
            result.success = False
            result.add_error("Empty domain")
            return result

        check_paths = config.get("check_sensitive_paths", True)
        check_github = config.get("check_github_leaks", False)
        check_gitlab = config.get("check_gitlab_leaks", check_github)
        check_issues_prs = config.get("check_github_issues_prs", check_github)
        check_commits = config.get("check_github_commits", check_github)
        # Pastebin matching follows the master use_leak gate. The shared
        # cache is operator-controlled; if the background fetcher isn't
        # running, the engine method returns an empty result silently.
        check_pastebin = config.get(
            "check_pastebin",
            os.environ.get("PASTEBIN_FETCHER_ENABLED", "").strip().lower() == "true",
        )
        max_searches = config.get("max_github_searches", 12)
        max_gitlab_searches = config.get("max_gitlab_searches", 8)
        max_issue_searches = config.get("max_github_issue_searches", 5)
        max_commit_searches = config.get("max_github_commit_searches", 5)
        max_pastebin_matches = config.get("max_pastebin_matches", 50)
        path_timeout = config.get("path_timeout", 5)

        data: Dict[str, Any] = {"domain": domain}

        # 1. Sensitive path scanning
        if check_paths:
            try:
                from app.tools.sensitive_paths import run_sensitive_path_scan
                path_results = run_sensitive_path_scan(domain, full=True)
                data["sensitive_paths"] = {
                    "paths_checked": path_results.get("pathsChecked", 0),
                    "findings": path_results.get("findings", []),
                }
                logger.info(
                    f"LeakEngine: checked {path_results.get('pathsChecked', 0)} paths on {domain}, "
                    f"found {len(path_results.get('findings', []))} exposed"
                )
            except Exception as e:
                logger.error(f"LeakEngine: sensitive path scan failed for {domain}: {e}")
                data["sensitive_paths"] = {"paths_checked": 0, "findings": [], "error": str(e)}
        else:
            data["sensitive_paths"] = {"paths_checked": 0, "findings": []}

        # 2. GitHub code search
        if check_github:
            github_token = os.environ.get("GITHUB_TOKEN")
            if not github_token:
                logger.info("LeakEngine: GITHUB_TOKEN not set, skipping GitHub search")
                data["github_leaks"] = {
                    "total_leaks": 0,
                    "searches": [],
                    "skipped": True,
                    "reason": "GITHUB_TOKEN not configured",
                }
            else:
                try:
                    from app.tools.github_leaks import run_github_leak_scan
                    gh_results = run_github_leak_scan(domain, full=True)
                    data["github_leaks"] = {
                        "total_leaks": gh_results.get("totalLeaks", 0),
                        "searches": gh_results.get("searches", []),
                        "rate_limited": gh_results.get("rateLimited", False),
                    }
                    data["dorks"] = gh_results.get("dorks", [])
                    logger.info(
                        f"LeakEngine: GitHub search for {domain} - "
                        f"{gh_results.get('totalLeaks', 0)} potential leaks found"
                    )
                except Exception as e:
                    logger.error(f"LeakEngine: GitHub search failed for {domain}: {e}")
                    data["github_leaks"] = {"total_leaks": 0, "searches": [], "error": str(e)}
        else:
            data["github_leaks"] = {"total_leaks": 0, "searches": []}

        # 3. GitLab code search — same shape as GitHub. Runs against
        # gitlab.com's public blob index. Auth-optional (works without
        # GITLAB_TOKEN, but the per-IP rate limit is much harsher
        # without one).
        if check_gitlab:
            try:
                from app.tools.gitlab_leaks import run_gitlab_leak_scan
                gl_results = run_gitlab_leak_scan(
                    domain, full=True, max_searches=max_gitlab_searches,
                )
                data["gitlab_leaks"] = {
                    "total_leaks": gl_results.get("totalLeaks", 0),
                    "searches": gl_results.get("searches", []),
                    "rate_limited": gl_results.get("rateLimited", False),
                    "token_available": gl_results.get("tokenAvailable", False),
                }
                logger.info(
                    f"LeakEngine: GitLab search for {domain} - "
                    f"{gl_results.get('totalLeaks', 0)} potential leaks found"
                )
            except Exception as e:
                logger.error(f"LeakEngine: GitLab search failed for {domain}: {e}")
                data["gitlab_leaks"] = {"total_leaks": 0, "searches": [], "error": str(e)}
        else:
            data["gitlab_leaks"] = {"total_leaks": 0, "searches": []}

        # 4. GitHub Issues / PRs — extended public-surface coverage. Same
        #    GITHUB_TOKEN; lower max_searches by default since signal
        #    density is lower than code.
        if check_issues_prs:
            github_token = os.environ.get("GITHUB_TOKEN")
            if not github_token:
                data["github_issues_prs"] = {
                    "total_leaks": 0, "searches": [],
                    "skipped": True, "reason": "GITHUB_TOKEN not configured",
                }
            else:
                try:
                    from app.tools.github_leaks import run_github_issue_pr_scan
                    res = run_github_issue_pr_scan(
                        domain, full=True, max_searches=max_issue_searches,
                    )
                    data["github_issues_prs"] = {
                        "total_leaks": res.get("totalLeaks", 0),
                        "searches": res.get("searches", []),
                        "rate_limited": res.get("rateLimited", False),
                    }
                except Exception as e:
                    logger.error("LeakEngine: GitHub issues/PRs scan failed for %s: %s", domain, e)
                    data["github_issues_prs"] = {"total_leaks": 0, "searches": [], "error": str(e)}
        else:
            data["github_issues_prs"] = {"total_leaks": 0, "searches": []}

        # 5. GitHub Commit messages — same auth as code search.
        if check_commits:
            github_token = os.environ.get("GITHUB_TOKEN")
            if not github_token:
                data["github_commits"] = {
                    "total_leaks": 0, "searches": [],
                    "skipped": True, "reason": "GITHUB_TOKEN not configured",
                }
            else:
                try:
                    from app.tools.github_leaks import run_github_commits_scan
                    res = run_github_commits_scan(
                        domain, full=True, max_searches=max_commit_searches,
                    )
                    data["github_commits"] = {
                        "total_leaks": res.get("totalLeaks", 0),
                        "searches": res.get("searches", []),
                        "rate_limited": res.get("rateLimited", False),
                    }
                except Exception as e:
                    logger.error("LeakEngine: GitHub commits scan failed for %s: %s", domain, e)
                    data["github_commits"] = {"total_leaks": 0, "searches": [], "error": str(e)}
        else:
            data["github_commits"] = {"total_leaks": 0, "searches": []}

        # 6. Pastebin — SQL match against the background-ingested cache.
        if check_pastebin:
            try:
                from app.services.pastebin_client import match_pastes_for_domain
                matches = match_pastes_for_domain(domain, max_matches=max_pastebin_matches)
                data["pastebin"] = {
                    "matches": matches,
                    "total_leaks": len(matches),
                    "ingestion_active": True,
                }
            except Exception as e:
                logger.error("LeakEngine: Pastebin match failed for %s: %s", domain, e)
                data["pastebin"] = {"matches": [], "total_leaks": 0, "error": str(e)}
        else:
            data["pastebin"] = {
                "matches": [], "total_leaks": 0,
                "ingestion_active": False,
            }

        # 7. Google dorks (always generated, no API call)
        if "dorks" not in data:
            from app.tools.github_leaks import GOOGLE_DORKS
            data["dorks"] = [
                {
                    "query": d["query"].replace("{domain}", domain),
                    "title": d["title"],
                    "description": d["description"],
                    "search_url": f"https://www.google.com/search?q={d['query'].replace('{domain}', domain).replace(' ', '+')}",
                }
                for d in GOOGLE_DORKS
            ]

        result.data = data
        result.metadata = {
            "paths_checked": check_paths,
            "github_checked": check_github,
            "gitlab_checked": check_gitlab,
            "github_issues_prs_checked": check_issues_prs,
            "github_commits_checked": check_commits,
            "pastebin_checked": check_pastebin,
            "github_token_available": bool(os.environ.get("GITHUB_TOKEN")),
            "gitlab_token_available": bool(os.environ.get("GITLAB_TOKEN")),
            "pastebin_fetcher_enabled": (
                os.environ.get("PASTEBIN_FETCHER_ENABLED", "").strip().lower() == "true"
            ),
        }

        return result