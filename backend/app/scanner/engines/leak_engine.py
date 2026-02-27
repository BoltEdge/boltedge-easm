# app/scanner/engines/leak_engine.py
"""
Leak Detection engine.

Combines multiple leak detection methods during scan jobs:
    1. Sensitive path scanning - checks for exposed files (.env, .git, etc.)
    2. GitHub code search - searches public repos for leaked credentials
    3. Google dork generation - produces manual investigation queries

This engine collects raw data. The LeakAnalyzer interprets findings.

Profile config options:
    check_sensitive_paths:  bool  (default: True)
    check_github_leaks:    bool  (default: False for Quick, True for Deep)
    max_github_searches:   int   (default: 12)
    path_timeout:          int   (default: 5)
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
        max_searches = config.get("max_github_searches", 12)
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

        # 3. Google dorks (always generated, no API call)
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
            "github_token_available": bool(os.environ.get("GITHUB_TOKEN")),
        }

        return result