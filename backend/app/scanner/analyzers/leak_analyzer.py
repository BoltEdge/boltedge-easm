# app/scanner/analyzers/leak_analyzer.py
"""
Leak Detection Analyzer.

Reads leak engine data (sensitive paths + GitHub code search) and
produces properly classified FindingDrafts.

Required engine: leak
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext

logger = logging.getLogger(__name__)


class LeakAnalyzer(BaseAnalyzer):

    @property
    def name(self) -> str:
        return "leak_analyzer"

    @property
    def required_engines(self) -> List[str]:
        return ["leak"]

    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        leak_data = ctx.get_engine_data("leak")
        if not leak_data:
            return []

        drafts: List[FindingDraft] = []
        domain = leak_data.get("domain", ctx.asset_value)

        # 1. Sensitive path findings
        path_findings = leak_data.get("sensitive_paths", {}).get("findings", [])
        for pf in path_findings:
            if pf.get("severity") == "info":
                continue

            severity = pf.get("severity", "medium")
            path = pf.get("path", "")
            category = pf.get("category", "config")
            confirmed = pf.get("confirmed", False)

            title = pf.get("title", f"Exposed path: {path}")
            description = pf.get("description", f"The path {path} is accessible on {domain}.")

            cwe_map = {
                "source_control": "CWE-538",
                "secrets": "CWE-200",
                "config": "CWE-16",
                "data_leak": "CWE-200",
                "info_leak": "CWE-200",
            }

            remediation_map = {
                "source_control": (
                    f"Remove the {path} path from the web server. Add the directory to "
                    f".gitignore or your deployment exclusion list. Verify with: curl -I https://{domain}{path}"
                ),
                "secrets": (
                    f"Immediately remove {path} from the web server. Rotate ALL credentials "
                    f"that may have been exposed. Add the file to your deployment exclusion list. "
                    f"Consider using a secrets manager instead of filesystem-based credential storage."
                ),
                "config": (
                    f"Remove or restrict access to {path}. Server configuration files should "
                    f"never be accessible via HTTP. Update your web server config to deny access "
                    f"to sensitive file extensions and paths."
                ),
                "data_leak": (
                    f"Immediately remove {path} from the web server. If this contains real data, "
                    f"assess the scope of the exposure. Database dumps should never exist in "
                    f"web-accessible directories."
                ),
                "info_leak": (
                    f"Remove or restrict access to {path}. Information leakage can help "
                    f"attackers understand your infrastructure and plan targeted attacks."
                ),
            }

            drafts.append(FindingDraft(
                template_id=f"leak-path-{category}-{path.replace('/', '-').strip('-')}",
                title=title,
                severity=severity,
                category="leak",
                description=description,
                remediation=remediation_map.get(category, f"Remove or restrict access to {path}."),
                engine="leak",
                confidence="high" if confirmed else "medium",
                cwe=cwe_map.get(category, "CWE-200"),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                ],
                tags=["exposed-file", category, path.split("/")[-1].lstrip(".")],
                details={
                    "path": path,
                    "status_code": pf.get("status"),
                    "category": category,
                    "confirmed": confirmed,
                    "url": pf.get("url"),
                    "snippet": pf.get("snippet", "")[:200] if pf.get("snippet") else None,
                },
                dedupe_fields={
                    "domain": domain,
                    "path": path,
                },
            ))

        # 2. GitHub leak findings
        gh_data = leak_data.get("github_leaks", {})
        gh_searches = gh_data.get("searches", [])

        for search in gh_searches:
            count = search.get("totalResults") or search.get("total_results", 0)
            if count == 0:
                continue

            severity = search.get("severity", "high")
            category = search.get("category", "credentials")
            query = search.get("query", "")
            files = search.get("files", [])

            title = f"GitHub code leak: {search.get('title', category)} ({count} results)"
            description = (
                f"Public GitHub code search found {count} result(s) matching "
                f"'{query}'. This may indicate leaked credentials, API keys, "
                f"or configuration files in public repositories."
            )

            file_details = []
            for f in files[:5]:
                file_details.append({
                    "repository": f.get("repository", ""),
                    "path": f.get("path", ""),
                    "url": f.get("htmlUrl", f.get("html_url", "")),
                })

            drafts.append(FindingDraft(
                template_id=f"leak-github-{category}",
                title=title,
                severity=severity,
                category="leak",
                description=description,
                remediation=(
                    "1. Review each GitHub result and determine if real secrets are exposed.\n"
                    "2. If credentials are found: rotate them immediately.\n"
                    "3. Contact the repository owner to request removal or make the repo private.\n"
                    "4. Use GitHub's secret scanning alerts to prevent future leaks.\n"
                    "5. Consider using git-secrets or truffleHog in CI/CD to prevent commits with secrets."
                ),
                engine="leak",
                confidence="medium",
                cwe="CWE-200",
                references=[
                    "https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning",
                ],
                tags=["github-leak", category, "code-search"],
                details={
                    "search_query": query,
                    "total_results": count,
                    "category": category,
                    "sample_files": file_details,
                },
                dedupe_fields={
                    "domain": domain,
                    "category": category,
                    "query_hash": query[:50],
                },
            ))

        if drafts:
            logger.info(
                f"LeakAnalyzer: {len(drafts)} finding(s) for {domain} - "
                f"{sum(1 for d in drafts if d.severity == 'critical')} critical, "
                f"{sum(1 for d in drafts if d.severity == 'high')} high"
            )

        return drafts