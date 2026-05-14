# app/scanner/analyzers/leak_analyzer.py
"""
Leak Detection Analyzer.

Reads leak engine data (sensitive paths + GitHub code search) and
produces FindingDrafts whose copy comes from the curated registry in
app/scanner/templates.py.

Path findings are routed by file family via PATH_TEMPLATE_MAP — one
template per family (.git, .env, ssh-key, sql-dump, etc.) rather than
one per individual probe path. GitHub findings are routed by category
(credentials / api_key / cloud_creds / etc.).

Required engine: leak
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext
from app.scanner.templates import FindingTemplate, get_template

logger = logging.getLogger(__name__)


# ─── Path → template-family routing ──────────────────────────────────────
# Each probe path the engine knows about maps to one curated template.
# Paths added to the engine that aren't in this map fall through to the
# generic `leak-path` template, so detection coverage doesn't depend on
# this map being complete.

PATH_TEMPLATE_MAP: Dict[str, str] = {
    # Source control
    "/.git/HEAD":                "leak-git-exposed",
    "/.git/config":              "leak-git-exposed",
    "/.svn/entries":             "leak-svn-exposed",
    # Secrets / env files
    "/.env":                     "leak-env-file",
    "/.env.local":               "leak-env-file",
    "/.env.production":          "leak-env-file",
    "/.env.backup":              "leak-env-file",
    # SSH keys
    "/id_rsa":                   "leak-ssh-private-key",
    "/.ssh/id_rsa":              "leak-ssh-private-key",
    # Package manager creds
    "/.npmrc":                   "leak-package-creds",
    "/.pypirc":                  "leak-package-creds",
    # Server config
    "/.htpasswd":                "leak-htpasswd",
    "/.htaccess":                "leak-htaccess",
    "/web.config":               "leak-web-config",
    # WordPress
    "/wp-config.php.bak":        "leak-wp-config-backup",
    "/wp-config.php~":           "leak-wp-config-backup",
    "/wp-admin/install.php":     "leak-wp-installer",
    # SQL dumps
    "/backup.sql":               "leak-sql-dump",
    "/dump.sql":                 "leak-sql-dump",
    "/database.sql":             "leak-sql-dump",
    "/db.sql":                   "leak-sql-dump",
    # Debug endpoints
    "/phpinfo.php":              "leak-phpinfo",
    "/server-status":            "leak-apache-status",
    "/server-info":              "leak-apache-status",
    # API docs
    "/swagger.json":             "leak-api-docs",
    "/api-docs":                 "leak-api-docs",
    "/openapi.json":             "leak-api-docs",
    # Container / infra
    "/docker-compose.yml":       "leak-docker-compose",
    "/Dockerfile":               "leak-dockerfile",
    # Dependency manifests
    "/package.json":             "leak-package-manifest",
    "/composer.json":            "leak-package-manifest",
    # macOS metadata
    "/.DS_Store":                "leak-ds-store",
    # Recon paths (engine emits these as severity=info, filtered out below)
    "/robots.txt":               None,
    "/.well-known/security.txt": None,
}


# ─── GitHub category → template routing ──────────────────────────────────

GITHUB_CATEGORY_MAP: Dict[str, str] = {
    "credentials": "leak-github-credentials",
    "api_key":     "leak-github-api-key",
    "cloud_creds": "leak-github-cloud-creds",
    "secrets":     "leak-github-secrets",
    "env_file":    "leak-github-env-file",
    "config":      "leak-github-config",
}


# ─── GitLab category → template routing ──────────────────────────────────
# Parallel to GITHUB_CATEGORY_MAP. Distinct templates so the user-facing
# copy can correctly say "found on GitLab" vs "found on GitHub".

GITLAB_CATEGORY_MAP: Dict[str, str] = {
    "credentials": "leak-gitlab-credentials",
    "api_key":     "leak-gitlab-api-key",
    "cloud_creds": "leak-gitlab-cloud-creds",
    "secrets":     "leak-gitlab-secrets",
    "env_file":    "leak-gitlab-env-file",
    "config":      "leak-gitlab-config",
}


# ─── Render helper ───────────────────────────────────────────────────────

def _render(text: Optional[str], **subs: Any) -> Optional[str]:
    """Replace {key} placeholders with runtime values.

    Uses str.replace rather than str.format so curly braces inside
    Markdown / code snippets in templates don't blow up when a
    placeholder dict doesn't cover every brace pair.
    """
    if not text:
        return text
    out = text
    for k, v in subs.items():
        if v is None or v == "":
            continue
        out = out.replace("{" + k + "}", str(v))
    return out


def _draft_from_template(
    template: FindingTemplate,
    *,
    template_id: str,
    severity_override: Optional[str],
    confidence: str,
    asset: str,
    value: str,
    extra_tags: List[str],
    details: Dict[str, Any],
    dedupe_fields: Dict[str, Any],
    finding_type: str,
) -> FindingDraft:
    """Build a FindingDraft by rendering a registered template's copy."""
    title = _render(template.title, asset=asset, value=value)
    description = _render(template.description, asset=asset, value=value)
    remediation = _render(template.remediation, asset=asset, value=value)

    return FindingDraft(
        template_id=template_id,
        title=title or f"Leak finding for {asset}",
        severity=severity_override or template.severity or "medium",
        category=template.category or "leak",
        description=description or "",
        remediation=remediation,
        finding_type=finding_type,
        engine="leak",
        confidence=confidence,
        cwe=template.cwe,
        references=list(template.references),
        tags=list(template.tags) + extra_tags,
        details=details,
        dedupe_fields=dedupe_fields,
    )


# ─── Analyzer ────────────────────────────────────────────────────────────

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

        # ── 1. Sensitive path findings ──
        path_findings = leak_data.get("sensitive_paths", {}).get("findings", [])
        for pf in path_findings:
            engine_severity = pf.get("severity", "medium")
            if engine_severity == "info":
                # Recon paths (robots.txt, security.txt) — engine flags them
                # for inventory only, not as findings.
                continue

            path = pf.get("path", "")
            confirmed = pf.get("confirmed", False)
            tid = PATH_TEMPLATE_MAP.get(path) or "leak-path"

            template = get_template(tid)
            if template is None:
                logger.warning("Missing leak path template: %s (path=%s)", tid, path)
                continue

            details = {
                "value": path,
                "path": path,
                "url": pf.get("url"),
                "status_code": pf.get("status"),
                "category": pf.get("category"),
                "confirmed": confirmed,
                "snippet": pf.get("snippet", "")[:200] if pf.get("snippet") else None,
            }

            # Engine severity wins over template default — the engine knows
            # which specific path was found and the severity table inside
            # the engine is the source of truth for path-level severity.
            drafts.append(_draft_from_template(
                template,
                template_id=tid,
                severity_override=engine_severity,
                confidence="high" if confirmed else "medium",
                asset=domain,
                value=path,
                extra_tags=[pf.get("category", "leak")],
                details=details,
                dedupe_fields={
                    "domain": domain,
                    "path": path,
                },
                finding_type="leak",
            ))

        # ── 2. GitHub code-search leaks ──
        gh_data = leak_data.get("github_leaks", {})
        for search in gh_data.get("searches", []):
            count = search.get("totalResults") or search.get("total_results", 0)
            if count == 0:
                continue

            category = search.get("category", "credentials")
            tid = GITHUB_CATEGORY_MAP.get(category) or "leak-github"

            template = get_template(tid)
            if template is None:
                logger.warning("Missing leak github template: %s (category=%s)", tid, category)
                continue

            files = search.get("files", []) or []
            sample_files = [
                {
                    "repository": f.get("repository", ""),
                    "path": f.get("path", ""),
                    "url": f.get("htmlUrl", f.get("html_url", "")),
                }
                for f in files[:5]
            ]

            details = {
                "value": search.get("title") or category,
                "search_query": search.get("query", ""),
                "total_results": count,
                "category": category,
                "sample_files": sample_files,
            }

            # Engine severity wins — its per-search-pattern severity is
            # already tuned (e.g., AWS-creds match is critical even when
            # the catch-all `credentials` family is high).
            engine_severity = search.get("severity", template.severity or "high")

            drafts.append(_draft_from_template(
                template,
                template_id=tid,
                severity_override=engine_severity,
                confidence="medium",
                asset=domain,
                value=search.get("title") or category,
                extra_tags=[category],
                details=details,
                dedupe_fields={
                    "domain": domain,
                    "category": category,
                    "query_hash": (search.get("query", "") or "")[:50],
                },
                finding_type="leak",
            ))

        # ── 3. GitLab code-search leaks ──
        gl_data = leak_data.get("gitlab_leaks", {})
        for search in gl_data.get("searches", []):
            count = search.get("leak_count", 0) or search.get("total_count", 0)
            if count == 0:
                continue

            category = search.get("category", "credentials")
            tid = GITLAB_CATEGORY_MAP.get(category) or "leak-gitlab"

            template = get_template(tid)
            if template is None:
                logger.warning("Missing leak gitlab template: %s (category=%s)", tid, category)
                continue

            matches = search.get("matches", []) or []
            sample_files = [
                {
                    "project_id": m.get("project_id"),
                    "path": m.get("path", ""),
                    "ref": m.get("ref"),
                    "startline": m.get("startline"),
                    "secret_matches": m.get("secret_matches") or [],
                }
                for m in matches[:5]
            ]

            details = {
                "value": search.get("title") or category,
                "search_query": search.get("query", ""),
                "total_results": count,
                "category": category,
                "sample_files": sample_files,
                "source": "gitlab",
            }

            engine_severity = search.get("severity", template.severity or "high")

            drafts.append(_draft_from_template(
                template,
                template_id=tid,
                severity_override=engine_severity,
                confidence="medium",
                asset=domain,
                value=search.get("title") or category,
                extra_tags=[category, "gitlab"],
                details=details,
                dedupe_fields={
                    "domain": domain,
                    "source": "gitlab",
                    "category": category,
                    "query_hash": (search.get("query", "") or "")[:50],
                },
                finding_type="leak",
            ))

        # ── 4. GitHub Issues / PRs ──
        gh_issues = leak_data.get("github_issues_prs", {})
        for search in gh_issues.get("searches", []):
            count = search.get("totalResults") or search.get("total_results", 0)
            if count == 0:
                continue
            template = get_template("leak-github-issue-pr")
            if template is None:
                logger.warning("Missing leak template: leak-github-issue-pr")
                continue
            category = search.get("category", "credentials")
            sample_items = (search.get("items") or [])[:5]
            details = {
                "value": search.get("title") or category,
                "search_query": search.get("query", ""),
                "total_results": count,
                "category": category,
                "source": "github_issues_prs",
                "sample_items": [
                    {
                        "type": it.get("type"),
                        "number": it.get("number"),
                        "title": it.get("title", "")[:200],
                        "url": it.get("htmlUrl") or it.get("html_url"),
                        "repository": it.get("repository", ""),
                        "state": it.get("state"),
                    }
                    for it in sample_items
                ],
            }
            engine_severity = search.get("severity", template.severity or "high")
            drafts.append(_draft_from_template(
                template,
                template_id="leak-github-issue-pr",
                severity_override=engine_severity,
                confidence="medium",
                asset=domain,
                value=search.get("title") or category,
                extra_tags=[category, "github-issues-prs"],
                details=details,
                dedupe_fields={
                    "domain": domain,
                    "source": "github_issues_prs",
                    "category": category,
                    "query_hash": (search.get("query", "") or "")[:50],
                },
                finding_type="leak",
            ))

        # ── 5. GitHub commit messages ──
        gh_commits = leak_data.get("github_commits", {})
        for search in gh_commits.get("searches", []):
            count = search.get("totalResults") or search.get("total_results", 0)
            if count == 0:
                continue
            template = get_template("leak-github-commit")
            if template is None:
                logger.warning("Missing leak template: leak-github-commit")
                continue
            category = search.get("category", "credentials")
            sample_items = (search.get("items") or [])[:5]
            details = {
                "value": search.get("title") or category,
                "search_query": search.get("query", ""),
                "total_results": count,
                "category": category,
                "source": "github_commits",
                "sample_items": [
                    {
                        "sha": it.get("sha", "")[:12],
                        "message": (it.get("message") or "")[:300],
                        "url": it.get("htmlUrl") or it.get("html_url"),
                        "repository": it.get("repository", ""),
                        "author": it.get("author"),
                        "date": it.get("date"),
                    }
                    for it in sample_items
                ],
            }
            engine_severity = search.get("severity", template.severity or "high")
            drafts.append(_draft_from_template(
                template,
                template_id="leak-github-commit",
                severity_override=engine_severity,
                confidence="medium",
                asset=domain,
                value=search.get("title") or category,
                extra_tags=[category, "github-commits"],
                details=details,
                dedupe_fields={
                    "domain": domain,
                    "source": "github_commits",
                    "category": category,
                    "query_hash": (search.get("query", "") or "")[:50],
                },
                finding_type="leak",
            ))

        # ── 6. Pastebin matches ──
        pb_data = leak_data.get("pastebin", {})
        for match in pb_data.get("matches", []) or []:
            template = get_template("leak-pastebin")
            if template is None:
                logger.warning("Missing leak template: leak-pastebin")
                break  # one missing template aborts the whole pastebin batch
            paste_key = match.get("paste_key") or ""
            if not paste_key:
                continue
            details = {
                "value": match.get("paste_url") or f"https://pastebin.com/{paste_key}",
                "paste_url": match.get("paste_url"),
                "paste_key": paste_key,
                "title": match.get("title"),
                "author": match.get("author"),
                "syntax": match.get("syntax"),
                "size_bytes": match.get("size_bytes"),
                "snippet": match.get("snippet", "")[:500] if match.get("snippet") else None,
                "date_pasted": match.get("date_pasted"),
                "source": "pastebin",
            }
            # Severity here is uniform — the LeakEngine cache match just
            # tells us "your domain is in a public paste." Whether that
            # paste is a credential dump or a benign mention is up to the
            # operator to confirm. Treat all matches as high by default;
            # the template-rendering layer surfaces remediation guidance.
            drafts.append(_draft_from_template(
                template,
                template_id="leak-pastebin",
                severity_override=template.severity or "high",
                confidence="medium",
                asset=domain,
                value=match.get("paste_url") or paste_key,
                extra_tags=["pastebin", "paste-site"],
                details=details,
                dedupe_fields={
                    "domain": domain,
                    "source": "pastebin",
                    "paste_key": paste_key,
                },
                finding_type="leak",
            ))

        if drafts:
            logger.info(
                "LeakAnalyzer: %d finding(s) for %s — %d critical, %d high",
                len(drafts), domain,
                sum(1 for d in drafts if d.severity == "critical"),
                sum(1 for d in drafts if d.severity == "high"),
            )

        return drafts
