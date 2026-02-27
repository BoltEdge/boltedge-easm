# create-leak-scanner-files.ps1
# Run from your project root directory
# Creates all backend files for the Leak Scanner feature

Write-Host "Creating Leak Scanner backend files..." -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────
# 1. app/tools/sensitive_paths.py
# ─────────────────────────────────────────────────────────────

$sensitivePathsContent = @'
# app/tools/sensitive_paths.py
"""
Sensitive Path Scanner tool.

Checks a domain for commonly exposed files and directories that could
leak secrets, source code, configuration, or internal information.

Public mode:  summary only (found paths, severity counts)
Full mode:    all details including response snippets, headers
"""

from __future__ import annotations

import logging
import re
import ssl as _ssl
import time
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

logger = logging.getLogger(__name__)


# ───────────────────────────────────────────────────────────────
# Path definitions
# ───────────────────────────────────────────────────────────────

def _confirm_git_head(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("ref:" in body.lower() or body.strip().startswith("ref:"))

def _confirm_git_config(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("[core]" in body or "[remote" in body)

def _confirm_env(status: int, body: str, _h: dict) -> bool:
    if status != 200:
        return False
    lines = body.strip().split("\n")[:20]
    kv_count = sum(1 for l in lines if re.match(r"^[A-Z_][A-Z0-9_]*=", l.strip()))
    return kv_count >= 2

def _confirm_phpinfo(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("phpinfo()" in body or "PHP Version" in body)

def _confirm_server_status(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("Apache Server Status" in body or "Server uptime" in body)

def _confirm_swagger(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("swagger" in body.lower() or '"openapi"' in body.lower() or '"paths"' in body.lower())

def _confirm_sql_dump(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("CREATE TABLE" in body or "INSERT INTO" in body or "DROP TABLE" in body)

def _confirm_ds_store(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("Bud1" in body or "\x00\x00\x00\x01" in body)

def _confirm_htpasswd(status: int, body: str, _h: dict) -> bool:
    if status != 200:
        return False
    lines = body.strip().split("\n")[:10]
    return any(":" in l and (l.count(":") >= 1) and "$" in l for l in lines)

def _confirm_svn(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("svn" in body.lower() or "dir" in body.lower())

def _confirm_ssh_key(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("BEGIN RSA PRIVATE KEY" in body or "BEGIN OPENSSH PRIVATE KEY" in body or "BEGIN EC PRIVATE KEY" in body)

def _confirm_package_json(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ('"name"' in body and ('"version"' in body or '"dependencies"' in body))

def _confirm_docker_compose(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("services:" in body or "version:" in body)

def _confirm_wp_config(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("DB_NAME" in body or "DB_PASSWORD" in body or "AUTH_KEY" in body)

def _confirm_wp_install(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("WordPress" in body and ("install" in body.lower() or "setup" in body.lower()))

def _confirm_robots(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("user-agent" in body.lower() or "disallow" in body.lower() or "sitemap" in body.lower())

def _confirm_security_txt(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("contact:" in body.lower() or "policy:" in body.lower())

def _confirm_npmrc(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("registry" in body.lower() or "_authToken" in body or "//npm" in body)

def _confirm_web_config(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("<configuration" in body.lower() or "<system.web" in body.lower())

def _confirm_dockerfile(status: int, body: str, _h: dict) -> bool:
    return status == 200 and ("FROM " in body and ("RUN " in body or "CMD " in body or "COPY " in body))


SENSITIVE_PATHS: List[Dict[str, Any]] = [
    # -- Source Control --
    {"path": "/.git/HEAD", "category": "source_control", "severity": "critical",
     "title": "Git Repository Exposed", "confirm": _confirm_git_head,
     "description": "The .git directory is accessible, potentially exposing the full source code history."},
    {"path": "/.git/config", "category": "source_control", "severity": "critical",
     "title": "Git Config Exposed", "confirm": _confirm_git_config,
     "description": "Git configuration file is accessible, may reveal remote repository URLs and credentials."},
    {"path": "/.svn/entries", "category": "source_control", "severity": "high",
     "title": "SVN Repository Exposed", "confirm": _confirm_svn,
     "description": "Subversion repository metadata is accessible."},

    # -- Environment / Secrets --
    {"path": "/.env", "category": "secrets", "severity": "critical",
     "title": "Environment File Exposed (.env)", "confirm": _confirm_env,
     "description": "Environment file with potential API keys, database passwords, and secrets is publicly accessible."},
    {"path": "/.env.local", "category": "secrets", "severity": "critical",
     "title": "Local Environment File Exposed", "confirm": _confirm_env,
     "description": "Local environment override file is publicly accessible."},
    {"path": "/.env.production", "category": "secrets", "severity": "critical",
     "title": "Production Environment File Exposed", "confirm": _confirm_env,
     "description": "Production environment file with likely real credentials is publicly accessible."},
    {"path": "/.env.backup", "category": "secrets", "severity": "critical",
     "title": "Environment Backup File Exposed", "confirm": _confirm_env,
     "description": "Backup of environment file is publicly accessible."},

    # -- SSH Keys --
    {"path": "/id_rsa", "category": "secrets", "severity": "critical",
     "title": "SSH Private Key Exposed", "confirm": _confirm_ssh_key,
     "description": "SSH private key file is publicly accessible, enabling unauthorized server access."},
    {"path": "/.ssh/id_rsa", "category": "secrets", "severity": "critical",
     "title": "SSH Private Key Exposed (.ssh/)", "confirm": _confirm_ssh_key,
     "description": "SSH private key in .ssh directory is publicly accessible."},

    # -- Package Manager Credentials --
    {"path": "/.npmrc", "category": "secrets", "severity": "high",
     "title": "NPM Config Exposed (.npmrc)", "confirm": _confirm_npmrc,
     "description": "NPM configuration file may contain auth tokens for private registries."},
    {"path": "/.pypirc", "category": "secrets", "severity": "high",
     "title": "PyPI Config Exposed (.pypirc)", "confirm": None,
     "description": "PyPI configuration file may contain upload credentials."},

    # -- Server Configuration --
    {"path": "/.htpasswd", "category": "config", "severity": "critical",
     "title": "Apache Password File Exposed", "confirm": _confirm_htpasswd,
     "description": "Apache htpasswd file with hashed passwords is publicly accessible."},
    {"path": "/.htaccess", "category": "config", "severity": "medium",
     "title": "Apache htaccess Exposed", "confirm": None,
     "description": "Apache configuration file may reveal rewrite rules and internal paths."},
    {"path": "/web.config", "category": "config", "severity": "high",
     "title": "IIS Web.config Exposed", "confirm": _confirm_web_config,
     "description": "IIS configuration file may contain connection strings and security settings."},

    # -- CMS Configuration --
    {"path": "/wp-config.php.bak", "category": "config", "severity": "critical",
     "title": "WordPress Config Backup Exposed", "confirm": _confirm_wp_config,
     "description": "WordPress configuration backup with database credentials is accessible."},
    {"path": "/wp-config.php~", "category": "config", "severity": "critical",
     "title": "WordPress Config Editor Backup", "confirm": _confirm_wp_config,
     "description": "WordPress configuration editor backup file is accessible."},
    {"path": "/wp-admin/install.php", "category": "config", "severity": "high",
     "title": "WordPress Installer Accessible", "confirm": _confirm_wp_install,
     "description": "WordPress installation script is accessible - may allow re-installation."},

    # -- Database Dumps --
    {"path": "/backup.sql", "category": "data_leak", "severity": "critical",
     "title": "SQL Backup File Exposed", "confirm": _confirm_sql_dump,
     "description": "SQL database backup file is publicly accessible."},
    {"path": "/dump.sql", "category": "data_leak", "severity": "critical",
     "title": "SQL Dump File Exposed", "confirm": _confirm_sql_dump,
     "description": "SQL database dump file is publicly accessible."},
    {"path": "/database.sql", "category": "data_leak", "severity": "critical",
     "title": "Database SQL File Exposed", "confirm": _confirm_sql_dump,
     "description": "Database SQL file is publicly accessible."},
    {"path": "/db.sql", "category": "data_leak", "severity": "critical",
     "title": "Database SQL File Exposed", "confirm": _confirm_sql_dump,
     "description": "Database SQL file is publicly accessible."},

    # -- Debug / Info Endpoints --
    {"path": "/phpinfo.php", "category": "info_leak", "severity": "high",
     "title": "phpinfo() Exposed", "confirm": _confirm_phpinfo,
     "description": "PHP info page reveals server configuration, modules, and environment variables."},
    {"path": "/server-status", "category": "info_leak", "severity": "high",
     "title": "Apache Server Status Exposed", "confirm": _confirm_server_status,
     "description": "Apache server status page reveals active connections and server internals."},
    {"path": "/server-info", "category": "info_leak", "severity": "high",
     "title": "Apache Server Info Exposed", "confirm": _confirm_server_status,
     "description": "Apache server info page reveals module configuration and server details."},

    # -- API Documentation --
    {"path": "/swagger.json", "category": "info_leak", "severity": "medium",
     "title": "Swagger API Documentation Exposed", "confirm": _confirm_swagger,
     "description": "API documentation is publicly accessible, revealing endpoints and data structures."},
    {"path": "/api-docs", "category": "info_leak", "severity": "medium",
     "title": "API Documentation Endpoint Exposed", "confirm": _confirm_swagger,
     "description": "API documentation endpoint is accessible."},
    {"path": "/openapi.json", "category": "info_leak", "severity": "medium",
     "title": "OpenAPI Spec Exposed", "confirm": _confirm_swagger,
     "description": "OpenAPI specification file is publicly accessible."},

    # -- Container / Infra --
    {"path": "/docker-compose.yml", "category": "config", "severity": "high",
     "title": "Docker Compose File Exposed", "confirm": _confirm_docker_compose,
     "description": "Docker compose file reveals service architecture, ports, and possibly credentials."},
    {"path": "/Dockerfile", "category": "config", "severity": "medium",
     "title": "Dockerfile Exposed", "confirm": _confirm_dockerfile,
     "description": "Dockerfile reveals build process, base images, and potentially embedded secrets."},

    # -- Dependency Manifests --
    {"path": "/package.json", "category": "info_leak", "severity": "low",
     "title": "package.json Exposed", "confirm": _confirm_package_json,
     "description": "Node.js package manifest reveals dependencies and may disclose private packages."},
    {"path": "/composer.json", "category": "info_leak", "severity": "low",
     "title": "composer.json Exposed", "confirm": _confirm_package_json,
     "description": "PHP Composer manifest reveals dependencies."},

    # -- macOS Metadata --
    {"path": "/.DS_Store", "category": "info_leak", "severity": "low",
     "title": ".DS_Store File Exposed", "confirm": _confirm_ds_store,
     "description": "macOS directory metadata file reveals filenames and directory structure."},

    # -- Recon / Informational --
    {"path": "/robots.txt", "category": "recon", "severity": "info",
     "title": "robots.txt Found", "confirm": _confirm_robots,
     "description": "robots.txt reveals which paths the site wants hidden from search engines."},
    {"path": "/.well-known/security.txt", "category": "recon", "severity": "info",
     "title": "security.txt Found", "confirm": _confirm_security_txt,
     "description": "Security contact information is published (this is good practice)."},
]


# ───────────────────────────────────────────────────────────────
# Scanner
# ───────────────────────────────────────────────────────────────

def _fetch_path(
    domain: str, path: str, timeout: int = 5
) -> Dict[str, Any]:
    """Fetch a URL and return status, snippet, headers."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}{path}"
        try:
            req = Request(url, headers={
                "User-Agent": "Mozilla/5.0 (compatible; BoltEdge EASM Scanner)",
                "Accept": "text/html,*/*",
            })
            ssl_ctx = None
            if scheme == "https":
                ssl_ctx = _ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = _ssl.CERT_NONE

            start = time.time()
            resp = urlopen(req, timeout=timeout, context=ssl_ctx)
            latency = round((time.time() - start) * 1000)
            body = resp.read(32768).decode("utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.getheaders()}

            return {
                "status": resp.status,
                "body": body,
                "headers": headers,
                "latency_ms": latency,
                "url": url,
                "error": None,
            }
        except HTTPError as e:
            body = ""
            try:
                body = e.read(32768).decode("utf-8", errors="replace")
            except Exception:
                pass
            headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            return {
                "status": e.code,
                "body": body,
                "headers": headers,
                "latency_ms": 0,
                "url": url,
                "error": None,
            }
        except (URLError, OSError):
            continue
        except Exception as e:
            return {
                "status": None,
                "body": "",
                "headers": {},
                "latency_ms": 0,
                "url": url,
                "error": str(e),
            }

    return {"status": None, "body": "", "headers": {}, "latency_ms": 0, "url": f"https://{domain}{path}", "error": "Connection failed"}


def run_sensitive_path_scan(domain: str, full: bool = True) -> dict:
    """
    Scan a domain for sensitive/exposed paths.
    """
    findings: List[Dict[str, Any]] = []
    checked = 0
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for path_def in SENSITIVE_PATHS:
        path = path_def["path"]
        checked += 1

        resp = _fetch_path(domain, path)

        if resp["error"] or resp["status"] is None:
            continue

        status = resp["status"]
        body = resp["body"]
        headers = resp["headers"]

        if status in (404, 410):
            continue

        if status == 403 and path_def["category"] in ("source_control",):
            finding = {
                "path": path,
                "status": status,
                "category": path_def["category"],
                "severity": "medium",
                "title": f"{path_def['title']} (Forbidden)",
                "description": f"Path {path} returned 403 Forbidden - the path exists but access is blocked. Verify it's not partially accessible.",
                "confirmed": False,
            }
            if full:
                finding["url"] = resp["url"]
                finding["latency_ms"] = resp["latency_ms"]
                finding["snippet"] = body[:200] if body else None
            findings.append(finding)
            sev_counts["medium"] += 1
            continue

        if status == 403:
            continue

        confirm_fn = path_def.get("confirm")
        confirmed = True
        if confirm_fn:
            try:
                confirmed = confirm_fn(status, body, headers)
            except Exception:
                confirmed = False

        if not confirmed:
            continue

        severity = path_def["severity"]
        finding = {
            "path": path,
            "status": status,
            "category": path_def["category"],
            "severity": severity,
            "title": path_def["title"],
            "description": path_def["description"],
            "confirmed": True,
        }

        if full:
            finding["url"] = resp["url"]
            finding["latency_ms"] = resp["latency_ms"]
            if severity in ("critical", "high"):
                finding["snippet"] = body[:100] + "..." if len(body) > 100 else body
            else:
                finding["snippet"] = body[:300] if body else None

        findings.append(finding)
        sev_counts[severity] = sev_counts.get(severity, 0) + 1

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 5))

    issues = []
    for f in findings:
        if f["severity"] == "info":
            continue
        issues.append({
            "severity": f["severity"],
            "title": f["title"],
            "description": f["description"],
            "recommendation": f"Remove or restrict access to {f['path']}. Ensure sensitive files are not deployed to production.",
        })

    return {
        "domain": domain,
        "pathsChecked": checked,
        "pathsFound": len(findings),
        "findings": findings,
        "severityCounts": sev_counts,
        "issues": issues,
    }
'@

New-Item -ItemType Directory -Force -Path "app/tools" | Out-Null
Set-Content -Path "app/tools/sensitive_paths.py" -Value $sensitivePathsContent -Encoding UTF8 -NoNewline
Write-Host "  [OK] app/tools/sensitive_paths.py" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# 2. app/tools/github_leaks.py
# ─────────────────────────────────────────────────────────────

$githubLeaksContent = @'
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


# ───────────────────────────────────────────────────────────────
# Search patterns
# ───────────────────────────────────────────────────────────────

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


# ───────────────────────────────────────────────────────────────
# GitHub API search
# ───────────────────────────────────────────────────────────────

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
        "User-Agent": "BoltEdge-EASM-Scanner",
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


# ───────────────────────────────────────────────────────────────
# Main tool
# ───────────────────────────────────────────────────────────────

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

    return response
'@

Set-Content -Path "app/tools/github_leaks.py" -Value $githubLeaksContent -Encoding UTF8 -NoNewline
Write-Host "  [OK] app/tools/github_leaks.py" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# 3. app/scanner/engines/leak_engine.py
# ─────────────────────────────────────────────────────────────

$leakEngineContent = @'
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
'@

New-Item -ItemType Directory -Force -Path "app/scanner/engines" | Out-Null
Set-Content -Path "app/scanner/engines/leak_engine.py" -Value $leakEngineContent -Encoding UTF8 -NoNewline
Write-Host "  [OK] app/scanner/engines/leak_engine.py" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# 4. app/scanner/analyzers/leak_analyzer.py
# ─────────────────────────────────────────────────────────────

$leakAnalyzerContent = @'
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
'@

New-Item -ItemType Directory -Force -Path "app/scanner/analyzers" | Out-Null
Set-Content -Path "app/scanner/analyzers/leak_analyzer.py" -Value $leakAnalyzerContent -Encoding UTF8 -NoNewline
Write-Host "  [OK] app/scanner/analyzers/leak_analyzer.py" -ForegroundColor Green

# ─────────────────────────────────────────────────────────────
# 5. Update engine registry
# ─────────────────────────────────────────────────────────────

$enginesInitPath = "app/scanner/engines/__init__.py"
$enginesInit = Get-Content $enginesInitPath -Raw -ErrorAction SilentlyContinue

if ($enginesInit -and $enginesInit -notmatch "LeakEngine") {
    $enginesInit = $enginesInit -replace "(from app\.scanner\.engines\.cloud_asset_engine import CloudAssetEngine)", "`$1`nfrom app.scanner.engines.leak_engine import LeakEngine"
    $enginesInit = $enginesInit -replace '("cloud_asset":\s*CloudAssetEngine,)', "`$1`n    `"leak`": LeakEngine,"
    $enginesInit = $enginesInit -replace '("CloudAssetEngine",)', "`$1`n    `"LeakEngine`","
    Set-Content -Path $enginesInitPath -Value $enginesInit -Encoding UTF8 -NoNewline
    Write-Host "  [OK] $enginesInitPath (updated)" -ForegroundColor Green
} elseif (-not $enginesInit) {
    Write-Host "  [SKIP] $enginesInitPath not found - add LeakEngine import manually" -ForegroundColor Yellow
} else {
    Write-Host "  [SKIP] $enginesInitPath already has LeakEngine" -ForegroundColor Yellow
}

# ─────────────────────────────────────────────────────────────
# 6. Update analyzer registry
# ─────────────────────────────────────────────────────────────

$analyzersInitPath = "app/scanner/analyzers/__init__.py"
$analyzersInit = Get-Content $analyzersInitPath -Raw -ErrorAction SilentlyContinue

if ($analyzersInit -and $analyzersInit -notmatch "LeakAnalyzer") {
    # Add import
    $analyzersInit = $analyzersInit -replace "(from app\.scanner\.analyzers\.exposure_scorer import ExposureScorer)", "from app.scanner.analyzers.leak_analyzer import LeakAnalyzer`n`$1"
    # Add to registry (before exposure_scorer)
    $analyzersInit = $analyzersInit -replace '(\s*"exposure_scorer":\s*ExposureScorer)', "    `"leak_analyzer`": LeakAnalyzer,`n`$1"
    # Add to __all__
    $analyzersInit = $analyzersInit -replace '("ExposureScorer")', "`"LeakAnalyzer`", `$1"
    Set-Content -Path $analyzersInitPath -Value $analyzersInit -Encoding UTF8 -NoNewline
    Write-Host "  [OK] $analyzersInitPath (updated)" -ForegroundColor Green
} elseif (-not $analyzersInit) {
    Write-Host "  [SKIP] $analyzersInitPath not found - add LeakAnalyzer import manually" -ForegroundColor Yellow
} else {
    Write-Host "  [SKIP] $analyzersInitPath already has LeakAnalyzer" -ForegroundColor Yellow
}

# ─────────────────────────────────────────────────────────────
# 7. Update routes.py - append new endpoints
# ─────────────────────────────────────────────────────────────

$routesPath = "app/tools/routes.py"
$routesContent = Get-Content $routesPath -Raw -ErrorAction SilentlyContinue

if ($routesContent -and $routesContent -notmatch "sensitive-paths") {
    $newRoutes = @'


# ═══════════════════════════════════════════════════════════════
# SENSITIVE PATH SCANNER
# ═══════════════════════════════════════════════════════════════

@tools_bp.post("/sensitive-paths")
@require_auth
def sensitive_paths_auth():
    """Authenticated sensitive path scan - full results."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    _, ssrf_err = _resolve_and_check_ssrf(domain)
    if ssrf_err:
        return ssrf_err
    from app.tools.sensitive_paths import run_sensitive_path_scan
    return jsonify(run_sensitive_path_scan(domain, full=True)), 200


@tools_bp.post("/public/sensitive-paths")
def sensitive_paths_public():
    """Public sensitive path scan - summary only."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    _, ssrf_err = _resolve_and_check_ssrf(domain)
    if ssrf_err:
        return ssrf_err
    from app.tools.sensitive_paths import run_sensitive_path_scan
    return jsonify(run_sensitive_path_scan(domain, full=False)), 200


# ═══════════════════════════════════════════════════════════════
# GITHUB LEAK SCANNER
# ═══════════════════════════════════════════════════════════════

@tools_bp.post("/github-leaks")
@require_auth
def github_leaks_auth():
    """Authenticated GitHub leak scan - full results."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    from app.tools.github_leaks import run_github_leak_scan
    return jsonify(run_github_leak_scan(domain, full=True)), 200


@tools_bp.post("/public/github-leaks")
def github_leaks_public():
    """Public GitHub leak scan - summary only."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    from app.tools.github_leaks import run_github_leak_scan
    return jsonify(run_github_leak_scan(domain, full=False)), 200
'@
    Add-Content -Path $routesPath -Value $newRoutes -Encoding UTF8
    Write-Host "  [OK] $routesPath (appended leak routes)" -ForegroundColor Green
} elseif (-not $routesContent) {
    Write-Host "  [SKIP] $routesPath not found" -ForegroundColor Yellow
} else {
    Write-Host "  [SKIP] $routesPath already has leak routes" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "All backend files created successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Don't forget to:" -ForegroundColor Yellow
Write-Host "  1. Add leak engine to your scan profiles:" -ForegroundColor Yellow
Write-Host '     Quick: "leak": {"check_sensitive_paths": True, "check_github_leaks": False}' -ForegroundColor DarkGray
Write-Host '     Deep:  "leak": {"check_sensitive_paths": True, "check_github_leaks": True}' -ForegroundColor DarkGray
Write-Host "  2. Set GITHUB_TOKEN env var for GitHub code search" -ForegroundColor Yellow
Write-Host "  3. Update the frontend tools page separately" -ForegroundColor Yellow