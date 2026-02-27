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


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Path definitions
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Scanner
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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