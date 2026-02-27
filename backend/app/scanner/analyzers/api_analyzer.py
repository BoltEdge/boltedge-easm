# app/scanner/analyzers/api_analyzer.py
"""
API Security Analyzer.

Reads API endpoint discovery data from the HTTP engine and produces
findings for exposed documentation, debug endpoints, sensitive files,
and unauthenticated API access.

Checks performed:
    CRITICAL:
        - .env file publicly accessible (credentials/secrets exposure)
        - .git repository exposed (source code leakage)
        - Spring Actuator /env or /configprops exposed (secrets leakage)

    HIGH:
        - Swagger/OpenAPI docs publicly accessible without auth
        - GraphQL endpoint with potential introspection
        - GraphQL IDE (GraphiQL) exposed
        - phpinfo() page exposed
        - ELMAH error log exposed
        - Go debug/vars or pprof endpoints exposed
        - Apache server-status or server-info exposed

    MEDIUM:
        - API root or versioned endpoints respond without auth
        - Spring Actuator root or health endpoint exposed
        - FastAPI/ReDoc documentation exposed
        - Debug pages detected

    LOW:
        - API health endpoint exposed
        - OpenID configuration exposed
        - JWKS endpoint exposed
        - API endpoints that require authentication (exist but protected)

    INFO:
        - security.txt found (positive finding)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext

logger = logging.getLogger(__name__)


# Maps endpoint type → severity and finding details
# Endpoints not in this map are skipped (no finding generated)
ENDPOINT_FINDINGS = {
    # ── CRITICAL — Secrets / Source Code Exposure ──
    "env_file": {
        "severity": "critical",
        "template_id": "api-env-file-exposed",
        "title_suffix": ".env file publicly accessible",
        "description": (
            "The .env file is publicly accessible at {url}. Environment files "
            "typically contain database credentials, API keys, secret keys, and "
            "other sensitive configuration. An attacker can read this file to "
            "obtain credentials for backend systems."
        ),
        "remediation": (
            "Immediately block public access to .env files. In Nginx: "
            "location ~ /\\.env { deny all; }. In Apache: add to .htaccess. "
            "Rotate ALL credentials found in the exposed file — they must be "
            "considered compromised."
        ),
        "cwe": "CWE-538",
        "tags": ["api", "sensitive-file", "credentials", "env"],
    },
    "git_config": {
        "severity": "critical",
        "template_id": "api-git-exposed",
        "title_suffix": ".git repository exposed",
        "description": (
            "The .git directory is publicly accessible at {url}. This exposes "
            "the entire source code repository including commit history, "
            "configuration files, and potentially hardcoded credentials. "
            "Tools exist to automatically reconstruct the full repository from "
            "an exposed .git directory."
        ),
        "remediation": (
            "Block access to the .git directory. In Nginx: "
            "location ~ /\\.git { deny all; }. In Apache: add RedirectMatch 404 /\\.git. "
            "Review the repository for any hardcoded secrets and rotate them."
        ),
        "cwe": "CWE-538",
        "tags": ["api", "sensitive-file", "source-code", "git"],
    },
    "git_head": {
        "severity": "critical",
        "template_id": "api-git-exposed",
        "title_suffix": ".git repository exposed",
        "description": (
            "The .git/HEAD file is publicly accessible at {url}. This confirms "
            "the .git directory is exposed, allowing attackers to reconstruct "
            "the full source code repository including commit history and "
            "potentially hardcoded credentials."
        ),
        "remediation": (
            "Block access to the .git directory. In Nginx: "
            "location ~ /\\.git { deny all; }. In Apache: add RedirectMatch 404 /\\.git. "
            "Review the repository for any hardcoded secrets and rotate them."
        ),
        "cwe": "CWE-538",
        "tags": ["api", "sensitive-file", "source-code", "git"],
    },
    "spring_actuator_env": {
        "severity": "critical",
        "template_id": "api-actuator-env-exposed",
        "title_suffix": "Spring Actuator /env endpoint exposed",
        "description": (
            "The Spring Boot Actuator /env endpoint is publicly accessible at {url}. "
            "This endpoint exposes all environment variables including database "
            "credentials, API keys, and application secrets. This is a critical "
            "information disclosure vulnerability."
        ),
        "remediation": (
            "Restrict access to Actuator endpoints. In application.properties: "
            "management.endpoints.web.exposure.include=health,info. "
            "Use Spring Security to require authentication for all Actuator endpoints. "
            "Rotate any credentials that may have been exposed."
        ),
        "cwe": "CWE-215",
        "tags": ["api", "debug", "spring-actuator", "credentials"],
    },
    "spring_actuator_config": {
        "severity": "critical",
        "template_id": "api-actuator-config-exposed",
        "title_suffix": "Spring Actuator /configprops endpoint exposed",
        "description": (
            "The Spring Boot Actuator /configprops endpoint is publicly accessible "
            "at {url}. This endpoint reveals all configuration properties including "
            "potentially sensitive values like database passwords and API tokens."
        ),
        "remediation": (
            "Restrict access to Actuator endpoints. In application.properties: "
            "management.endpoints.web.exposure.include=health,info. "
            "Use Spring Security to require authentication for all Actuator endpoints."
        ),
        "cwe": "CWE-215",
        "tags": ["api", "debug", "spring-actuator", "configuration"],
    },

    # ── HIGH — API Documentation / Debug Endpoints ──
    "swagger_json": {
        "severity": "high",
        "template_id": "api-swagger-exposed",
        "title_suffix": "Swagger/OpenAPI specification publicly accessible",
        "description": (
            "An OpenAPI/Swagger specification is publicly accessible at {url}. "
            "This reveals the complete API structure including all endpoints, "
            "parameters, authentication schemes, and data models. Attackers use "
            "this information to understand the API surface and craft targeted attacks."
        ),
        "remediation": (
            "Restrict access to API documentation. Serve it only behind "
            "authentication or on internal networks. If the API is intentionally "
            "public, ensure all endpoints have proper authentication and input "
            "validation."
        ),
        "cwe": "CWE-200",
        "tags": ["api", "documentation", "swagger", "openapi"],
    },
    "openapi_json": {
        "severity": "high",
        "template_id": "api-openapi-exposed",
        "title_suffix": "OpenAPI specification publicly accessible",
        "description": (
            "An OpenAPI specification is publicly accessible at {url}. "
            "This reveals the complete API structure including all endpoints, "
            "parameters, authentication schemes, and data models."
        ),
        "remediation": (
            "Restrict access to API documentation behind authentication "
            "or serve it only on internal networks."
        ),
        "cwe": "CWE-200",
        "tags": ["api", "documentation", "openapi"],
    },
    "openapi_yaml": {
        "severity": "high",
        "template_id": "api-openapi-exposed",
        "title_suffix": "OpenAPI specification publicly accessible",
        "description": (
            "An OpenAPI YAML specification is publicly accessible at {url}. "
            "This reveals the complete API structure."
        ),
        "remediation": (
            "Restrict access to API documentation behind authentication "
            "or serve it only on internal networks."
        ),
        "cwe": "CWE-200",
        "tags": ["api", "documentation", "openapi"],
    },
    "swagger_ui": {
        "severity": "high",
        "template_id": "api-swagger-ui-exposed",
        "title_suffix": "Swagger UI interactive API documentation exposed",
        "description": (
            "Swagger UI is publicly accessible at {url}. This provides an "
            "interactive interface where anyone can view all API endpoints and "
            "execute API calls directly from the browser. This significantly "
            "lowers the barrier for attackers to discover and exploit API vulnerabilities."
        ),
        "remediation": (
            "Remove Swagger UI from production or restrict access behind "
            "authentication. In Spring Boot: set springdoc.swagger-ui.enabled=false "
            "for production profiles."
        ),
        "cwe": "CWE-200",
        "tags": ["api", "documentation", "swagger-ui", "interactive"],
    },
    "graphql": {
        "severity": "high",
        "template_id": "api-graphql-exposed",
        "title_suffix": "GraphQL endpoint publicly accessible",
        "description": (
            "A GraphQL endpoint is publicly accessible at {url}. If introspection "
            "is enabled (the default in many frameworks), attackers can query the "
            "full schema to discover all types, queries, mutations, and their "
            "arguments — effectively a complete API blueprint."
        ),
        "remediation": (
            "Disable GraphQL introspection in production. Require authentication "
            "for all GraphQL queries. Implement query depth limiting and rate "
            "limiting to prevent abuse."
        ),
        "cwe": "CWE-200",
        "tags": ["api", "graphql", "introspection"],
    },
    "graphql_ide": {
        "severity": "high",
        "template_id": "api-graphql-ide-exposed",
        "title_suffix": "GraphQL IDE (GraphiQL) publicly accessible",
        "description": (
            "A GraphQL IDE (GraphiQL) is publicly accessible at {url}. This "
            "provides an interactive query builder that anyone can use to explore "
            "and execute GraphQL queries against the API."
        ),
        "remediation": (
            "Disable GraphiQL in production. Only enable it in development "
            "environments or behind authentication."
        ),
        "cwe": "CWE-200",
        "tags": ["api", "graphql", "graphiql", "interactive"],
    },
    "phpinfo": {
        "severity": "high",
        "template_id": "api-phpinfo-exposed",
        "title_suffix": "phpinfo() page publicly accessible",
        "description": (
            "A phpinfo() page is publicly accessible at {url}. This reveals "
            "the full PHP configuration including file paths, loaded extensions, "
            "environment variables, and server details. This information aids "
            "attackers in crafting targeted exploits."
        ),
        "remediation": (
            "Remove phpinfo.php from production servers. If needed for "
            "debugging, restrict access to internal networks or authenticated users."
        ),
        "cwe": "CWE-200",
        "tags": ["api", "debug", "phpinfo", "php"],
    },
    "elmah": {
        "severity": "high",
        "template_id": "api-elmah-exposed",
        "title_suffix": "ELMAH error log publicly accessible",
        "description": (
            "The ELMAH (Error Logging Modules and Handlers) page is publicly "
            "accessible at {url}. This exposes application error logs including "
            "stack traces, request details, and potentially sensitive data from "
            "error contexts."
        ),
        "remediation": (
            "Restrict ELMAH access to authenticated administrators. In web.config: "
            "add authorization rules to the elmah.axd location."
        ),
        "cwe": "CWE-209",
        "tags": ["api", "debug", "elmah", "error-log"],
    },
    "go_debug_vars": {
        "severity": "high",
        "template_id": "api-go-debug-vars-exposed",
        "title_suffix": "Go debug/vars endpoint publicly accessible",
        "description": (
            "The Go debug/vars endpoint is publicly accessible at {url}. "
            "This exposes runtime variables including command-line arguments, "
            "memory statistics, and any custom variables registered by the application."
        ),
        "remediation": (
            "Do not expose Go debug endpoints in production. Remove or restrict "
            "the /debug/ handler behind authentication or an internal network."
        ),
        "cwe": "CWE-215",
        "tags": ["api", "debug", "go", "runtime"],
    },
    "go_pprof": {
        "severity": "high",
        "template_id": "api-go-pprof-exposed",
        "title_suffix": "Go pprof profiling endpoint publicly accessible",
        "description": (
            "The Go pprof profiling endpoint is publicly accessible at {url}. "
            "This exposes CPU profiles, memory allocations, goroutine stacks, "
            "and other runtime data that reveals application internals."
        ),
        "remediation": (
            "Do not expose pprof endpoints in production. Remove the "
            "net/http/pprof import or restrict access behind authentication."
        ),
        "cwe": "CWE-215",
        "tags": ["api", "debug", "go", "pprof", "profiling"],
    },
    "apache_status": {
        "severity": "high",
        "template_id": "api-apache-status-exposed",
        "title_suffix": "Apache server-status page publicly accessible",
        "description": (
            "The Apache server-status page is publicly accessible at {url}. "
            "This reveals active connections, request details, client IPs, "
            "and server performance data."
        ),
        "remediation": (
            "Restrict server-status to localhost or trusted IPs. In Apache config: "
            "<Location /server-status> Require local </Location>"
        ),
        "cwe": "CWE-200",
        "tags": ["api", "debug", "apache", "server-status"],
    },
    "apache_info": {
        "severity": "high",
        "template_id": "api-apache-info-exposed",
        "title_suffix": "Apache server-info page publicly accessible",
        "description": (
            "The Apache server-info page is publicly accessible at {url}. "
            "This reveals the full server configuration, loaded modules, "
            "and their settings."
        ),
        "remediation": (
            "Restrict server-info to localhost or trusted IPs. In Apache config: "
            "<Location /server-info> Require local </Location>"
        ),
        "cwe": "CWE-200",
        "tags": ["api", "debug", "apache", "server-info"],
    },

    # ── MEDIUM — Documentation / Debug (less severe) ──
    "fastapi_docs": {
        "severity": "medium",
        "template_id": "api-fastapi-docs-exposed",
        "title_suffix": "FastAPI documentation publicly accessible",
        "description": (
            "FastAPI auto-generated documentation is publicly accessible at {url}. "
            "This provides an interactive interface for exploring and testing API "
            "endpoints."
        ),
        "remediation": (
            "Disable docs in production by setting docs_url=None in the FastAPI app. "
            "Or restrict access via middleware or reverse proxy rules."
        ),
        "cwe": "CWE-200",
        "tags": ["api", "documentation", "fastapi"],
    },
    "redoc": {
        "severity": "medium",
        "template_id": "api-redoc-exposed",
        "title_suffix": "ReDoc API documentation publicly accessible",
        "description": (
            "ReDoc API documentation is publicly accessible at {url}. "
            "This reveals the API structure and data models."
        ),
        "remediation": (
            "Restrict access to API documentation behind authentication or "
            "disable in production."
        ),
        "cwe": "CWE-200",
        "tags": ["api", "documentation", "redoc"],
    },
    "spring_actuator": {
        "severity": "medium",
        "template_id": "api-actuator-root-exposed",
        "title_suffix": "Spring Boot Actuator root endpoint exposed",
        "description": (
            "The Spring Boot Actuator root endpoint is publicly accessible at {url}. "
            "This lists available management endpoints. While the root itself may "
            "not leak sensitive data, individual endpoints (env, configprops, etc.) "
            "may expose secrets if also accessible."
        ),
        "remediation": (
            "Restrict Actuator endpoints. In application.properties: "
            "management.endpoints.web.exposure.include=health,info. "
            "Require authentication for all Actuator endpoints."
        ),
        "cwe": "CWE-200",
        "tags": ["api", "debug", "spring-actuator"],
    },
    "spring_actuator_health": {
        "severity": "medium",
        "template_id": "api-actuator-health-exposed",
        "title_suffix": "Spring Boot Actuator health endpoint exposed",
        "description": (
            "The Spring Boot Actuator health endpoint is publicly accessible "
            "at {url}. This may reveal service status, database connectivity, "
            "and dependency health information."
        ),
        "remediation": (
            "If health checks need to be public for load balancer probes, "
            "limit the detail: management.endpoint.health.show-details=never."
        ),
        "cwe": "CWE-200",
        "tags": ["api", "debug", "spring-actuator", "health"],
    },
    "debug_page": {
        "severity": "medium",
        "template_id": "api-debug-page-exposed",
        "title_suffix": "Debug page publicly accessible",
        "description": (
            "A debug page is publicly accessible at {url}. Debug pages may "
            "expose stack traces, environment variables, and internal "
            "application state."
        ),
        "remediation": (
            "Disable debug mode in production. Remove or restrict access to "
            "debug endpoints."
        ),
        "cwe": "CWE-215",
        "tags": ["api", "debug"],
    },
    "api_root": {
        "severity": "medium",
        "template_id": "api-root-exposed",
        "title_suffix": "API root endpoint publicly accessible without authentication",
        "description": (
            "The API root endpoint at {url} responds with JSON data without "
            "requiring authentication. This may allow enumeration of available "
            "API endpoints and their capabilities."
        ),
        "remediation": (
            "Require authentication for all API endpoints. If certain endpoints "
            "must be public, ensure they do not leak sensitive data or allow "
            "data modification."
        ),
        "cwe": "CWE-306",
        "tags": ["api", "unauthenticated", "enumeration"],
    },
    "api_versioned": {
        "severity": "medium",
        "template_id": "api-versioned-exposed",
        "title_suffix": "Versioned API endpoint publicly accessible without authentication",
        "description": (
            "A versioned API endpoint at {url} responds without requiring "
            "authentication. This confirms an active API that may expose data "
            "or functionality to unauthenticated users."
        ),
        "remediation": (
            "Require authentication for all API endpoints. Review what data "
            "and operations are accessible without credentials."
        ),
        "cwe": "CWE-306",
        "tags": ["api", "unauthenticated"],
    },

    # ── LOW — Informational ──
    "api_health": {
        "severity": "low",
        "template_id": "api-health-exposed",
        "title_suffix": "API health endpoint publicly accessible",
        "description": (
            "An API health check endpoint is publicly accessible at {url}. "
            "This reveals whether the service is running and may include "
            "dependency status information."
        ),
        "remediation": (
            "Health endpoints are often intentionally public for load balancer "
            "probes. Ensure they do not expose detailed internal status. "
            "Consider restricting to internal networks if not needed externally."
        ),
        "cwe": "CWE-200",
        "tags": ["api", "health", "informational"],
    },
    "openid_config": {
        "severity": "low",
        "template_id": "api-openid-config-exposed",
        "title_suffix": "OpenID Connect configuration exposed",
        "description": (
            "The OpenID Connect discovery document is accessible at {url}. "
            "This is often intentionally public (required by the protocol) but "
            "reveals the authentication infrastructure including issuer, "
            "authorization and token endpoints."
        ),
        "remediation": (
            "This is typically expected for OpenID Connect implementations. "
            "Ensure the authorization and token endpoints have proper security "
            "controls and rate limiting."
        ),
        "cwe": "CWE-200",
        "tags": ["api", "auth", "openid-connect"],
    },
    "jwks": {
        "severity": "low",
        "template_id": "api-jwks-exposed",
        "title_suffix": "JSON Web Key Set (JWKS) endpoint exposed",
        "description": (
            "The JWKS endpoint is accessible at {url}. This exposes public "
            "signing keys used for JWT validation. While these are public keys "
            "(not secrets), the endpoint reveals the authentication infrastructure."
        ),
        "remediation": (
            "JWKS endpoints are typically expected to be public. Ensure the "
            "keys are rotated regularly and that private keys are never exposed."
        ),
        "cwe": "CWE-200",
        "tags": ["api", "auth", "jwks", "jwt"],
    },

    # ── INFO — Positive findings ──
    "security_txt": {
        "severity": "info",
        "template_id": "api-security-txt-found",
        "title_suffix": "security.txt found",
        "description": (
            "A security.txt file was found at {url}. This is a positive "
            "finding — it indicates the organization has a responsible "
            "disclosure policy in place (RFC 9116)."
        ),
        "remediation": (
            "No action required. Ensure the security.txt contact information "
            "is up to date and that the team monitors the listed channels."
        ),
        "tags": ["api", "security-policy", "positive"],
    },
}


class APIAnalyzer(BaseAnalyzer):
    """
    Analyzes discovered API endpoints for security issues.

    Reads api_endpoints data from the HTTP engine and produces findings
    for exposed documentation, debug endpoints, sensitive files, and
    unauthenticated API access.
    """

    @property
    def name(self) -> str:
        return "api_analyzer"

    @property
    def required_engines(self) -> List[str]:
        return ["http"]

    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []

        http_data = ctx.get_engine_data("http")
        if not http_data:
            return drafts

        api_endpoints = http_data.get("api_endpoints", [])
        if not api_endpoints:
            return drafts

        domain = ctx.asset_value
        seen_template_ids = set()

        for endpoint in api_endpoints:
            endpoint_type = endpoint.get("type", "")
            finding_def = ENDPOINT_FINDINGS.get(endpoint_type)

            if not finding_def:
                continue

            template_id = finding_def["template_id"]

            # Deduplicate — e.g. git_config and git_head map to the same template
            if template_id in seen_template_ids:
                continue
            seen_template_ids.add(template_id)

            url = endpoint.get("url", "")
            path = endpoint.get("path", "")
            status_code = endpoint.get("status_code", 0)
            authenticated = endpoint.get("authenticated", False)
            evidence = endpoint.get("evidence", "")

            # For auth-required endpoints, downgrade severity to low
            severity = finding_def["severity"]
            if authenticated:
                severity = "low"

            # Build title
            title = f"{finding_def['title_suffix']} on {domain}"

            # Build description with URL
            description = finding_def["description"].format(url=url)
            if authenticated:
                description += (
                    f" Note: this endpoint requires authentication (HTTP {status_code}), "
                    f"which reduces the immediate risk."
                )

            drafts.append(FindingDraft(
                template_id=template_id,
                title=title,
                severity=severity,
                category="api",
                description=description,
                remediation=finding_def.get("remediation", ""),
                finding_type="api_security",
                cwe=finding_def.get("cwe"),
                tags=finding_def.get("tags", ["api"]),
                engine="http",
                confidence="high" if not authenticated else "medium",
                details={
                    "domain": domain,
                    "url": url,
                    "path": path,
                    "status_code": status_code,
                    "endpoint_type": endpoint_type,
                    "category": endpoint.get("category", ""),
                    "content_type": endpoint.get("content_type", ""),
                    "authenticated": authenticated,
                    "evidence": evidence,
                },
                dedupe_fields={
                    "check": "api_endpoint",
                    "template_id": template_id,
                    "domain": domain,
                },
            ))

        return drafts