# app/scanner/engines/http_engine.py
"""
HTTP Probe data collection engine.

Connects to HTTP and HTTPS ports, collects response headers, status codes,
redirect chains, page titles, and server identification info.
Also probes for exposed API documentation and common API endpoints.

Pure Python — uses only stdlib urllib and ssl modules.

What this engine collects:
    - HTTP/HTTPS response status and headers
    - Redirect chain (follows up to 5 redirects)
    - Page title from <title> tag
    - Server software from Server header
    - Technology hints from X-Powered-By, Via, X-Generator, etc.
    - Cookie names and security flags (Secure, HttpOnly, SameSite)
    - Whether HTTP redirects to HTTPS
    - Exposed API endpoints and documentation

Output data structure (stored in EngineResult.data):
    {
        "probes": [
            {
                "url": "https://example.com:443",
                "port": 443,
                "scheme": "https",
                "status_code": 200,
                "headers": {"Server": "nginx/1.21", "Content-Type": "text/html", ...},
                "title": "Example Domain",
                "server": "nginx/1.21",
                "powered_by": "PHP/8.1",
                "redirect_chain": ["http://example.com → https://example.com"],
                "cookies": [
                    {"name": "session", "secure": true, "httponly": true, "samesite": "Lax"}
                ],
                "http_to_https_redirect": true,
                "response_time_ms": 245,
                "error": null
            }
        ],
        "api_endpoints": [
            {
                "url": "https://example.com/swagger.json",
                "path": "/swagger.json",
                "status_code": 200,
                "type": "swagger_json",
                "category": "api_documentation",
                "content_type": "application/json",
                "authenticated": false,
                "evidence": "OpenAPI/Swagger JSON schema detected"
            }
        ],
        "errors": []
    }

Profile config options:
    ports:    list[int] — which ports to probe (default: [80, 443])
    timeout:  int       — connection timeout in seconds (default: 10)
    check_api_endpoints: bool — probe for exposed API docs (default: true)
"""

from __future__ import annotations

import json
import logging
import re
import ssl
import time
from http.client import HTTPResponse
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from app.scanner.base import BaseEngine, EngineResult, ScanContext

logger = logging.getLogger(__name__)

# Default ports
DEFAULT_HTTP_PORTS = [80, 443]
EXTENDED_HTTP_PORTS = [80, 443, 8080, 8443]

# Title extraction regex
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Max response body to read for title extraction (64KB)
MAX_BODY_READ = 65536

# ---------------------------------------------------------------------------
# API endpoint probes
# ---------------------------------------------------------------------------
# Each entry defines a path to check, what type of API it indicates,
# and how to confirm it's actually an API doc vs a generic 404/redirect.
# ---------------------------------------------------------------------------

API_ENDPOINT_PROBES = [
    # ── OpenAPI / Swagger ──
    {
        "path": "/swagger.json",
        "type": "swagger_json",
        "category": "api_documentation",
        "confirm_content": ['"swagger"', '"openapi"', '"paths"'],
    },
    {
        "path": "/swagger/v1/swagger.json",
        "type": "swagger_json",
        "category": "api_documentation",
        "confirm_content": ['"swagger"', '"openapi"', '"paths"'],
    },
    {
        "path": "/openapi.json",
        "type": "openapi_json",
        "category": "api_documentation",
        "confirm_content": ['"openapi"', '"paths"'],
    },
    {
        "path": "/api/openapi.json",
        "type": "openapi_json",
        "category": "api_documentation",
        "confirm_content": ['"openapi"', '"paths"'],
    },
    {
        "path": "/openapi.yaml",
        "type": "openapi_yaml",
        "category": "api_documentation",
        "confirm_content": ["openapi:", "paths:"],
    },
    {
        "path": "/api-docs",
        "type": "swagger_ui",
        "category": "api_documentation",
        "confirm_content": ["swagger-ui", "Swagger UI", "api-docs"],
    },
    {
        "path": "/swagger-ui.html",
        "type": "swagger_ui",
        "category": "api_documentation",
        "confirm_content": ["swagger-ui", "Swagger UI"],
    },
    {
        "path": "/swagger-ui/",
        "type": "swagger_ui",
        "category": "api_documentation",
        "confirm_content": ["swagger-ui", "Swagger UI"],
    },
    {
        "path": "/docs",
        "type": "fastapi_docs",
        "category": "api_documentation",
        "confirm_content": ["swagger-ui", "openapi", "FastAPI"],
    },
    {
        "path": "/redoc",
        "type": "redoc",
        "category": "api_documentation",
        "confirm_content": ["redoc", "ReDoc"],
    },

    # ── GraphQL ──
    {
        "path": "/graphql",
        "type": "graphql",
        "category": "api_endpoint",
        "confirm_content": ["graphql", "GraphiQL", "playground", '"data"'],
        "methods": ["GET"],
    },
    {
        "path": "/graphiql",
        "type": "graphql_ide",
        "category": "api_endpoint",
        "confirm_content": ["graphiql", "GraphiQL"],
    },
    {
        "path": "/api/graphql",
        "type": "graphql",
        "category": "api_endpoint",
        "confirm_content": ["graphql", "GraphiQL", "playground", '"data"'],
    },

    # ── Well-known / Discovery ──
    {
        "path": "/.well-known/openid-configuration",
        "type": "openid_config",
        "category": "auth_endpoint",
        "confirm_content": ['"issuer"', '"authorization_endpoint"', '"token_endpoint"'],
    },
    {
        "path": "/.well-known/jwks.json",
        "type": "jwks",
        "category": "auth_endpoint",
        "confirm_content": ['"keys"', '"kty"'],
    },
    {
        "path": "/.well-known/security.txt",
        "type": "security_txt",
        "category": "security_policy",
        "confirm_content": ["Contact:", "contact:"],
    },

    # ── Common API base paths ──
    {
        "path": "/api",
        "type": "api_root",
        "category": "api_endpoint",
        "confirm_content": ['"version"', '"endpoints"', '"api"', '"status"'],
        "confirm_content_type": ["application/json"],
    },
    {
        "path": "/api/v1",
        "type": "api_versioned",
        "category": "api_endpoint",
        "confirm_content": ['"version"', '"endpoints"', '"api"', '"status"'],
        "confirm_content_type": ["application/json"],
    },
    {
        "path": "/api/v2",
        "type": "api_versioned",
        "category": "api_endpoint",
        "confirm_content": ['"version"', '"endpoints"', '"api"', '"status"'],
        "confirm_content_type": ["application/json"],
    },
    {
        "path": "/api/health",
        "type": "api_health",
        "category": "api_endpoint",
        "confirm_content": ['"status"', '"ok"', '"healthy"', '"alive"'],
        "confirm_content_type": ["application/json"],
    },

    # ── Debug / Admin endpoints ──
    {
        "path": "/actuator",
        "type": "spring_actuator",
        "category": "debug_endpoint",
        "confirm_content": ['"_links"', '"self"', '"actuator"'],
    },
    {
        "path": "/actuator/health",
        "type": "spring_actuator_health",
        "category": "debug_endpoint",
        "confirm_content": ['"status"', '"UP"', '"DOWN"'],
    },
    {
        "path": "/actuator/env",
        "type": "spring_actuator_env",
        "category": "debug_endpoint",
        "confirm_content": ['"propertySources"', '"activeProfiles"'],
    },
    {
        "path": "/actuator/configprops",
        "type": "spring_actuator_config",
        "category": "debug_endpoint",
        "confirm_content": ['"contexts"', '"beans"'],
    },
    {
        "path": "/_debug",
        "type": "debug_page",
        "category": "debug_endpoint",
        "confirm_content": ["debug", "stacktrace", "traceback", "environment"],
    },
    {
        "path": "/debug/vars",
        "type": "go_debug_vars",
        "category": "debug_endpoint",
        "confirm_content": ['"cmdline"', '"memstats"'],
    },
    {
        "path": "/debug/pprof/",
        "type": "go_pprof",
        "category": "debug_endpoint",
        "confirm_content": ["profile", "heap", "goroutine", "pprof"],
    },
    {
        "path": "/server-status",
        "type": "apache_status",
        "category": "debug_endpoint",
        "confirm_content": ["Apache Server Status", "Server Version"],
    },
    {
        "path": "/server-info",
        "type": "apache_info",
        "category": "debug_endpoint",
        "confirm_content": ["Apache Server Information", "Server Settings"],
    },
    {
        "path": "/elmah.axd",
        "type": "elmah",
        "category": "debug_endpoint",
        "confirm_content": ["Error Log for", "ELMAH"],
    },
    {
        "path": "/phpinfo.php",
        "type": "phpinfo",
        "category": "debug_endpoint",
        "confirm_content": ["phpinfo()", "PHP Version", "Configuration"],
    },
    {
        "path": "/.env",
        "type": "env_file",
        "category": "sensitive_file",
        "confirm_content": ["DB_PASSWORD", "DATABASE_URL", "SECRET_KEY", "API_KEY", "AWS_"],
    },
    {
        "path": "/.git/config",
        "type": "git_config",
        "category": "sensitive_file",
        "confirm_content": ["[core]", "[remote", "repositoryformatversion"],
    },
    {
        "path": "/.git/HEAD",
        "type": "git_head",
        "category": "sensitive_file",
        "confirm_content": ["ref: refs/"],
    },
]


class HTTPEngine(BaseEngine):
    """
    Probes HTTP/HTTPS ports and collects response metadata.

    For each port, attempts both HTTP and HTTPS connections (as appropriate),
    follows redirects, and extracts headers, title, and server info.
    Also probes for exposed API documentation and debug endpoints.

    Profile config:
        ports:   List of ports or "extended" for [80, 443, 8080, 8443].
        timeout: Connection timeout in seconds. Default 10.
        check_api_endpoints: Whether to probe API paths. Default True.
    """

    @property
    def name(self) -> str:
        return "http"

    @property
    def supported_asset_types(self) -> List[str]:
        return ["domain", "ip"]

    def execute(self, ctx: ScanContext, config: Dict[str, Any]) -> EngineResult:
        result = EngineResult(engine_name=self.name)

        # --- Config ---
        timeout = config.get("timeout", 10)
        ports_config = config.get("ports", DEFAULT_HTTP_PORTS)
        check_api = config.get("check_api_endpoints", True)

        if ports_config == "extended":
            ports = EXTENDED_HTTP_PORTS
        elif isinstance(ports_config, list):
            ports = ports_config
        else:
            ports = DEFAULT_HTTP_PORTS

        host = ctx.asset_value
        probes: List[Dict[str, Any]] = []
        errors: List[Dict[str, str]] = []

        for port in ports:
            # Decide scheme based on port
            schemes = self._schemes_for_port(port)

            for scheme in schemes:
                probe = self._probe_url(
                    host=host,
                    port=port,
                    scheme=scheme,
                    timeout=timeout,
                )
                if probe:
                    if probe.get("error"):
                        errors.append({
                            "url": probe.get("url", f"{scheme}://{host}:{port}"),
                            "error": probe["error"],
                        })
                    else:
                        probes.append(probe)

        if not probes and not errors:
            result.success = False
            result.add_error(f"No HTTP/HTTPS services found on ports {ports}")
            return result

        # Check if HTTP→HTTPS redirect exists
        http_probe = next((p for p in probes if p.get("scheme") == "http"), None)
        https_probe = next((p for p in probes if p.get("scheme") == "https"), None)

        if http_probe and https_probe:
            # Check if HTTP redirected to HTTPS
            chain = http_probe.get("redirect_chain", [])
            http_probe["http_to_https_redirect"] = any(
                "https://" in str(r) for r in chain
            )
        elif http_probe:
            http_probe["http_to_https_redirect"] = False

        # --- API endpoint discovery ---
        api_endpoints: List[Dict[str, Any]] = []
        if check_api and probes:
            # Use the best working probe to determine base URL
            # Prefer HTTPS on 443, then HTTP on 80, then whatever worked
            base_probe = (
                https_probe or http_probe or probes[0]
            )
            base_url = base_probe.get("final_url") or base_probe.get("url", "")

            # Normalize base URL — strip trailing slash
            if base_url.endswith("/"):
                base_url = base_url[:-1]

            api_endpoints = self._discover_api_endpoints(
                base_url=base_url,
                host=host,
                timeout=timeout,
            )

            if api_endpoints:
                logger.info(
                    f"HTTP Engine: found {len(api_endpoints)} API endpoint(s) on {host}"
                )

        result.data = {
            "probes": probes,
            "api_endpoints": api_endpoints,
            "errors": errors,
        }

        result.metadata = {
            "ports_checked": ports,
            "probes_successful": len(probes),
            "api_endpoints_found": len(api_endpoints),
            "api_paths_checked": len(API_ENDPOINT_PROBES) if check_api else 0,
            "errors_count": len(errors),
        }

        return result

    def _schemes_for_port(self, port: int) -> List[str]:
        """Determine which schemes to try for a given port."""
        if port == 80:
            return ["http"]
        if port == 443:
            return ["https"]
        if port in (8443, 993, 995, 465):
            return ["https"]
        if port == 8080:
            return ["http"]
        # Unknown port — try HTTPS first, then HTTP
        return ["https", "http"]

    def _probe_url(
        self,
        host: str,
        port: int,
        scheme: str,
        timeout: int,
    ) -> Optional[Dict[str, Any]]:
        """
        Make an HTTP(S) request and collect response metadata.
        Returns probe dict on success/error, None if connection refused.
        """
        # Build URL
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            url = f"{scheme}://{host}"
        else:
            url = f"{scheme}://{host}:{port}"

        probe: Dict[str, Any] = {
            "url": url,
            "port": port,
            "scheme": scheme,
            "host": host,
        }

        start_time = time.monotonic()

        try:
            # Create request with a browser-like user agent
            req = Request(url, headers={
                "User-Agent": "Mozilla/5.0 (compatible; XternSec Scanner)",
                "Accept": "text/html,application/xhtml+xml,*/*",
                "Accept-Language": "en-US,en;q=0.5",
            })

            # SSL context that doesn't verify (we want to probe even bad certs)
            ssl_ctx = None
            if scheme == "https":
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            response = urlopen(req, timeout=timeout, context=ssl_ctx)
            elapsed_ms = round((time.monotonic() - start_time) * 1000)

            probe["status_code"] = response.status
            probe["response_time_ms"] = elapsed_ms

            # Collect headers
            headers = {}
            for key, val in response.getheaders():
                headers[key] = val
            probe["headers"] = headers

            # Extract useful header values
            probe["server"] = headers.get("Server") or headers.get("server")
            probe["powered_by"] = (
                headers.get("X-Powered-By") or
                headers.get("x-powered-by")
            )

            # Read partial body for title extraction
            try:
                body_bytes = response.read(MAX_BODY_READ)
                body_text = body_bytes.decode("utf-8", errors="replace")
                title_match = TITLE_RE.search(body_text)
                probe["title"] = title_match.group(1).strip()[:200] if title_match else None
            except Exception:
                probe["title"] = None

            # Extract cookies
            probe["cookies"] = self._extract_cookies(headers)

            # Redirect chain
            probe["redirect_chain"] = []
            if hasattr(response, "geturl") and response.geturl() != url:
                probe["redirect_chain"].append(f"{url} → {response.geturl()}")
                probe["final_url"] = response.geturl()

            return probe

        except HTTPError as e:
            elapsed_ms = round((time.monotonic() - start_time) * 1000)
            probe["status_code"] = e.code
            probe["response_time_ms"] = elapsed_ms

            # Still collect headers from error responses
            headers = {}
            for key, val in e.headers.items():
                headers[key] = val
            probe["headers"] = headers
            probe["server"] = headers.get("Server") or headers.get("server")
            probe["powered_by"] = headers.get("X-Powered-By")
            probe["cookies"] = self._extract_cookies(headers)
            probe["title"] = None
            probe["redirect_chain"] = []

            return probe

        except URLError as e:
            reason = str(e.reason) if hasattr(e, "reason") else str(e)
            if "Connection refused" in reason or "Errno 111" in reason:
                return None  # Port closed, not an error
            probe["error"] = f"Connection failed: {reason}"
            return probe

        except Exception as e:
            probe["error"] = f"{type(e).__name__}: {str(e)}"
            return probe

    def _extract_cookies(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Extract cookie names and security flags from Set-Cookie headers."""
        cookies: List[Dict[str, Any]] = []

        # Headers might have multiple Set-Cookie entries
        # In our dict format, they get overwritten — check both forms
        for key in ("Set-Cookie", "set-cookie"):
            val = headers.get(key)
            if not val:
                continue

            # Parse the cookie
            cookie = self._parse_set_cookie(val)
            if cookie:
                cookies.append(cookie)

        return cookies

    def _parse_set_cookie(self, header_value: str) -> Optional[Dict[str, Any]]:
        """Parse a Set-Cookie header value into name + flags."""
        if not header_value:
            return None

        parts = header_value.split(";")
        if not parts:
            return None

        # First part is name=value
        name_val = parts[0].strip()
        name = name_val.split("=")[0].strip() if "=" in name_val else name_val

        flags_str = header_value.lower()

        return {
            "name": name,
            "secure": "secure" in flags_str,
            "httponly": "httponly" in flags_str,
            "samesite": self._extract_samesite(flags_str),
        }

    def _extract_samesite(self, cookie_str: str) -> Optional[str]:
        """Extract SameSite value from cookie string."""
        match = re.search(r"samesite\s*=\s*(\w+)", cookie_str, re.IGNORECASE)
        if match:
            return match.group(1).capitalize()
        return None

    # -------------------------------------------------------------------
    # API endpoint discovery
    # -------------------------------------------------------------------

    def _discover_api_endpoints(
        self,
        base_url: str,
        host: str,
        timeout: int,
    ) -> List[Dict[str, Any]]:
        """
        Probe common API documentation and debug endpoint paths.

        For each path in API_ENDPOINT_PROBES:
          1. Make an HTTP request to base_url + path
          2. Check if the response status is 200 (or 401/403 for auth-required)
          3. Verify the response body contains expected fingerprint content
          4. If confirmed, record the endpoint

        Returns a list of discovered API endpoints.
        """
        discovered: List[Dict[str, Any]] = []

        # Determine scheme for SSL context
        is_https = base_url.startswith("https://")

        ssl_ctx = None
        if is_https:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        for probe_def in API_ENDPOINT_PROBES:
            path = probe_def["path"]
            url = f"{base_url}{path}"

            endpoint_result = self._probe_api_path(
                url=url,
                path=path,
                probe_def=probe_def,
                ssl_ctx=ssl_ctx,
                timeout=timeout,
            )

            if endpoint_result:
                discovered.append(endpoint_result)

        return discovered

    def _probe_api_path(
        self,
        url: str,
        path: str,
        probe_def: Dict[str, Any],
        ssl_ctx: Optional[ssl.SSLContext],
        timeout: int,
    ) -> Optional[Dict[str, Any]]:
        """
        Probe a single API path and verify the response matches expectations.

        Returns endpoint dict if confirmed, None otherwise.
        """
        try:
            req = Request(url, headers={
                "User-Agent": "Mozilla/5.0 (compatible; BoltEdge EASM Scanner)",
                "Accept": "application/json, text/html, */*",
            })

            response = urlopen(req, timeout=min(timeout, 5), context=ssl_ctx)
            status = response.status

            # Read response body
            try:
                body = response.read(MAX_BODY_READ).decode("utf-8", errors="replace")
            except Exception:
                body = ""

            # Get content type
            content_type = ""
            for key, val in response.getheaders():
                if key.lower() == "content-type":
                    content_type = val.lower()
                    break

            # Verify content matches expectations
            confirmed = self._verify_api_content(
                body=body,
                content_type=content_type,
                probe_def=probe_def,
            )

            if not confirmed:
                return None

            # Determine evidence string
            evidence = self._build_api_evidence(
                probe_def=probe_def,
                status=status,
                content_type=content_type,
                body=body,
            )

            return {
                "url": url,
                "path": path,
                "status_code": status,
                "type": probe_def["type"],
                "category": probe_def["category"],
                "content_type": content_type,
                "authenticated": False,  # 200 means no auth required
                "evidence": evidence,
            }

        except HTTPError as e:
            # 401/403 means the endpoint exists but requires authentication
            # This is still worth recording — it confirms the API exists
            if e.code in (401, 403):
                return {
                    "url": url,
                    "path": path,
                    "status_code": e.code,
                    "type": probe_def["type"],
                    "category": probe_def["category"],
                    "content_type": "",
                    "authenticated": True,  # Auth required
                    "evidence": f"Endpoint exists but requires authentication (HTTP {e.code})",
                }

            # 404, 405, 500, etc. — endpoint doesn't exist or isn't relevant
            return None

        except (URLError, OSError, Exception):
            # Connection failed, timeout, etc. — skip silently
            return None

    def _verify_api_content(
        self,
        body: str,
        content_type: str,
        probe_def: Dict[str, Any],
    ) -> bool:
        """
        Verify the response body or content type matches the expected
        fingerprint for this API endpoint probe.

        Returns True if at least one fingerprint matches.
        """
        # Check content type filter if specified
        confirm_ct = probe_def.get("confirm_content_type", [])
        if confirm_ct:
            ct_matched = any(ct in content_type for ct in confirm_ct)
            if not ct_matched:
                return False

        # Check body content fingerprints
        confirm_content = probe_def.get("confirm_content", [])
        if not confirm_content:
            # No fingerprints to check — accept any 200 response
            return True

        body_lower = body.lower()
        return any(fp.lower() in body_lower for fp in confirm_content)

    def _build_api_evidence(
        self,
        probe_def: Dict[str, Any],
        status: int,
        content_type: str,
        body: str,
    ) -> str:
        """Build a human-readable evidence string for the API endpoint."""
        endpoint_type = probe_def["type"]
        category = probe_def["category"]

        evidence_map = {
            "swagger_json": "OpenAPI/Swagger JSON schema detected — full API structure exposed",
            "openapi_json": "OpenAPI JSON specification detected — full API structure exposed",
            "openapi_yaml": "OpenAPI YAML specification detected — full API structure exposed",
            "swagger_ui": "Swagger UI interactive documentation detected — API can be tested directly",
            "fastapi_docs": "FastAPI auto-generated documentation detected — API can be tested directly",
            "redoc": "ReDoc API documentation detected — API structure visible",
            "graphql": "GraphQL endpoint detected — may allow introspection queries",
            "graphql_ide": "GraphQL IDE (GraphiQL) detected — interactive query interface exposed",
            "openid_config": "OpenID Connect configuration exposed — reveals auth infrastructure",
            "jwks": "JSON Web Key Set exposed — reveals public signing keys",
            "security_txt": "security.txt found — responsible disclosure policy (informational)",
            "api_root": "API root endpoint returns JSON — API structure may be enumerable",
            "api_versioned": "Versioned API endpoint responds — API is accessible",
            "api_health": "API health endpoint exposed — reveals service status",
            "spring_actuator": "Spring Boot Actuator root detected — management endpoints may be exposed",
            "spring_actuator_health": "Spring Boot Actuator health endpoint exposed",
            "spring_actuator_env": "Spring Boot Actuator /env endpoint exposed — may leak environment variables and secrets",
            "spring_actuator_config": "Spring Boot Actuator /configprops endpoint exposed — may leak configuration details",
            "debug_page": "Debug page detected — may expose stack traces and internal state",
            "go_debug_vars": "Go debug/vars endpoint exposed — leaks runtime variables and memory stats",
            "go_pprof": "Go pprof profiling endpoint exposed — leaks performance data and goroutine info",
            "apache_status": "Apache server-status page exposed — reveals active connections and server info",
            "apache_info": "Apache server-info page exposed — reveals full server configuration",
            "elmah": "ELMAH error log exposed — reveals application errors and stack traces",
            "phpinfo": "phpinfo() page exposed — reveals full PHP configuration, paths, and environment",
            "env_file": ".env file publicly accessible — may contain database credentials, API keys, and secrets",
            "git_config": ".git/config exposed — source code repository may be downloadable",
            "git_head": ".git/HEAD exposed — source code repository may be downloadable",
        }

        return evidence_map.get(endpoint_type, f"API endpoint ({endpoint_type}) detected at HTTP {status}")