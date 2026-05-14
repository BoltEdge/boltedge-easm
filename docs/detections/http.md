# HTTP Header + Behaviour Analysis

**Module:** `backend/app/scanner/engines/http_engine.py` + `backend/app/scanner/analyzers/header_analyzer.py` + `backend/app/scanner/analyzers/api_analyzer.py`
**Detects:** Missing or weak security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), permissive CORS, weak cookies (missing Secure/HttpOnly/SameSite), open redirects, HTTP-method anomalies, exposed API endpoints
**Plan gate:** Runs on all paid tiers via Standard / Deep profiles. Always-on once the engine is in the orchestrator
**Severity:** From the analyzer's per-header severity table. Permissive CORS with credentials → high; missing CSP → medium; missing X-Content-Type-Options → low

## Required setup

None.

## Optional setup

None.

## How to verify

```bash
# Trigger a scan; look for HTTP engine activity
docker compose logs easm-backend --tail=200 2>&1 | grep -i "HTTPEngine\|header_analyzer"

# Findings from header analysis:
docker compose exec easm-db psql -U easm_user -d easm -c "
SELECT public_id, severity, title FROM finding
WHERE category='headers' AND ignored=false AND resolved=false
ORDER BY id DESC LIMIT 10;
"
```

## Operational notes

- The engine does a small set of HTTP probes per endpoint (HEAD + GET / + GET a couple of common API paths). ~2-5 seconds total
- Cookie analysis happens here; the engine captures Set-Cookie headers and the analyzer flags missing attributes
- CORS misconfiguration detection runs by sending requests with the Origin header set to several test values and reading the Access-Control-* response headers
- Open redirect detection is best-effort — full coverage requires fuzzing every URL parameter, which we don't do (out of scope)

## Findings produced

| Template ID | Trigger | Severity |
|---|---|---|
| `header-missing-hsts` | No `Strict-Transport-Security` header | medium |
| `header-missing-csp` | No `Content-Security-Policy` | medium |
| `header-missing-xfo` | No `X-Frame-Options` or frame-ancestors CSP | low |
| `header-missing-xcto` | No `X-Content-Type-Options: nosniff` | low |
| `header-missing-referrer-policy` | No `Referrer-Policy` | low |
| `header-missing-permissions-policy` | No `Permissions-Policy` | low |
| `header-cors-wildcard-with-creds` | `Access-Control-Allow-Origin: *` + `Allow-Credentials: true` | high |
| `header-cors-permissive` | `Access-Control-Allow-Origin: *` (without creds) | medium |
| `cookie-missing-secure` | Session cookie without `Secure` flag | medium |
| `cookie-missing-httponly` | Session cookie without `HttpOnly` flag | medium |
| `cookie-missing-samesite` | Session cookie without `SameSite` attribute | low |
| `http-open-redirect` | Endpoint follows arbitrary `?next=` / `?url=` params | high |

**Customer-facing category:** Security Hygiene (headers), Misconfigurations (CORS, redirects)
