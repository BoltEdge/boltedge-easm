# SRS Module 17 — API & Programmatic Access

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 17 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies the REST API surface, authentication for programmatic clients (API keys), what the API may and may not do versus the web app, and the public API documentation.

---

## FR-API-001 — REST API base

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system shall expose a REST API under `/api/...` (proxied to backend Flask) with:

**Acceptance criteria:**
- AC-1 JSON request and response bodies (`Content-Type: application/json`).
- AC-2 Consistent error shape (`{ "error": "...", "code": "...", ... }`).
- AC-3 Standard HTTP status codes (200, 201, 202, 400, 401, 403, 404, 409, 429, 5xx).
- AC-4 Versioning through the URL path is **not** used; backwards-incompatible changes require a deprecation cycle and customer communication.

---

## FR-API-002 — Authentication via JWT (web app)

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The web frontend authenticates to the API via the JWT issued at login: `Authorization: Bearer <jwt>` header. JWT lifetime + inactivity gate per FR-AUTH / NFR-SEC-005, NFR-SEC-006.

---

## FR-API-003 — Authentication via API key (programmatic)

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

External programmatic clients authenticate via API key:

**Acceptance criteria:**
- AC-1 Two equivalent transport mechanisms accepted: `Authorization: Bearer ag_sk_<rest>` or `X-API-Key: ag_sk_<rest>`.
- AC-2 The key prefix `ag_sk_` is reserved and stable; do not change without coordinated migration.
- AC-3 Server-side validation rate-limits per-key brute-force attempts.
- AC-4 Revoked keys return HTTP 401 immediately.
- AC-5 The key's organisation context is determined at validation time; the route's tenant scoping (NFR-SEC-008) applies as for any authenticated request.

---

## FR-API-004 — Endpoints accessible by API key

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

By default, API key authentication is **not** allowed; routes must explicitly opt-in via decorator (`@allow_api_key`). Routes that mutate billing, member-management, settings of significance, or any superadmin action shall **never** opt in.

**Acceptance criteria:**
- AC-1 Routes opt-in by decoration; default-deny.
- AC-2 An API key call to a non-opted-in route returns HTTP 403 with code `API_KEY_NOT_ALLOWED`.
- AC-3 Documented opt-ins include: read-only listings (assets, scan jobs, findings, reports, monitors), read-only details, scan kickoff, finding status updates, monitor read.
- AC-4 The list of opted-in routes is documented in the public API docs.

---

## FR-API-005 — Rate limiting on API key

**Priority:** P0 — Must
**Status:** [PARTIAL — basic per-route rate limits via Flask-Limiter where applied]

API-key calls shall be rate-limited per key to prevent runaway scripts. Defaults:

- AC-1 Read endpoints: 600 calls / hour / key
- AC-2 Write endpoints (scan kickoff, finding update): 60 calls / hour / key
- AC-3 Exceeded → HTTP 429 with `Retry-After`.

[GAP — explicit per-key limits not yet enforced beyond the per-IP and per-route defaults; tighten before public API GA.]

---

## FR-API-006 — API key creation, listing, revocation

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Per Module 14 (FR-SET-005) — Admin / Owner manages keys via `/settings/api-keys`. Plaintext shown once; storage hashed (NFR-SEC-011).

---

## FR-API-007 — Public API documentation

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system shall publish public API documentation at `/api-docs` covering at minimum: authentication, error shape, every opted-in endpoint with method, URL, request schema, response schema, example, and rate limits.

---

## FR-API-008 — OpenAPI / Swagger

**Priority:** P2 — Could
**Status:** [GAP: not implemented]

A machine-readable OpenAPI 3.x specification of the public API endpoints shall be available at `/api-docs/openapi.json`. Useful for customer-side codegen and Postman collections.

---

## FR-API-009 — CORS

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The API shall accept cross-origin requests **only** from the configured frontend origin(s). Wildcard origins are not permitted. Pre-flight requests are honoured for non-simple methods. Cookies are not used for API authentication, eliminating CSRF surface (NFR-SEC-021).

---

## FR-API-010 — Pagination

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

List endpoints shall page using `?page=<n>&limit=<m>` query parameters. Default limit is 50, maximum 200. Responses include `total`, `page`, `pages` so clients can paginate without a `Link` header.

---

## FR-API-011 — Filtering and sorting

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

List endpoints shall accept query parameters for the most common filters (status, severity, asset, date range) and sorting (`?sort=-created_at`). The exact parameter set per endpoint is documented in the API docs.

---

## FR-API-012 — Idempotency for write endpoints

**Priority:** P1 — Should
**Status:** [GAP: not implemented for the public API]

Write endpoints (scan kickoff, finding update) should accept an optional `Idempotency-Key` header allowing safe retry. [GAP — current implementation does not honour this header; clients today must take care not to double-submit.]

---

## FR-API-013 — Public ID acceptance

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Endpoints that accept a resource ID shall accept either the integer primary key OR the public display id (e.g., `AS0042`). The display id is the canonical user-facing identifier.

---

## FR-API-014 — API auditing

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Every API key call to a mutating endpoint produces an audit log entry tagged with the API key id (so revocation can correlate damage). API key reads are not audit-logged individually (volume), but per-key call counters are tracked for rate-limit purposes.

---

*End of module 17.*
