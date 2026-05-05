# ADR 0002 — Flask as Backend Framework

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-05-05 |
| Deciders | Founder / sole engineer |
| Supersedes | – |
| Superseded by | – |

## Context

Nano EASM's backend is a JSON REST API serving a single-page Next.js frontend, plus a small set of scheduled jobs. The team is one engineer; the deployment is one host. The shape of the workload:

- ~20 blueprints / domain areas, each with a handful of routes.
- Most routes do CRUD against PostgreSQL with tenant scoping; a few orchestrate longer-running scan / discovery work.
- Scheduled work (monitoring ticks, trial expiry, free-tier expiry) runs in the same process.
- External integrations: Stripe webhooks, Resend, Shodan, customer-supplied audit webhooks.

We need a Python web framework. The relevant axes:

- **Maturity / community size** — we want a framework that any contributor has likely seen, that has well-known idioms, and where googling errors works.
- **Synchronous-first** — the workload is mostly DB-bound CRUD with explicit threading for long jobs. We do not need a fully async runtime, and async-everywhere comes with library-ecosystem friction.
- **Extension surface** — JWT, migrations, rate limiting, CORS — we want each of these to be a 30-line decision, not a project.
- **Footprint** — small, predictable; not a kitchen-sink batteries-included framework where half the features go unused.

## Decision

We use **Flask** with these complementary libraries:
- **SQLAlchemy + Flask-SQLAlchemy** for ORM
- **Flask-Migrate (Alembic)** for schema migrations
- **Flask-JWT-Extended** for JWT auth
- **Flask-Limiter** for rate limiting
- **Flask-CORS** for CORS
- **APScheduler** (in-process) for scheduled jobs (see ADR 0004)
- **Gunicorn** (`gthread` workers) as the WSGI server in production

Each blueprint is a Python package under `app/` with `routes.py` + `service.py` + `schemas.py`.

## Considered alternatives

| Alternative | Why rejected |
|---|---|
| **FastAPI** | Async-first; valuable when the workload is many concurrent I/O calls per request. Our workload is mostly one DB hit per request with occasional thread-pool dispatch. The async ecosystem (async DB drivers, async Stripe SDK shims) adds complexity for marginal benefit at our scale. We may revisit at a future scaling step. |
| **Django** | Heavier. The admin we needed wasn't a Django admin (we built a bespoke superadmin console for our specific needs). DRF for the API would have worked but pulls in opinionated patterns we didn't need. The "all-in" surface (Django apps, signals, middleware ordering) costs more than it saves at our scale. |
| **Starlette / aiohttp / bare ASGI** | Too low-level. We'd reinvent extensions we get for free in Flask. |
| **Node.js (Express / Fastify) backend** | Splitting Python (scanner / scoring math) and Node (API) adds a process-boundary that buys nothing. The scanner ecosystem (Python tooling, Shodan SDK, vulnerability libraries) skews Python; doubling languages is a tax. |

## Consequences

**Positive:**
- Familiar idioms; easy to read for anyone who has touched Flask.
- Library-by-library composition — each piece is replaceable. We can swap Flask-Limiter without rewriting auth.
- Synchronous request handling makes thread-of-execution reasoning straightforward (per-request DB session, `g` object, transaction lifecycle).
- WSGI deployment is well-understood. Gunicorn `gthread` is boring and reliable.

**Negative:**
- No first-class async support. When we need to fan out concurrent I/O within a single request (e.g. discovery's 11 modules), we drop to `concurrent.futures` rather than `asyncio.gather`. This is fine today.
- Manual schema validation (Pydantic-or-Marshmallow). FastAPI's "function-signature is the schema" ergonomic is genuinely nice; we accept the slight overhead.
- Smaller batteries-included surface than Django. We've sized that against the surface we actually use.

## Notes

The decision is reversible per blueprint. If a future module is genuinely async-shaped (lots of I/O fan-out per request, or long-lived connections), we could host it on a sidecar FastAPI service behind the same Nginx — though doing so without good reason is a step backward in operational simplicity.

## References

- ADR 0004 (APScheduler) — depends on Flask's in-process model
- ADR 0007 (Single EC2 deployment) — single Gunicorn process per host

---
