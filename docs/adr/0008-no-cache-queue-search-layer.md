# ADR 0008 — No Cache, Queue, or Search Layer (Yet)

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-05-05 |
| Deciders | Founder / sole engineer |
| Supersedes | – |
| Superseded by | – |

## Context

Production SaaS architectures often grow a "supporting cast" early:

- **Redis** for caching, session storage, queue backing, rate-limit counters.
- **Elasticsearch / OpenSearch / Meilisearch** for full-text and faceted search.
- **S3 / object store** for large blobs (reports, evidence files).
- **Memcached** for read caching.

We don't have any of them. The temptation to add them — particularly Redis — is constant, because every blog post and reference architecture for "Python web app" assumes Redis is in the picture.

The question this ADR resolves: **do we add them now, or accept Postgres as the single store across all these concerns?**

## Decision

For the foreseeable single-host scale, we run with **none of these layers**:

| Layer | Substitute |
|---|---|
| Cache | None. Postgres handles read load fine. Hot-row caching not needed. |
| Queue | In-process APScheduler + thread pool (ADR 0004). |
| Rate-limit store | Flask-Limiter's default `memory://` (per-process). At one-process scale, this is correct. |
| Search | Postgres GIN indexes on `tsvector` columns where full-text is needed. Today, we filter findings by structured fields — even GIN is overkill. |
| Object store | EBS-backed filesystem inside the backend container, mounted to the host. Reports are tens of KB; evidence is JSON in `jsonb`. |
| Session store | Stateless JWT (ADR 0005). |

## Considered alternatives

| Alternative | Why rejected (today) |
|---|---|
| **Add Redis "just in case"** | An always-on dependency we'd hit in zero hot paths. Operational cost (monitoring, backup, version pinning) without offsetting benefit. |
| **Add Elasticsearch for findings search** | Findings are filtered by structured fields (severity, status, asset, date, CWE). Postgres B-tree indexes serve this fine. Full-text on a corpus this small (thousands of findings per org) does not justify a search cluster. |
| **Add S3 for report storage** | Reports are <1 MB. Filesystem on EBS is cheaper and simpler. When report volume or sharing requirements grow, S3 is a one-screen migration. |
| **Distributed rate limiting (Redis Flask-Limiter backend)** | Required when multiple processes share state. We have one Gunicorn process today (one host); per-process counters are correct. |

## Consequences

**Positive:**
- **One backup target.** Postgres dump captures everything important. No "did the Redis dump make it" worry.
- **One thing to monitor for health.** Postgres up = system up.
- **One thing to upgrade.** Major version upgrades happen on a known cadence; no Redis-version / ES-version cycles to track.
- **Cost.** Roughly half the AWS bill of a comparable "Redis + ES + RDS" deployment.
- **Mental model is simple.** New contributor reads `models.py`, runs `flask db upgrade`, has the whole picture.

**Negative:**
- **Some patterns are slightly slower.** Rate limiting is per-process; distributed rate limiting would be more accurate. Postgres caching is what we get from `shared_buffers`, not a millisecond app-layer cache. In practice, none of this is a hot path.
- **Some operations would be cheaper with the layer.** Rebuilding a complex finding query from scratch is microseconds slower than a cache hit. We accept the slight cost.
- **A future migration to add the layer is non-trivial.** Wiring Redis into Flask-Limiter, scheduler, and (eventually) cache is not one-screen work. We accept this and tackle it when it becomes load-bearing.

## When each layer earns its way in

| Layer | Adds value when |
|---|---|
| **Redis (rate limiting + lock store)** | We deploy a second backend host. Per-process rate limiting and file-lock scheduling no longer work; Redis is the natural rendezvous. |
| **Redis (queue backing for RQ / Celery)** | Concurrent scan throughput passes ~50 sustained, or scans need separate-process isolation. (ADR 0004 revisit.) |
| **Elasticsearch / Meilisearch** | Customers want free-text search across findings / assets / scan history that Postgres FTS can't keep up with. Probably 10K+ findings per org. |
| **S3** | Reports / evidence regularly exceed 1 MB, or we need pre-signed download URLs that bypass the API. |
| **Memcached / hot-row cache** | A specific read becomes a measured bottleneck. Not before. |

## References

- ADR 0003 (PostgreSQL) — the single store
- ADR 0004 (APScheduler) — the in-process queue substitute
- ADR 0007 (Single EC2) — corollary of single-host
- §04 Deployment View §10 — scaling path

---
