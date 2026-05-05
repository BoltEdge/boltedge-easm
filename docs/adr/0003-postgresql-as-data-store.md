# ADR 0003 — PostgreSQL as the Single Data Store

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-05-05 |
| Deciders | Founder / sole engineer |
| Supersedes | – |
| Superseded by | – |

## Context

Nano EASM stores: tenant data (orgs, users, assets, scans, findings), audit logs, billing state, integration settings, scheduled-job state, idempotency tables (Stripe events, webhook deliveries), and an unauthenticated quick-scan log. The data shape is overwhelmingly relational: orgs have users, assets, scans; scans produce findings; findings have a CWE id mapped to compliance frameworks. Cross-table joins are the norm.

There is also a category of "data we display but don't query much" — scan evidence, discovery raw outputs, asset enrichment metadata. These are flexible-shaped per-record.

We need to choose:
1. The primary data store.
2. Whether to add a secondary store (search index, document store, cache).

## Decision

**PostgreSQL 16 is the single data store** for all persistent state. We use `jsonb` columns for flexible-shaped data that lives alongside relational data.

Specifically:
- Tenant data, audit log, billing state — relational tables, scoped by `organization_id`.
- Scan evidence, asset metadata, finding evidence, report parameters — `jsonb` columns on the parent relational row.
- Idempotency tables (`stripe_event`, `audit_webhook_delivery`) — relational rows with unique constraints on the idempotency key.

We do **not** add Redis, Elasticsearch, MongoDB, S3, or any other store at this stage. (See ADR 0008.)

## Considered alternatives

| Alternative | Why rejected |
|---|---|
| **MySQL / MariaDB** | Comparable for our shape. Postgres wins on `jsonb` ergonomics, partial indexes, advisory locks (which we use for the scheduler), and CTE clarity. No reason to pick MySQL for green-field. |
| **MongoDB primary** | Our data is relational. The "document database" framing fits poorly when every read needs `{org, asset, scan, finding}` traversal. We'd reinvent joins. |
| **Postgres + Elasticsearch (search)** | Useful when the corpus is large and full-text search dominates the workload. Today we filter findings by structured fields; Postgres full-text + GIN indexes are sufficient for the search we have. Adding ES doubles operational surface for marginal benefit. |
| **Postgres + Redis (cache + queue)** | We'd love the queue (replaces in-process APScheduler at scale) but don't need it yet. Cache: most of our reads are cheap; we don't have hot-row contention. Premature now. |
| **Postgres + S3 (large evidence)** | Today, evidence is small (tens of KB per finding at the high end). When it grows past ~100 KB / row regularly, S3 with a pointer in Postgres is the right move. Not yet. |
| **DynamoDB / Spanner / CockroachDB** | We don't have multi-region or 100K-ops/s requirements. The trade-off (operational ceiling and cost) doesn't pay back at our scale. |

## Consequences

**Positive:**
- One backup target, one monitoring target, one migration tool, one query language. Operations is dramatically simpler.
- Joins are free. The data model can evolve without "denormalise this for the search index" pressure.
- `jsonb` absorbs schema evolution for evidence-shaped data without requiring a second store.
- Postgres advisory locks give us the scheduler-coordination primitive without Redis. Postgres's own concurrency model handles our "scheduler tick + request" race conditions.

**Negative:**
- All eggs in one basket. Postgres going down = full outage. We accept this at single-host scale; mitigated by snapshot backups + `pg_dump` (see §08 Backup & DR).
- No native horizontal scaling. When we need it, we step to RDS read replicas first; sharding is far in the future.
- `jsonb` queries are slower than dedicated columns. Columns we filter on regularly are promoted to first-class columns (rule from §05 Data §6).
- Long-running transactions hold locks. We avoid them by design (no big batch jobs in transactions; big work runs row-by-row outside a transaction).

## Notes

The first thing that pushes us off this decision is **scan workload concurrency outgrowing one host's connection pool**. At that point we (a) move Postgres off the app host (RDS), (b) tune `pgBouncer` in front of it, and (c) potentially add a Redis-backed queue (see ADR 0004's revisit conditions).

## References

- ADR 0008 (No cache/queue/search layer) — corollary
- ADR 0011 (Multi-tenancy shared schema) — depends on a single relational store
- §05 Data Architecture — full data model

---
