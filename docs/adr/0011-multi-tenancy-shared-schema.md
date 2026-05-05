# ADR 0011 — Multi-Tenancy: Shared Schema with `organization_id` Discriminator

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-05-05 |
| Deciders | Founder / sole engineer |
| Supersedes | – |
| Superseded by | – |

## Context

Nano EASM is a multi-tenant SaaS. Every customer is an "organization"; users belong to one organization; assets, scans, findings, audit logs, and so on are owned by one organization. Strict tenant isolation is non-negotiable — a leak between tenants is the worst-case bug for a security product.

There are three classical multi-tenancy patterns:

1. **Database per tenant.** Each tenant has its own physical database.
2. **Schema per tenant.** One database, one schema per tenant, identical tables in each.
3. **Shared schema.** One database, one set of tables, every tenant-scoped row carries a `tenant_id` column.

The decision determines: backup strategy, migration ergonomics, query patterns, isolation guarantees, and operational cost per customer.

## Decision

We use **shared schema** in a single PostgreSQL database. Every tenant-scoped table carries an `organization_id` foreign key. Tenant isolation is enforced in code: every read of a tenant-scoped model is filtered by `organization_id = g.user.org_id`.

Defence-in-depth:

1. **Query filter** — every `Model.query.filter_by(organization_id=...)` is the standard pattern. Drift is a code-review priority.
2. **Route decorator** — `@require_org_member` confirms the URL-referenced org matches the JWT's org.
3. **Foreign-key denormalisation** — child rows (e.g. `Finding`) carry their own `organization_id`, redundantly with the parent (e.g. `Asset`). Single-filter scoping at the leaf table is sufficient; we don't have to walk parent chains in every query.

## Considered alternatives

| Alternative | Why rejected |
|---|---|
| **Database per tenant** | Migration storm at every schema change (run N migrations, one per tenant). Backup multiplication. Connection-pool fragmentation. Wins on isolation strength — but at our scale (potential thousands of tenants), it becomes operationally unmanageable. Right answer for a small number of huge tenants; wrong answer for a SaaS with a long tail of small ones. |
| **Schema per tenant** | Same migration problem at slightly less cost. SQLAlchemy support for schema-per-tenant is awkward (search-path manipulation). The pattern is rarely used outside of legacy systems. |
| **Hybrid: shared schema with database-per-tenant for paid tiers** | Operational complexity ×2 — two code paths for every cross-tenant operation. Tempting, but actually rejected. |
| **Row-level security (RLS) policies in Postgres** | Genuinely strong defence-in-depth. We considered it. Reasons not to (yet): SQLAlchemy session setup gets more complex (per-request `SET SESSION` calls); test setup pays the cost too; we accept code-level discipline as the primary guard, and we will likely add RLS later as belt-and-braces. **This is a deliberate gap, flagged for re-evaluation**. |

## Consequences

**Positive:**
- **Migrations are single-shot.** `flask db upgrade` runs once for the whole platform.
- **Backups are single-shot.** One `pg_dump` covers everyone. Restoration is one operation.
- **Cross-tenant operations are easy** when intentional (admin views, scheduler ticks across orgs, billing webhook dispatch). The same DB session sees everything.
- **Connection pool is shared** — no per-tenant pool fragmentation.
- **Schema evolution is fast.** A new table is one migration, not N.
- **Operational simplicity** — Postgres pg_stat_activity, slow query log, and indexing decisions cover the whole platform.

**Negative:**
- **Code-discipline tax.** Every developer must remember `organization_id` filtering. We mitigate with reviewer attention, decorator helpers, and (eventually) RLS.
- **Single failure domain.** A query that holds a row lock can affect requests across tenants. Mitigated by short transactions and avoiding bulk operations in transactions.
- **Noisy-neighbour.** A tenant with 100K assets and an expensive query can starve another tenant briefly. We address it with limits (no unbounded queries), pagination on every list endpoint, and timeouts on slow operations.
- **Compliance posture is harder to argue.** Some enterprise prospects expect "your data is in its own database." We are honest in the SAD and DPA: shared schema with code-enforced isolation. We may add a "database-per-tenant" SKU at the Custom tier later if a customer pays for it.

## Defensive practices we enforce

- **Tests:** every tenant-scoped route has a test that creates two orgs and verifies user A cannot read / write user B's resource. Cross-tenant lookups return **404, not 403**, so we don't reveal existence.
- **Code review:** unscoped queries on tenant-scoped models are a high-priority finding. The reviewer is responsible.
- **Audit-log convention:** the `audit_log.organization_id` is **nullable** — null means "platform-level action," non-null means "tenant action scoped to that org." This makes admin audit views and per-tenant audit views unambiguous.

## Future evolution

- **Add Postgres RLS** as belt-and-braces defence-in-depth — second-tier guard so a missed `filter_by` does not become a leak. Cost: per-request `SET SESSION app.organization_id`; SQLAlchemy event hook.
- **Per-tier database isolation for Custom-tier** if an enterprise customer demands it as a contractual term. Implementable as a "tenant routing" layer that picks a connection by tenant id; we'd need to build connection-pool plumbing first.
- **Encrypt sensitive columns app-layer** so even a row leak (e.g. through a backup) doesn't expose plaintext for high-sensitivity fields. (See §05 Data §12 — known gap.)

## References

- ADR 0003 (PostgreSQL) — single store enables shared schema
- §05 Data Architecture §3 — tenant scoping detail
- §06 Security Architecture §8 — security-perspective view of tenant isolation
- §09 Key Scenarios §8 — cross-tenant attempted attack walk-through

---
