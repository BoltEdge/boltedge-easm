# SRS Module 03 — Asset Management

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 03 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies how an organisation declares, organises, classifies, and curates the assets it wants Nano EASM to monitor.

---

## FR-ASSET-001 — Asset types

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system shall support the following asset types as first-class entities:

- **Domain** — apex domains (`example.com`)
- **Subdomain** — derived hostnames (`shop.example.com`)
- **IP address** — IPv4 or IPv6 (`93.184.216.34`)
- **Cloud asset** — typed records for cloud-managed resources (S3 bucket, Azure storage, etc.)
- **Email asset** — derived MX / mail-server context

Each asset belongs to exactly one Asset Group within the organisation.

---

## FR-ASSET-002 — Add an asset (manual)

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Analyst (or higher) shall be able to add a single asset manually:

**Acceptance criteria:**
- AC-1 The form accepts the asset value, type (with validation per type — e.g., domain regex, IPv4 format, IPv6 format), an optional label, and an asset criticality tier (FR-ASSET-006).
- AC-2 The system validates that the value is well-formed for its type.
- AC-3 The system rejects duplicate assets within the same group with HTTP 409.
- AC-4 The asset count is checked against the plan's `assets` limit (FR-RBAC-012).
- AC-5 The new asset is associated with the chosen group and immediately available for scanning, monitoring, and discovery.
- AC-6 Audit-log `asset.created`.

---

## FR-ASSET-003 — Bulk add assets

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Analyst shall be able to add up to 500 assets at once via paste or upload (one asset per line or a CSV). The system reports per-asset success / skip / failure with reason in the response.

**Acceptance criteria:**
- AC-1 Plan-limit enforcement applies in aggregate (the partial batch is accepted up to the limit; the rest are rejected with reason `PLAN_LIMIT`).
- AC-2 Audit-log `asset.bulk_added` once per batch with summary metadata.

---

## FR-ASSET-004 — Update an asset

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Analyst shall be able to change an asset's label, criticality tier, and tags. The asset's value (e.g., the domain string) is immutable after creation; renaming requires delete + re-add.

---

## FR-ASSET-005 — Delete an asset

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

**Acceptance criteria:**
- AC-1 Single-asset delete cascades to that asset's scan jobs, findings, and monitors.
- AC-2 Bulk delete with confirmation is supported.
- AC-3 Audit-log `asset.deleted` (or `asset.bulk_deleted` for batches).

---

## FR-ASSET-006 — Asset criticality tier

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Each asset shall have a criticality tier: `tier_1`, `tier_2`, or `tier_3`, defaulting to `tier_2`.

The tier acts as a multiplier in exposure-score rollups (see Module 06):

- `tier_1` (1.5×) — crown-jewel assets where any finding is amplified
- `tier_2` (1.0×) — default
- `tier_3` (0.5×) — low-criticality assets where findings are dampened

**Acceptance criteria:**
- AC-1 Tier is settable on creation and editable thereafter.
- AC-2 The exposure score recalculation honours the tier weighting.
- AC-3 The asset list view shows the tier as a small badge.
- AC-4 The bulk-edit interface allows setting tier for many assets in one action.

---

## FR-ASSET-007 — Asset groups

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Assets shall be organised into named groups (e.g., "Production", "Subsidiary X"). Every asset belongs to exactly one group.

**Acceptance criteria:**
- AC-1 An Analyst may create, rename, archive, and delete groups.
- AC-2 Deleting a group with assets in it requires the assets to be reassigned or simultaneously deleted.
- AC-3 Reports, scans, and monitors can target either a specific group or the whole organisation.
- AC-4 Audit-log `group.created`, `group.updated`, `group.deleted`.

---

## FR-ASSET-008 — Asset tagging

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

Each asset shall carry an optional list of free-text tags (e.g., `prod`, `eu-region`, `legacy`). Tags are searchable / filterable in the asset list view.

**Acceptance criteria:**
- AC-1 Tags can be added and removed individually or in bulk.
- AC-2 The search box on the assets page supports `tag:foo` filter syntax.
- AC-3 Tags are tenant-scoped (no cross-tenant tag namespace).

---

## FR-ASSET-009 — Asset list view

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The `/assets` page shall present:

**Acceptance criteria:**
- AC-1 A list of asset groups with each group's asset count, IP count, domain count, email count, and cloud count.
- AC-2 Drill-into-group view that lists individual assets with type, value, criticality, tags, last scan time, finding counts by severity.
- AC-3 Search across groups and assets by name / value / label / type.
- AC-4 Pagination on large lists.
- AC-5 An "All Assets" view aggregating across groups.

---

## FR-ASSET-010 — Asset intelligence enrichment

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

The system shall, on demand or as part of scan completion, enrich an asset with intelligence data:

- WHOIS owner / registrar / expiry
- Reverse DNS
- IP reputation (where available)
- Service fingerprints (web technology stack, mail provider)
- Certificate details (issuer, expiry, SANs)

The enrichment data is displayed on the asset detail page.

**Acceptance criteria:**
- AC-1 Enrichment is best-effort — missing data does not error the page.
- AC-2 Enrichment refresh is rate-limited to once per asset per hour to avoid hammering upstream services.

---

## FR-ASSET-011 — Asset detail page

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/assets/<id>` shall present:

**Acceptance criteria:**
- AC-1 Asset value, type, group, criticality, tags.
- AC-2 Recent scan history (last 10) with status and finding counts.
- AC-3 Open findings for this asset, grouped by severity.
- AC-4 Active monitors targeting this asset.
- AC-5 Asset intelligence (FR-ASSET-010).
- AC-6 Action buttons: scan now, edit, delete, set criticality, manage tags.

---

## FR-ASSET-012 — Plan-limit-aware add affordance

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

When the organisation is at or near its asset limit, the "Add asset" UI shall:

- AC-1 Display current usage vs limit (e.g., "92/100 assets").
- AC-2 Disable the add button at the hard limit and show a clear "Upgrade for more" CTA linked to billing.
- AC-3 Reject server-side regardless of UI state (FR-RBAC-012 is the source of truth).

---

## FR-ASSET-013 — Group export (CSV)

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

A user with viewer-or-above role may export a group's assets as a CSV file (asset value, type, criticality, tags, last scan, exposure score). Audit-log `export.assets`.

---

*End of module 03.*
