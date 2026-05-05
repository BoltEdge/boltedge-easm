# SRS Module 04 — Asset Discovery

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 04 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies how Nano EASM discovers an organisation's externally-visible assets given a root domain — the discovery pipeline, the modules within it, the resulting "discovered assets" review queue, and the ingestion of accepted assets into the inventory.

---

## FR-DISC-001 — Launch a discovery job

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Analyst (or higher) shall be able to launch a discovery job against a root domain owned by the organisation.

**Acceptance criteria:**
- AC-1 The form accepts a root domain (regex-validated) and an optional list of opt-in modules to skip / include.
- AC-2 The system rejects domains that resolve to private / reserved / loopback IP ranges (NFR-SEC-020).
- AC-3 The system enforces the plan's `discoveries_per_month` limit (FR-RBAC-012).
- AC-4 A `DiscoveryJob` row is created with status `queued`, the requested modules, and the user_id.
- AC-5 The endpoint returns HTTP 202 with the job's display ID; work runs in the background.
- AC-6 Audit-log `discovery.started`.

---

## FR-DISC-002 — Discovery modules

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A discovery job shall execute the following modules in parallel where possible, sequentially where dependencies require:

| Module | Purpose | Default enabled |
|---|---|---|
| `dns_enum` | Brute-force common subdomains via DNS resolution | Yes |
| `ct_logs` | Query certificate transparency logs (crt.sh, etc.) for issued certificates | Yes |
| `shodan` | Shodan API: hosts, services, banners related to the domain | Yes |
| `subdomains_brute` | Wordlist-based subdomain bruteforce | Yes |
| `web_archive` | Wayback Machine / web archive enumeration | Yes |
| `reverse_dns` | Reverse-DNS sweep on resolved IP space | Yes |
| `mx_records` | Mail-server discovery via MX records | Yes |
| `cloud_buckets` | Heuristic discovery of S3 / Azure / GCS buckets following naming patterns | Yes |
| `github_search` | GitHub code-search heuristics for org-related leaks | Off by default; opt-in |
| `tls_sniff` | TLS handshake fingerprinting on resolved IPs | Yes |
| `aspx_dotnet_fingerprint` | Web stack fingerprinting (Apache, IIS, Cloudflare, etc.) | Yes |

**Acceptance criteria:**
- AC-1 Each module runs as an isolated unit; failure of one module does not abort the job.
- AC-2 Per-module status is recorded in `DiscoveryModuleResult` (status, assets found, duration, error if any).
- AC-3 The user can view per-module results in the job detail page.

---

## FR-DISC-003 — Deep discovery (Pro / Enterprise tiers)

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

Deep-discovery features (extended wordlists, recursive subdomain probing, full TLS scan of resolved IP space, more aggressive Shodan queries) shall be plan-gated to Professional tier and above (FR-RBAC-011).

---

## FR-DISC-004 — Discovery job status and progress

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`GET /discovery/jobs/<id>` shall return:

**Acceptance criteria:**
- AC-1 Job status: `queued`, `running`, `completed`, `failed`, `cancelled`.
- AC-2 Per-module results table.
- AC-3 Discovered asset count by type.
- AC-4 Start time, finish time, duration.
- AC-5 The user's organisation only — cross-tenant access blocked (NFR-SEC-008).

---

## FR-DISC-005 — Cancel a discovery job

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Analyst may cancel an in-flight discovery job. The system shall:

**Acceptance criteria:**
- AC-1 Mark the job's status as `cancelled`.
- AC-2 Abort any in-flight HTTP requests in the job's workers.
- AC-3 Preserve any assets discovered up to the cancellation point in the review queue.
- AC-4 Audit-log `discovery.cancelled`.

---

## FR-DISC-006 — Discovered asset review queue

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Assets surfaced by discovery do not automatically join the inventory. They land in a per-job review queue where the user accepts, rejects, or ignores each one.

**Acceptance criteria:**
- AC-1 The queue UI shows: asset value, type, source module, confidence indicator, and any enrichment metadata.
- AC-2 The user may filter by source module, type, and accepted-status.
- AC-3 The user may bulk-accept all assets, accept selected, or accept by source-module.
- AC-4 Acceptance is plan-limit-aware (FR-RBAC-012); over-limit acceptance returns HTTP 403.
- AC-5 Rejection is "ignore for this job" — re-running discovery may surface the asset again.
- AC-6 Audit-log `discovery.assets_accepted` (with counts and target group).

---

## FR-DISC-007 — Group assignment at acceptance

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

When accepting discovered assets, the user shall choose a target group (existing or new). The system creates the group on the fly if a new name is supplied.

---

## FR-DISC-008 — Discovered-asset deduplication

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

If a discovered asset already exists in the organisation's inventory (case-insensitive value match within the same type), it is **not** added a second time. The review queue marks it as "already in inventory".

---

## FR-DISC-009 — Tag accepted discovered assets

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

At acceptance time, the user shall be able to apply tags to all accepted assets in one action (e.g., `discovered`, `2026-Q2`).

---

## FR-DISC-010 — Discovery job listing

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/discovery` shall present a paginated list of past discovery jobs with status, root domain, asset counts, start time, and a link into the job detail.

---

## FR-DISC-011 — Discovery scheduling

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

An Admin may schedule a recurring discovery job (e.g., weekly) against a root domain. The scheduler runs at the configured cadence and respects the plan's `discoveries_per_month` limit; over-budget runs are skipped with a logged reason.

---

## FR-DISC-012 — Discovered-asset deletion (job cleanup)

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

A user may delete a discovery job entirely; the job and any discovered assets still in its review queue are removed. Already-accepted assets remain in the inventory.

---

*End of module 04.*
