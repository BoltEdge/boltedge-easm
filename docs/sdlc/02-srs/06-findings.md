# SRS Module 06 — Findings Management

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 06 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies the finding entity, the curated finding template catalogue, the triage workflow, severity / scoring, compliance framework mapping, bulk operations, and the exposure-score rollups derived from findings.

---

## FR-FIND-001 — Finding template catalogue

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system shall maintain a curated catalogue of finding templates. Each template has:

- A unique stable template ID (e.g., `nuclei-cve-2021-44228`, `dns-spf-missing`)
- A title
- A severity (critical / high / medium / low / info)
- A category (e.g., DNS, Subdomain Takeover, Cloud, Leak, SSL, Headers, Ports, CVE, Tech, Exposure)
- A description (what this means)
- Remediation guidance (what to do about it)
- Reference URLs
- An optional CWE association
- A confidence indicator (high / medium / low)

The catalogue currently comprises ~330 templates. Synchronisation between the registry and the human-readable catalogue (`docs/finding-templates.md`) is enforced by a regenerator script and pre-commit hook.

---

## FR-FIND-002 — Finding produced from scan output

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

When a scan engine emits a result that matches a finding template, the system shall create a `Finding` row with:

**Acceptance criteria:**
- AC-1 Linked to the originating scan job and asset.
- AC-2 Status `open`.
- AC-3 The template's title, severity, description, remediation, references, and category.
- AC-4 An evidence payload — the engine-specific data that triggered the match.
- AC-5 An audit log entry `finding.created` is **not** written per finding (volume); aggregate scan-completed audit entry is sufficient.

---

## FR-FIND-003 — Finding status workflow

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Each finding has a status drawn from a fixed enum:

```
open → acknowledged → resolved
                    ↘ accepted_risk
                    ↘ suppressed
```

**Acceptance criteria:**
- AC-1 An Analyst (or higher) may transition between any two valid states.
- AC-2 Each transition is audit-logged with the old and new status.
- AC-3 A finding's status persists across re-scans of the same asset (a re-run that re-detects an `accepted_risk` finding does not bump it back to `open`).
- AC-4 Re-detecting a `resolved` finding flips it back to `open` and audit-logs `finding.regression`.

---

## FR-FIND-004 — Finding severity

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Findings carry one of five severities: `critical`, `high`, `medium`, `low`, `info`. Severity is set by the template at creation; an Admin may override on a per-finding basis with audit-logged `finding.severity_changed`.

---

## FR-FIND-005 — Compliance framework tagging

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Each finding shall surface its compliance framework mapping derived from CWE associations:

**Acceptance criteria:**
- AC-1 **Direct mapping** badges for OWASP ASVS 4.0, CIS Controls v8, NIST CSF v2.0, PCI-DSS 4.0 — these mappings come from the framework taxonomy and are labelled "direct".
- AC-2 **Cross-walked** badges for SOC 2 / ISO 27001 — derived through NIST CSF cross-walks and labelled "supports" with a citation. **Never labelled "direct"**, per NFR-COMP-001.
- AC-3 The findings page allows filtering by framework (e.g., "show me all findings that map to PCI-DSS 4.0").

---

## FR-FIND-006 — Finding detail view

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/findings/<id>` (or the modal opened from the findings list) shall present:

**Acceptance criteria:**
- AC-1 Title, severity, status, asset, asset criticality, asset group.
- AC-2 Template description and remediation.
- AC-3 Compliance framework chips (FR-FIND-005).
- AC-4 Evidence payload (what the scanner saw).
- AC-5 Status workflow controls: mark acknowledged / resolved / accepted-risk / suppressed.
- AC-6 Optional analyst notes per finding.
- AC-7 Reference links.
- AC-8 Cross-link back to the originating scan job.
- AC-9 [BEYOND SPEC] AI-assisted explanation panel where available.

---

## FR-FIND-007 — Findings list

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/findings` shall present a paginated list of all findings in the organisation, with:

**Acceptance criteria:**
- AC-1 Filter by status, severity, asset, asset group, template, compliance framework, time window.
- AC-2 Search by free text across title and asset value.
- AC-3 Bulk-select and bulk-update status (FR-FIND-008).
- AC-4 Severity counts at the top of the page.
- AC-5 Sort by severity, asset criticality, date detected.

---

## FR-FIND-008 — Bulk status update

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Analyst shall be able to update the status of many findings in one action:

**Acceptance criteria:**
- AC-1 Select up to 200 findings; choose target status.
- AC-2 The system applies the status transition per-finding, audit-logging each.
- AC-3 The response summarises processed / skipped / errored counts.

---

## FR-FIND-009 — Finding suppression

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

A finding may be suppressed at the template level for a specific asset or asset group, so future re-detections do not surface as new findings.

**Acceptance criteria:**
- AC-1 Suppression rule scope: per-template + per-asset, per-template + per-group, or per-template + organisation-wide.
- AC-2 Suppression is reversible.
- AC-3 The suppression rule is audit-logged.

---

## FR-FIND-010 — Manual finding creation

**Priority:** P1 — Should
**Status:** [PARTIAL — admin-only via the alert flow]

[GAP for the user-facing case.] An Analyst should be able to manually record a finding (e.g., observed during a manual review) without it being produced by a scan. The finding behaves identically to scan-produced findings except its origin is marked `manual`.

---

## FR-FIND-011 — Findings export (CSV)

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A user with read access shall be able to export the current findings list (with active filters applied) as CSV. Audit-log `export.findings`.

---

## FR-FIND-012 — Exposure score rollup

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system shall compute an exposure score for each asset and an aggregate score for each organisation:

**Acceptance criteria:**
- AC-1 Per-asset score = weighted sum of open finding severities × asset criticality multiplier.
  - Severity weights (default): critical=10, high=4, medium=1.5, low=0.3, info=0.
  - Criticality multipliers (per FR-ASSET-006): tier_1=1.5, tier_2=1.0, tier_3=0.5.
- AC-2 Per-organisation score = aggregate over assets, normalised to 0–100.
- AC-3 The score is labelled (Secure / Low Risk / Moderate / High Risk / Critical).
- AC-4 The dashboard exposes the org-level score on the home page.

---

## FR-FIND-013 — Save finding as alert

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

An Analyst shall be able to save a finding as a manual alert routed through the organisation's notification rules (Module 09). Useful for escalating individual findings without waiting for the scheduled monitor sweep.

---

## FR-FIND-014 — Finding "Nano AI" assist (AI-assisted explanation)

**Priority:** P2 — Could
**Status:** [BEYOND SPEC]

The platform offers an AI-assisted explanation panel that takes a finding's template and evidence and produces a plain-English summary plus suggested remediation. This is an enhancement on top of the templated guidance, not a replacement.

---

*End of module 06.*
