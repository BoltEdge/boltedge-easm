# SRS Module 08 — Reports

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 08 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies the PDF report generation pipeline — supported templates, scope, generation lifecycle, download behaviour, and retention.

---

## FR-REPT-001 — Report templates

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The system shall offer the following report templates:

| Template | Audience | Content |
|---|---|---|
| **Executive** | Non-technical stakeholders | Exposure score, severity-distribution charts, trend, top risks, no per-finding evidence |
| **Technical** | Security analysts | Full findings list with evidence, remediation, and references |
| **Compliance** | Auditors | Findings grouped by compliance framework (OWASP, CIS, NIST CSF, PCI-DSS) with explicit "supports" labels for SOC 2 / ISO 27001 |

---

## FR-REPT-002 — Report scope

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A report shall be generatable at:

- **Organisation scope** — all assets, all groups
- **Group scope** — one asset group's assets and findings

The user picks scope + template at creation time.

---

## FR-REPT-003 — Generate a report

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Analyst (or higher) shall be able to request a new report:

**Acceptance criteria:**
- AC-1 The form accepts template, scope (organisation / group), an optional title, and an optional time-window filter.
- AC-2 The system creates a `Report` row with status `pending` and queues the generation job.
- AC-3 The endpoint returns HTTP 202 with the report's display ID; the work runs asynchronously.
- AC-4 The user is notified (in-app, optionally email) when generation completes.
- AC-5 Audit-log `export.report`.

---

## FR-REPT-004 — Report lifecycle

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A report transitions through:

```
pending → generating → ready | failed
```

`ready` reports have a downloadable PDF; `failed` reports surface a sanitised error message.

---

## FR-REPT-005 — Report generation time

**Priority:** P1 — Should
**Status:** [PARTIAL]

See NFR-PERF-009 — a report (any template) for an organisation with ≤ 1000 findings shall be ready within 30 seconds.

---

## FR-REPT-006 — Report download

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A user with read access shall be able to download a `ready` report. The download:

**Acceptance criteria:**
- AC-1 Uses a signed URL or session-authenticated direct download (NOT a public URL).
- AC-2 Audit-log `export.report_downloaded`.
- AC-3 The download filename includes the org name, scope label, and date.

---

## FR-REPT-007 — Report listing

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/reports` shall list past reports filterable by template, scope, and status, with pagination. Each row shows status, scope, generated_by, generated_at, and a download button (when ready).

---

## FR-REPT-008 — Report deletion

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

An Admin may delete a report. The PDF artefact is deleted from storage; the row is removed. Audit-log `report.deleted`.

---

## FR-REPT-009 — PDF rendering — fallback to HTML

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

If the PDF library (e.g., xhtml2pdf, weasyprint) is unavailable, the system shall fall back to an HTML download with the same content. The user is informed in-page that the format is HTML.

---

## FR-REPT-010 — Report content correctness — exposure score

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The Executive report's headline exposure score shall match the live dashboard's number for the same scope at the time of generation.

---

## FR-REPT-011 — Report content correctness — compliance template

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The Compliance report shall:

**Acceptance criteria:**
- AC-1 Group findings by framework (OWASP, CIS, NIST CSF, PCI-DSS, SOC 2, ISO 27001).
- AC-2 Label SOC 2 and ISO 27001 sections with explicit "supports — verify with your auditor" wording (NFR-COMP-001).
- AC-3 Show finding counts per framework section.
- AC-4 Include the Acceptable Use Policy URL and the platform's compliance posture statement (charter §12) verbatim.

---

## FR-REPT-012 — Report retention

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

Generated reports shall be retained for at least 90 days from generation. Reports older than 12 months may be auto-pruned with a 30-day pre-deletion warning.

---

*End of module 08.*
