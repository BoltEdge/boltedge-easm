# SRS Module 12 — Lookup Tools

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 12 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies the authenticated **Lookup workspace** — the ad-hoc investigation panel with multiple per-tool query cards (Cert Lookup, DNS, WHOIS, Header Check, Sensitive Paths, GitHub Leaks, etc.) that an analyst can arrange, target, and run individually or in batch.

---

## FR-LOOK-001 — Lookup workspace

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/tools` shall present a workspace where the user can compose a set of tool panels, each running a specific lookup against a target.

**Acceptance criteria:**
- AC-1 The left sidebar lists every available tool, grouped by category (Discovery, Analysis, Recon).
- AC-2 The user adds a tool to the workspace by clicking it or dragging it onto the canvas.
- AC-3 Panels can be resized (8 directions: 4 edges, 4 corners) and re-arranged.
- AC-4 Panel layout is persisted in the user's browser via localStorage; refreshing preserves the workspace.
- AC-5 The plan tier caps the number of simultaneous panels (Free=3, Starter=6, Professional=12, Silver=12, Gold=18, Custom=24).

---

## FR-LOOK-002 — Available tools

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The workspace shall include the following tools (each is a tile in the sidebar; each runs a specific authenticated backend endpoint under `/tools/...`):

| Tool | Input | Output |
|---|---|---|
| Certificate Lookup | Domain or SHA-256 fingerprint | Cert details, TLS handshake, CT log history |
| DNS Lookup | Domain | All DNS record types + DKIM probe |
| Reverse DNS | IPv4 / IPv6 | PTR records + forward-confirmation |
| Header Check | Domain | HTTP security headers analysis with grade |
| WHOIS Lookup | Domain / IP / ASN | Registration / network / ASN details |
| Connectivity Check | Host:port | TCP reachability + banner grab + TLS detection |
| Email Security | Domain | SPF / DKIM / DMARC validation |
| Exposed Paths | Domain | Sensitive-paths sweep (.env, .git, dumps) |
| GitHub Leaks | Domain | Leaked credentials / secrets in public GitHub |

---

## FR-LOOK-003 — Per-panel input + run

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Each panel shall support:

**Acceptance criteria:**
- AC-1 An optional **local target** input (overrides the workspace-level shared target).
- AC-2 A **Run** button that fires the tool against the effective target (local target wins; otherwise shared workspace target).
- AC-3 An idle / running / done / error state with a result rendering pane.
- AC-4 In-flight cancellation when the user clicks Run again or removes the panel.

---

## FR-LOOK-004 — Workspace-level "Run All"

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A toolbar **Run All** button shall fire every panel that has an effective target. The system shall:

**Acceptance criteria:**
- AC-1 Run up to 3 tools concurrently per shared target (concurrency cap to avoid bursting the same host with N parallel probes).
- AC-2 Surface a "Running batch X/N" indicator with the current target.
- AC-3 Provide a Stop / Cancel button that aborts in-flight requests and breaks the loop.

---

## FR-LOOK-005 — Bulk targets mode

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

The workspace shall support a bulk-targets toggle that turns the shared target input into a textarea (one target per line). **Run All** in this mode iterates sequentially over each line, running the workspace's panels against each in turn (with the same per-target concurrency cap).

---

## FR-LOOK-006 — Workspace presets

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

The workspace shall include built-in presets that load a curated tool set tied to a common workflow:

- **Pre-engagement Recon** — WHOIS, DNS, certs, security headers
- **Email Posture** — DNS + SPF / DKIM / DMARC
- **DNS Hygiene** — DNS records, reverse DNS, certs
- **Exposure Audit** — Headers, exposed paths, GitHub leaks

The user shall be able to save additional custom presets named by them and stored in localStorage.

---

## FR-LOOK-007 — History

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

The workspace shall maintain a sliding window of the last 50 lookups (per browser, in localStorage). The history drawer shows tool, target, status, duration, and "ago" timestamp; clicking a row re-runs that target in that tool.

---

## FR-LOOK-008 — Cross-tool result chaining

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

A result that contains a derivable target (an IP returned from a DNS query, a hostname returned from reverse DNS, a domain on a covered cert) shall expose a "Send to..." chip that opens a small picker of compatible tools. Selecting one creates a new panel pre-targeted to that value and runs it.

---

## FR-LOOK-009 — Result diff vs previous run

**Priority:** P2 — Could
**Status:** [IMPLEMENTED — change indicator only, no full diff display]

A re-run of the same tool against the same target shall be compared (via content hash) against the previous run. If the hash differs, the panel title bar shows a "changed" badge. A full inline diff is out of scope.

---

## FR-LOOK-010 — Per-result notes

**Priority:** P2 — Could
**Status:** [IMPLEMENTED]

A user shall be able to attach a free-text note to any tool result (keyed by tool + target). Notes are stored in localStorage, debounced auto-save.

---

## FR-LOOK-011 — Save tool result as alert

**Priority:** P1 — Should
**Status:** [IMPLEMENTED]

A user shall be able to "Save as alert" against a tool result on plans that include monitoring (Starter+). The alert is created with a sensible suggested title and severity derived from the tool / result.

---

## FR-LOOK-012 — URL-shareable workspace

**Priority:** P2 — Could
**Status:** [IMPLEMENTED]

The user shall be able to copy a `#share=<encoded>` URL that captures the panel configuration + global target + bulk-mode flag. Pasting that URL into another browser restores the workspace shape (results re-fetch on Run; not included in the encoded payload).

---

## FR-LOOK-013 — SSRF / private-IP block

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Every tool that performs an outbound HTTP/network request shall block targets resolving to private / reserved / loopback / metadata IP ranges (NFR-SEC-020).

---

## FR-LOOK-014 — Audit logging

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Every tool invocation shall produce an audit log entry (`category="tool"`, `action="tool.<id>"`) with the target. This supports abuse review.

---

## FR-LOOK-015 — Disclaimer banner

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The workspace shall display a persistent disclaimer banner reminding users that some tools (port checks, exposed-path scanning, header probes) reach out to the target from Nano EASM infrastructure, and only authorised targets should be tested.

---

*End of module 12.*
