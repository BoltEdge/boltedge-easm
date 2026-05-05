# SRS Module 13 — Public Quick Scan

| Field | Value |
|---|---|
| Parent document | `02-srs.md` |
| Module ID | 13 |
| Status | Draft |
| Last reviewed | 2026-05-05 |

This module specifies the unauthenticated public Quick Scan tool — its target acceptance, abuse protection, output, and conversion-to-signup hand-off.

---

## FR-QSC-001 — Public Quick Scan endpoint

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

`/quick-scan` shall be a publicly accessible page (no authentication) where an anonymous visitor enters a domain or IP and receives a high-level exposure summary.

**Acceptance criteria:**
- AC-1 Input is validated (well-formed domain or IPv4 / IPv6).
- AC-2 The system rejects targets resolving to private / reserved IP ranges (NFR-SEC-020).
- AC-3 Result format includes: a summary risk score, severity counts (critical, high, medium, low, info), top findings (titles only, no detailed evidence), and a clear conversion CTA.
- AC-4 The result is delivered synchronously within a hard cap (≤ 60 seconds).

---

## FR-QSC-002 — Per-IP rate limiting

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Each source IP shall be limited to **5 Quick Scans per rolling hour**. Exceeded limit returns HTTP 429 with `Retry-After`.

---

## FR-QSC-003 — Quick Scan abuse log

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Every Quick Scan request — successful, blocked, or rate-limited — shall be logged to the `QuickScanLog` table with: source IP, user agent, target, status (`completed` / `rate_limited` / `blocked`), duration, risk score, finding counts.

---

## FR-QSC-004 — IP block list integration

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Every incoming Quick Scan request shall be checked against the platform's `BlockedIP` list. Blocked IPs receive HTTP 403 immediately and the attempt is logged.

---

## FR-QSC-005 — Trimmed / sanitised public output

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

The public Quick Scan output is intentionally a strict subset of the authenticated scan output:

- **Included:** risk score, severity counts, finding titles, generic remediation hint
- **Excluded:** detailed evidence, exploitation guidance, raw scan-engine output, CVE-specific exploit references, internal hostnames, cookie names, credential excerpts

This is enforced by a separate "public" code path (`run_*_check(target, full=False)`) on each scanner.

---

## FR-QSC-006 — Conversion CTA

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

Quick Scan results shall include a clear call-to-action linking to `/register?next=…` so the visitor can create an account and run a full scan against the same target.

---

## FR-QSC-007 — Admin visibility

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A superadmin shall be able to view the Quick Scan log at `/admin/quick-scans` with filters (date, status, IP) and a "top IPs in last 24 h" leaderboard for abuse triage.

---

## FR-QSC-008 — IP block management

**Priority:** P0 — Must
**Status:** [IMPLEMENTED]

A superadmin shall be able to add an IP to the block list with optional reason and expiry from `/admin/quick-scans` (or `/admin/blocked-ips`). Removing a block is similarly available.

---

## FR-QSC-009 — Honeypot field

**Priority:** P1 — Should
**Status:** [IMPLEMENTED — pattern reused from contact form; verify also present on Quick Scan]

The Quick Scan form shall include a hidden honeypot field; submissions with the field populated are silently ignored (responding with a fake-success page so the bot doesn't retry).

[GAP — verify in implementation; pattern is documented for the contact form but not strictly confirmed for the Quick Scan form.]

---

*End of module 13.*
