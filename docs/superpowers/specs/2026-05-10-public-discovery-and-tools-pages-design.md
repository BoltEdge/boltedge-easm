# Public Quick Discovery & Tools Pages — Design

**Date:** 2026-05-10
**Status:** Draft (pending user review)

## Goal

Promote the platform's existing public-endpoint surface from "embedded card on the landing page" to discoverable, SEO-targeted, dedicated pages that:

1. Mirror the success of `/quick-scan` (already a dedicated public page).
2. Capture top-of-funnel search traffic for keywords like "free WHOIS lookup", "free subdomain finder", "free DNS lookup tool".
3. Stay reachable from the landing page (visitors who skip the nav still see them).

All public endpoints already exist on the backend. This spec is purely a frontend + SEO + abuse-hardening exercise; no new business logic.

## Scope

### In scope

- New page: **`/quick-discovery`** — dedicated subdomain discovery page, hosting the existing `QuickDiscoveryCard` at full width plus intro/SEO copy and a registration CTA.
- New page: **`/tools`** — single combined page hosting all 8 lookup tools as a vertical accordion (one tool open at a time).
- Landing-page hookup — existing `QuickToolsSection` keeps its 3 in-place cards. Discovery + Tools cards each get a small "Open full page →" link that deep-links to the new pages.
- Nav update — add Quick Discovery + Free Tools entries to `LandingNav` (likely under a "Tools" dropdown alongside Quick Scan).
- Turnstile gating for the 8 `/tools/public/*` endpoints, matching the protection already on `/quick-scan` and `/quick-discovery`. Invisible mode means zero visible UI change.
- SEO metadata for both new pages: title, description, OG tags, JSON-LD `WebPage` + `SoftwareApplication` where appropriate.

### Out of scope

- Per-tool dedicated pages (e.g. `/tools/whois`). Decided against — single combined page chosen for faster shipping and simpler nav. Can revisit later if SEO data shows demand.
- Authenticated tool pages — already exist under `/(authenticated)/tools/*` and are unchanged.
- Backend logic changes — the 11 public endpoints already exist; only Turnstile decorators need to be added.
- New tools or new analyzers.

## Pages

### `/quick-discovery`

**Layout** (mirrors `/quick-scan` page structure):

1. **Hero block** — page title, one-paragraph intro explaining what subdomain discovery is and what data sources we use (CT logs, DNS resolution; deeper enumeration locked behind registration).
2. **Tool block** — full-width `QuickDiscoveryCard`. Currently lives in a 3-column landing grid; needs a wrapper or prop to stretch to a single-column hero width without changing the card's internals.
3. **What you get / what you miss** — short comparison: "free public discovery includes X" vs "registered users get Y". Drives the upgrade decision.
4. **CTA** — "Create a free account for deeper enumeration" linking to `/register`.

**Metadata:**

- Title: `Free Subdomain Finder & Asset Discovery — Nano EASM`
- Description: ≤155 chars. Mention "no signup", "CT logs", "free".
- JSON-LD: `WebPage` referencing the `SoftwareApplication` schema already defined for the platform.

### `/tools`

**Layout:**

1. **Hero block** — page title ("Free Security Lookup Tools"), one-paragraph intro framing this as a curated set of lookups for security teams (not a generic IP whois clone).
2. **Tool list** — vertical accordion with 8 rows. Default state: all collapsed (or first one open). Clicking a row header expands the input + result panel; clicking another row collapses the previous one.
3. **Per-tool row** — name, one-sentence description, severity/use-case tag (e.g. "DNS hygiene", "Cert lifecycle", "Email auth"). When expanded: input field, run button (disabled until valid), result panel, rate-limit notice.
4. **CTA at bottom** — "Run all of these on your full asset inventory — sign up free."

**Tools (in this order, surfacing highest-intent first):**

| # | Tool name | Endpoint | Input | Output preview |
|---|---|---|---|---|
| 1 | WHOIS Lookup | `/tools/public/whois` | domain | registrar, dates, contacts (trimmed) |
| 2 | DNS Lookup | `/tools/public/dns-lookup` | domain | A, AAAA, MX, NS, TXT records |
| 3 | Email Security | `/tools/public/email-security` | domain | SPF / DKIM / DMARC presence + grade |
| 4 | HTTP Header Check | `/tools/public/header-check` | URL or domain | security headers + grade |
| 5 | Certificate Lookup | `/tools/public/cert-lookup` | domain | issuer, validity, SAN list (trimmed) |
| 6 | Reverse DNS | `/tools/public/reverse-dns` | IP | resolved hostnames |
| 7 | Sensitive Paths | `/tools/public/sensitive-paths` | domain | found public paths (capped) |
| 8 | GitHub Leaks | `/tools/public/github-leaks` | domain | matching code-search results (capped) |

Cert Hash (`/tools/public/cert-hash`) is omitted from the visible list — niche, hash input is awkward, low SEO value. Keep the endpoint, just don't surface it. Revisit if we get demand.

**Metadata:**

- Title: `Free Security Lookup Tools — WHOIS, DNS, Cert, Headers — Nano EASM`
- Description: lists the highest-intent 3 (WHOIS, DNS, header check), mentions "no signup".
- JSON-LD: `WebPage` plus a `ItemList` enumerating the 8 tools as `SoftwareApplication` entries — gives Google a chance to render rich results.

## Backend changes

For each of the 8 `/tools/public/*` endpoints in `backend/app/tools/routes.py`:

1. Add `@public_abuse_check(source="tool_<short>", limit=10, label="<tool> runs")` decorator from `app/quick_scan/routes.py`. **Each tool gets its own source bucket** (e.g. `tool_whois`, `tool_dns`) so hitting one tool's cap doesn't lock out others.
2. Add Turnstile verification before running the tool: `ts_ok, ts_err = verify_turnstile(request); if not ts_ok: return jsonify(error=ts_err, code="TURNSTILE_FAILED"), 403`.
3. The tool function itself is unchanged — only the wrapper changes.

**Limits:** 10 runs/hour per IP per tool feels right for casual visitors but inadequate for power users — that's the upgrade nudge. Confirm the number with the user before shipping.

The `public_abuse_check` decorator currently lives in `quick_scan/routes.py`. If it's needed in `tools/routes.py` too, pull it out into a shared `app/utils/abuse_check.py` (or similar) so we don't import across blueprint modules.

## Landing-page changes

`QuickToolsSection.tsx` already renders `QuickScanCard`, `QuickDiscoveryCard`, `QuickToolsCard` as 3 in-place cards. Keep that. The only changes:

1. **Discovery card**: small "Open full page →" link below the result, linking to `/quick-discovery`. Visible only after the card has been used (when `result !== null`), so first-time visitors aren't distracted.
2. **Tools card**: same pattern — "See all 8 tools →" link to `/tools`. Visible after the card has been used.

No structural change to `QuickToolsSection`. The 3-card → 1-active-card grid behavior stays.

## Nav changes

`LandingNav.tsx` currently uses single-active-dropdown pattern. Add a **Tools** dropdown with three entries:

- Quick Scan → `/quick-scan`
- Quick Discovery → `/quick-discovery`
- Free Tools → `/tools`

If a Tools dropdown already exists with overlapping entries, merge — don't duplicate.

## Abuse protection summary

Once shipped, every public endpoint has uniform protection:

| Endpoint | Rate limit (per IP/hr) | Turnstile |
|---|---|---|
| `/quick-scan` | 5 | ✅ |
| `/quick-discovery` | 5 | ✅ |
| `/assistant/public-explain` | (existing) | ✅ |
| `/contact-requests` | (existing) | ✅ |
| `/tools/public/whois` | 10 | ✅ (new) |
| `/tools/public/dns-lookup` | 10 | ✅ (new) |
| `/tools/public/email-security` | 10 | ✅ (new) |
| `/tools/public/header-check` | 10 | ✅ (new) |
| `/tools/public/cert-lookup` | 10 | ✅ (new) |
| `/tools/public/cert-hash` | 10 | ✅ (new) |
| `/tools/public/reverse-dns` | 10 | ✅ (new) |
| `/tools/public/sensitive-paths` | 10 | ✅ (new) |
| `/tools/public/github-leaks` | 10 | ✅ (new) |

Each tool gets its own QuickScanLog source bucket so abuse on one doesn't gate the rest.

## Component reuse

- `QuickDiscoveryCard` — reuse as-is on `/quick-discovery`. Already has Turnstile wired and rate-limit-aware error rendering. The `onActiveChange` prop is optional, so the page can omit it.
- `QuickToolsCard` — current landing card. **Will become a thin wrapper** around 1-2 highlighted tools (or keep as-is) — TBD whether to refactor it now or leave for later. Default plan: leave it alone; the new `/tools` page is independent.
- `TurnstileWidget` — reused on every tool row. Eight widgets on one page is fine in Invisible mode (no visible UI). Each widget gets its own `widgetKey` state so re-issuing one fresh token doesn't tear down the others.

## Order of implementation

Splitting into 3 PRs keeps each one reviewable:

1. **PR 1 — Backend abuse hardening.** Move `public_abuse_check` to a shared module. Add the decorator + Turnstile verification to all 8 `/tools/public/*` endpoints. Tests: rate-limit hits return 429, missing Turnstile returns 403. Ship this first because it's purely additive — no UI change yet.
2. **PR 2 — `/quick-discovery` page.** New page, SEO metadata, landing-page "Open full page →" link, nav entry. Smallest UI surface, gets the SEO crawlers a head start while PR 3 is in review.
3. **PR 3 — `/tools` page.** Accordion list with 8 tool rows. Each row has its own input/output components. Largest scope; ship last.

## Open questions

1. **Tool rate-limit number.** 10/hr/IP/tool feels right for casual visitors but might frustrate power users. Confirm before shipping PR 1.
2. **Should the 1st tool open by default on `/tools`?** Probably yes (WHOIS) — gives visitors immediate "what does this look like" without a click. UX decision, will pick during PR 3 implementation.
3. **Per-tool icons.** Need a recognizable lucide icon for each (Globe, ShieldCheck, Mail, FileLock, etc.). Will pick during PR 3.
4. **Share/copy buttons in result panels.** Out of scope for v1, but worth noting for a v2 polish pass.

## Risks

- **8 simultaneous Turnstile widgets on `/tools`.** In invisible mode this should be fine (no visible UI), but Cloudflare might charge per challenge. Mitigation: check Turnstile billing tier before shipping, or fall back to rate-limit-only if cost is unacceptable.
- **SEO cannibalization between `/tools` and the 8 individual tool descriptions.** Single page means one URL ranking for many keywords — usually fine but Google sometimes prefers narrower pages. If `/tools` underperforms in search, revisit per-tool pages later.
- **Rate-limit DoS via tool combinations.** A bot can hit each of 8 tools at 10/hr = 80 runs/hr from one IP. Acceptable given backend cost is low, but watch the QuickScanLog volume in admin after launch.
