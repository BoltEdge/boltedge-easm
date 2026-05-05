# SEO — Public Surface

| Field | Value |
|---|---|
| Document | SEO plan and inventory |
| Owner | Founder / sole engineer |
| Last reviewed | 2026-05-05 |
| Scope | Public marketing / legal / API-docs pages only |

This document records the SEO posture of the public Nano EASM website — what we did, where it lives in the codebase, and how to verify it after deploy. Authenticated app routes (`/dashboard`, `/assets`, `/scan`, `/settings`, `/admin`, etc.) are deliberately excluded from search indexing and not covered here.

---

## 1. Goals

- Make public pages crawlable and intelligible to search engines.
- Per-page **titles, meta descriptions, Open Graph, Twitter cards, canonicals**.
- **`sitemap.xml`** + **`robots.txt`** on the root.
- **JSON-LD structured data**: `Organization`, `SoftwareApplication`, `FAQPage`, `BreadcrumbList`.
- **Auto-generated Open Graph image** so social shares render with a card.
- **No** changes to UI/design, backend, Stripe, auth, or scanning behaviour.

---

## 2. Files added / changed

| File | What it does |
|---|---|
| `frontend/app/layout.tsx` | Root metadata: `metadataBase`, default title template, description, keywords, locale `en_AU`, canonical, robots flags |
| `frontend/app/sitemap.ts` | Next.js convention — auto-served at `/sitemap.xml`. Lists 12 public URLs with `lastmod` from file mtimes |
| `frontend/app/robots.ts` | Next.js convention — auto-served at `/robots.txt`. Allows `/`, disallows authenticated app + admin + auth-flow + anonymous compute surfaces |
| `frontend/app/opengraph-image.tsx` | Default 1200×630 OG image generated via `next/og` `ImageResponse` — dark teal gradient, bolt logo, headline, URL pill |
| `frontend/app/(unauthenticated)/JsonLd.tsx` | Tiny helper that renders `<script type="application/ld+json">` server-side |
| `frontend/app/(unauthenticated)/page.tsx` | Homepage metadata + `Organization` + `SoftwareApplication` JSON-LD |
| `frontend/app/(unauthenticated)/faq/page.tsx` | FAQ metadata + `FAQPage` JSON-LD with 8 curated Q/A entries |
| `frontend/app/(unauthenticated)/api-docs/page.tsx` | API Docs metadata |
| `frontend/app/(unauthenticated)/terms-and-policies/page.tsx` | Terms index metadata |
| `frontend/app/(unauthenticated)/terms-and-policies/[slug]/page.tsx` | Per-policy `generateMetadata()` + `BreadcrumbList` JSON-LD |

---

## 3. Per-page metadata inventory

| Page | Title (browser tab / SERP) | Description |
|---|---|---|
| `/` | Nano EASM — External Attack Surface Management | Discover external assets, scan for risk, monitor exposure changes, and turn findings into clear remediation steps with Nano EASM. |
| `/faq` | FAQ — Scanning, Pricing, Data, and Security Questions \| Nano EASM | Answers to common questions about Nano EASM, authorised scanning, pricing, data handling, integrations, and external exposure monitoring. |
| `/api-docs` | API Docs — Automate Asset Discovery, Scans, and Findings \| Nano EASM | Use the Nano EASM REST API to manage assets, run scans, retrieve findings, monitor exposure, and integrate with security workflows. |
| `/terms-and-policies` | Terms and Policies \| Nano EASM | Review Nano EASM terms, privacy, acceptable use, authorised scanning, subscription, refund, liability, and data handling policies. |
| `/terms-and-policies/<slug>` | `<Policy Title>` \| Nano EASM | `<Policy Title> — part of the Nano EASM Terms and Policies.` |

The `%s | Nano EASM` template is set on the root layout, so every per-page title gets the brand suffix automatically.

---

## 4. `sitemap.xml` content

Public URLs only. Authenticated routes are deliberately excluded.

```
https://nanoasm.com/                                     priority 1.0  weekly
https://nanoasm.com/faq                                  priority 0.8  monthly
https://nanoasm.com/api-docs                             priority 0.8  monthly
https://nanoasm.com/terms-and-policies                   priority 0.5  monthly
https://nanoasm.com/terms-and-policies/terms-of-use      priority 0.3  yearly
https://nanoasm.com/terms-and-policies/privacy-policy    priority 0.3  yearly
https://nanoasm.com/terms-and-policies/acceptable-use-policy            priority 0.3  yearly
https://nanoasm.com/terms-and-policies/security-scanning-authorisation  priority 0.3  yearly
https://nanoasm.com/terms-and-policies/subscription-payment-terms       priority 0.3  yearly
https://nanoasm.com/terms-and-policies/refund-cancellation-policy       priority 0.3  yearly
https://nanoasm.com/terms-and-policies/liability-limitation             priority 0.3  yearly
https://nanoasm.com/terms-and-policies/data-handling-retention          priority 0.3  yearly
```

`lastmod` for legal pages reads the file mtime of the underlying markdown in `frontend/content/legal/`, so re-publishing a policy bumps the date automatically.

---

## 5. `robots.txt` behaviour

```
User-agent: *
Allow: /
Disallow: /dashboard
Disallow: /assets
Disallow: /groups
Disallow: /scan
Disallow: /scan/
Disallow: /discovery
Disallow: /findings
Disallow: /monitoring
Disallow: /reports
Disallow: /trending
Disallow: /tools
Disallow: /settings
Disallow: /oauth/
Disallow: /admin
Disallow: /admin/
Disallow: /api/
Disallow: /login
Disallow: /login/
Disallow: /register
Disallow: /forgot-password
Disallow: /reset-password
Disallow: /reset-password/
Disallow: /verify-email
Disallow: /complete-profile
Disallow: /invite
Disallow: /quick-scan

Sitemap: https://nanoasm.com/sitemap.xml
Host: https://nanoasm.com
```

Rationale per disallow:
- **App routes** (`/dashboard`, `/assets`, etc.) — auth-gated; nothing for crawlers to see anyway, and indexing the login redirect would be noise.
- **Admin** — `/admin/*` returns 404 to non-superadmins, so crawlers can't index it, but explicit disallow makes intent obvious.
- **Auth flow** (`/login`, `/register`, `/reset-password`, etc.) — single-purpose pages, no SEO value, and indexing them adds noise to "Nano EASM login" SERPs.
- **`/quick-scan`** — anonymous compute surface. Indexing it would invite scrapers; we already rate-limit and block via the abuse log.

---

## 6. Structured data (JSON-LD)

| Page | Schema types injected |
|---|---|
| `/` | `Organization` + `SoftwareApplication` |
| `/faq` | `FAQPage` (8 curated Q/A entries) |
| `/terms-and-policies/<slug>` | `BreadcrumbList` (Home → Terms and Policies → `<Policy>`) |

The FAQ JSON-LD is a **curated subset** of the visible FAQ content, paraphrased into plain text. Google's [FAQPage rich-result guidelines](https://developers.google.com/search/docs/appearance/structured-data/faqpage) require the structured data to substantively match the visible page; the 8 entries cover the highest-value queries (what does Nano EASM do, scanning authorisation, pricing, data residency, API, MFA, integrations, cancellation).

If you add new top-level FAQ questions, mirror them into the `FAQ_JSONLD` array in `frontend/app/(unauthenticated)/faq/page.tsx`.

---

## 7. Open Graph image

Generated dynamically by `frontend/app/opengraph-image.tsx` using Next.js `ImageResponse`. Output: 1200×630 PNG, dark teal gradient with the bolt logo, "External Attack Surface Management" headline, and `nanoasm.com` URL pill.

Why dynamic instead of a checked-in PNG:
- No binary in the repo; one file, one source of truth.
- Tied to brand colours via the existing palette — re-skinning the brand updates the OG card automatically.
- No third-party rendering service (avoids leaking content / domain to QR or image services).

To preview locally: `npm run dev` then visit `http://localhost:3000/opengraph-image`.

---

## 8. Verification after deploy

Run all four checks once the new build is live:

1. **Sitemap** — `curl https://nanoasm.com/sitemap.xml` returns the 12-URL XML.
2. **Robots** — `curl https://nanoasm.com/robots.txt` returns the rules above.
3. **OG card** — paste `https://nanoasm.com` into [opengraph.xyz](https://www.opengraph.xyz/) and confirm the teal preview card renders.
4. **Structured data** — submit `https://nanoasm.com` and `https://nanoasm.com/faq` to [Google's Rich Results Test](https://search.google.com/test/rich-results) and confirm `Organization`, `SoftwareApplication`, and `FAQPage` are detected without errors.

After verification, **submit the sitemap to Google Search Console** at https://search.google.com/search-console — paste `https://nanoasm.com/sitemap.xml`. Same for Bing Webmaster Tools if you're targeting Microsoft search traffic.

---

## 9. Copy guidance (for future content edits)

For credibility — and to match the compliance posture in `docs/sdlc/05-security-policy.md` and the Acceptable Use Policy — avoid absolute claims like:

- ❌ "find every asset"
- ❌ "full visibility"
- ❌ "complete attack surface"
- ❌ "audit-ready for SOC 2"

Prefer:

- ✅ "help uncover exposed assets"
- ✅ "monitor exposure changes"
- ✅ "improve external visibility"
- ✅ "prioritise what matters"
- ✅ "surface findings that may inform your compliance evidence"

This phrasing is consistent across the SLA, DPA, and security policy documents.

---

## 10. Out of scope (future work)

These are the natural next moves but deliberately not in this batch:

1. **Lighthouse / Core Web Vitals audit** — LCP, CLS, INP. The hero animation may be hitting CLS; worth a Lighthouse run before/after deploy to confirm we haven't regressed.
2. **Blog / content marketing** — long-tail keyword targeting (e.g. "subdomain enumeration tool", "shadow IT discovery"). Compounding effort; build cadence.
3. **Backlinks** — security-product directories, comparison pages, integration partner pages.
4. **`hreflang`** — only relevant if/when we add EU localisation.
5. **Schema additions** — `Product` / `Offer` per plan tier on the pricing page (when billing UI is fully restored).
6. **HreflangIndex / sitemap segmentation** — split into `sitemap-pages.xml` and `sitemap-blog.xml` once the blog ships.

---

## 11. Related docs

- `docs/sdlc/01-vision-and-charter.md` — product positioning that informs SERP messaging
- `docs/sdlc/05-security-policy.md` — compliance posture that shapes copy guidance (§9 above)
- `Legal docs/security-scanning-authorisation.md` — the "only test what you own" guardrail referenced in OG/Twitter copy
- `CLAUDE.md` "Plan tiers and limits" — the pricing surfaced via `SoftwareApplication` Offer

---

*End of SEO plan and inventory.*
