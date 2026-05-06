# SEO — Public Surface

| Field | Value |
|---|---|
| Document | SEO plan and inventory |
| Owner | Founder / sole engineer |
| Last reviewed | 2026-05-06 |
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
| `frontend/app/robots.ts` | Next.js convention — auto-served at `/robots.txt`. Allows `/`, disallows authenticated app + admin + auth-flow + anonymous compute surfaces. No `Host:` directive (Yandex-only, removed) |
| `frontend/middleware.ts` | Adds `X-Robots-Tag: noindex, nofollow` HTTP header on every authenticated/admin/auth-flow/quick-scan response — belt-and-braces alongside `robots.ts` since `Disallow:` is advisory and `X-Robots-Tag` is enforced |
| `frontend/app/opengraph-image.tsx` | Default 1200×630 OG image generated via `next/og` `ImageResponse` — dark teal gradient, bolt logo, headline, URL pill |
| `frontend/app/(unauthenticated)/JsonLd.tsx` | Tiny helper that renders `<script type="application/ld+json">` server-side |
| `frontend/app/(unauthenticated)/faq/faq-data.tsx` | Single source of truth for FAQ items — used by both the visible UI (FAQContent) and the JSON-LD generator (`faqsToJsonLd`). Guarantees structured data matches what users see |
| `frontend/app/(unauthenticated)/page.tsx` | Homepage metadata + `Organization` + `SoftwareApplication` JSON-LD |
| `frontend/app/(unauthenticated)/faq/page.tsx` | FAQ metadata + `FAQPage` JSON-LD covering all 27 visible questions, generated from `faq-data.tsx` |
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
https://nanoeasm.com/                                     priority 1.0  weekly
https://nanoeasm.com/faq                                  priority 0.8  monthly
https://nanoeasm.com/api-docs                             priority 0.8  monthly
https://nanoeasm.com/terms-and-policies                   priority 0.5  monthly
https://nanoeasm.com/terms-and-policies/terms-of-use      priority 0.3  yearly
https://nanoeasm.com/terms-and-policies/privacy-policy    priority 0.3  yearly
https://nanoeasm.com/terms-and-policies/acceptable-use-policy            priority 0.3  yearly
https://nanoeasm.com/terms-and-policies/security-scanning-authorisation  priority 0.3  yearly
https://nanoeasm.com/terms-and-policies/subscription-payment-terms       priority 0.3  yearly
https://nanoeasm.com/terms-and-policies/refund-cancellation-policy       priority 0.3  yearly
https://nanoeasm.com/terms-and-policies/liability-limitation             priority 0.3  yearly
https://nanoeasm.com/terms-and-policies/data-handling-retention          priority 0.3  yearly
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

Sitemap: https://nanoeasm.com/sitemap.xml
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
| `/faq` | `FAQPage` (all 27 visible questions, derived from `faq-data.tsx`) |
| `/terms-and-policies/<slug>` | `BreadcrumbList` (Home → Terms and Policies → `<Policy>`) |

The FAQ JSON-LD is **generated programmatically** from the same data structure that renders the visible FAQ accordion (`faq-data.tsx`). Every visible question is included; answers are flattened from JSX to plain text by `nodeToText()`. This guarantees compliance with Google's [FAQPage rich-result guidelines](https://developers.google.com/search/docs/appearance/structured-data/faqpage), which require structured data to substantively match what users see.

To add a new FAQ entry, add it to `FAQS` in `frontend/app/(unauthenticated)/faq/faq-data.tsx` — both the visible UI and the JSON-LD pick it up automatically.

---

## 7. Open Graph image

Generated dynamically by `frontend/app/opengraph-image.tsx` using Next.js `ImageResponse`. Output: 1200×630 PNG, dark teal gradient with the bolt logo, "External Attack Surface Management" headline, and `nanoeasm.com` URL pill.

Why dynamic instead of a checked-in PNG:
- No binary in the repo; one file, one source of truth.
- Tied to brand colours via the existing palette — re-skinning the brand updates the OG card automatically.
- No third-party rendering service (avoids leaking content / domain to QR or image services).

To preview locally: `npm run dev` then visit `http://localhost:3000/opengraph-image`.

---

## 8. Verification after deploy

Run all four checks once the new build is live:

1. **Sitemap** — `curl https://nanoeasm.com/sitemap.xml` returns the 12-URL XML.
2. **Robots** — `curl https://nanoeasm.com/robots.txt` returns the rules above.
3. **OG card** — paste `https://nanoeasm.com` into [opengraph.xyz](https://www.opengraph.xyz/) and confirm the teal preview card renders.
4. **Structured data** — submit `https://nanoeasm.com` and `https://nanoeasm.com/faq` to [Google's Rich Results Test](https://search.google.com/test/rich-results) and confirm `Organization`, `SoftwareApplication`, and `FAQPage` are detected without errors.

After verification, **submit the sitemap to Google Search Console** at https://search.google.com/search-console — paste `https://nanoeasm.com/sitemap.xml`. Same for Bing Webmaster Tools if you're targeting Microsoft search traffic.

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
7. **Product demo video** — capture a 30–45 s autoplay loop for the homepage hero ("see it in action"). Self-hosted MP4 + WebM fallback in `/public/`, `<video autoplay muted loop playsInline poster>`, with `VideoObject` JSON-LD on the page. Optionally a longer (2–5 min) walkthrough lower on the page via lite-youtube facade. Blocked on capturing the source video. See §11 below for the wiring plan when ready.

---

## 11. Demo video — wiring plan (when source video lands)

Documented now so the implementation is unambiguous when we get the video. Recommendation revisited: **self-host a 30–45 s muted autoplay loop on the homepage hero.** Privacy-first, no third-party tracking, ~2–4 MB encoded properly.

### Inputs needed
- Source video: 1920×1080 (or 16:9 equivalent), 30 fps, 30–45 s, no audio (or audio-optional with mute default)
- Poster image: 1920×1080 still frame from the video (~50–100 KB JPEG)

### Encoding (run locally with ffmpeg before drop-in)
```bash
# H.264 / MP4 — universal compatibility
ffmpeg -i source.mov -c:v libx264 -preset slow -crf 28 -an \
  -movflags +faststart -vf "scale=1920:1080" public/demo.mp4

# WebM / VP9 — smaller, modern browsers prefer it
ffmpeg -i source.mov -c:v libvpx-vp9 -crf 35 -b:v 0 -an \
  -vf "scale=1920:1080" public/demo.webm

# Poster
ffmpeg -i source.mov -ss 00:00:01 -frames:v 1 -q:v 3 public/demo-poster.jpg
```

### Element to drop into `app/(unauthenticated)/page.tsx` (replaces or sits alongside `<AnimatedDashboard />`)
```tsx
<video
  autoPlay
  muted
  loop
  playsInline
  preload="metadata"
  poster="/demo-poster.jpg"
  className="w-full rounded-2xl border border-white/[0.08] shadow-2xl"
  aria-label="Nano EASM dashboard demo: discover assets, scan for risk, monitor exposure"
>
  <source src="/demo.webm" type="video/webm" />
  <source src="/demo.mp4" type="video/mp4" />
</video>
```

### `VideoObject` JSON-LD to add on the homepage
```ts
const VIDEO_JSONLD = {
  "@context": "https://schema.org",
  "@type": "VideoObject",
  name: "Nano EASM Product Demo",
  description: "30-second walkthrough — discover external assets, scan for risk, monitor exposure changes.",
  thumbnailUrl: `${SITE_URL}/demo-poster.jpg`,
  uploadDate: "<ISO 8601 date>",
  duration: "PT30S", // ISO 8601 duration
  contentUrl: `${SITE_URL}/demo.mp4`,
};
// Add to <JsonLd data={[ORGANIZATION_JSONLD, SOFTWARE_APPLICATION_JSONLD, VIDEO_JSONLD]} />
```

### Out of scope for the autoplay loop, deferred for v2
- Captions / transcript file (`<track kind="captions">`) — only relevant if/when we add audio
- Longer (2–5 min) walkthrough via `lite-youtube` facade lower on the page — separate add-on once the loop ships
- Adaptive bitrate (HLS) — not needed at this length
- A dedicated `/tour` page — only if the longer walkthrough warrants it

---

## 12. Related docs

- `docs/sdlc/01-vision-and-charter.md` — product positioning that informs SERP messaging
- `docs/sdlc/05-security-policy.md` — compliance posture that shapes copy guidance (§9 above)
- `Legal docs/security-scanning-authorisation.md` — the "only test what you own" guardrail referenced in OG/Twitter copy
- `CLAUDE.md` "Plan tiers and limits" — the pricing surfaced via `SoftwareApplication` Offer

---

*End of SEO plan and inventory.*
