# Site Mimic Watch — coverage card copy (DRAFT, hold until engine ships)

> **Status:** Drafted 2026-05-16. Holds the customer-facing coverage-card
> copy until `mimic_engine` + `mimic_analyzer` + the 15-minute CT-log
> poller actually exist in the backend. See the design spec at
> `docs/superpowers/specs/2026-05-15-site-mimic-watch-design.md` and the
> operator-setup doc at `docs/detections/site-mimic.md`.
>
> **Why this isn't in the live coverage card yet:** the spec was approved
> 2026-05-15; backend implementation hasn't started. Publishing this copy
> at `nanoeasm.com/coverage/lookalike` before the engine ships
> would describe a feature customers cannot actually use.
>
> **When to drop this in:** once the engine + analyzer + scheduler job are
> deployed AND `MIMIC_ENABLED=true` on production, merge this content
> back into the `lookalike` entry in
> `frontend/app/(unauthenticated)/coverage/category-content.ts`.

## What changes vs. the live lookalike-only card

The live card is lookalike-only. This draft extends it to also cover
Site Mimic Watch — visual + structural clone confirmation on top of
variant detection.

### Label, title, meta, headline

```ts
label: "Lookalike Domains & Site Mimic Watch",
pageTitle: "Lookalike Domain Detection & Site Mimic Watch — Nano EASM",
metaDescription:
  "Detect typosquats, homoglyph confusables, TLD swaps, and other domains registered to impersonate yours — and confirm page-clone phishing with screenshot + structural similarity matching. Continuous monitoring; one weekly sweep per watched domain.",
headline: "Catch the domain a phisher just registered to look like yours — and prove it's a clone of your login page.",
```

### Intro paragraph

Replace the live intro's closing sentence with this expanded version:

```
Lookalike domain detection sits between attack surface management and brand protection. Attackers register thousands of variants every day — typos, vowel swaps, Cyrillic-letter substitutions, alternate TLDs — and the first time most teams find out is when a customer reports a phishing email. Nano EASM scans for the variants continuously so you see them while they're being prepared, not after they've been weaponised. **Site Mimic Watch** then renders each suspect URL and compares its screenshot, favicon, DOM structure, and key text against the baseline of your own pages — turning a list of 'maybe-suspicious' domains into a ranked list of confirmed clones, with the screenshot attached to the finding.
```

### Additional `whatWeDetect` bullets

Append these two bullets to the existing 6:

```
- Page-clone phishing sites — Site Mimic Watch fingerprints your real pages (screenshot perceptual hash, favicon hash, DOM structural hash, key strings) and matches the same signals against every suspect URL. A composite score above the high-confidence bucket means the suspect page is a visual + structural clone of yours, not just a same-sounding domain.
- Brand impersonation on unrelated domains — Site Mimic Watch also polls Certificate Transparency logs for any new certificate whose hostname contains your brand keyword, then renders and matches those candidates the same way. Catches phishing sites that don't follow a DNSTwist variant pattern (e.g. nanoeasm-secure-login.com).
```

### Extended `whyItMatters`

Append this sentence to the existing paragraph:

```
Site Mimic Watch raises the bar further: a takedown notice that includes 'here is the screenshot of our login page' next to 'here is the screenshot of theirs' moves through registrar abuse desks and hosting providers materially faster than a domain-only complaint.
```

### Extended `howItWorks`

Append this paragraph to the existing one (the existing paragraph
already has the en-dash + thousands-separator polish and the "Lookalike
finding on the parent domain" clarification that we kept in the live
copy when the rest of these mimic additions reverted):

```
Site Mimic Watch then takes the next step on each live candidate — and on any brand-keyword match from a separate CT-log poll that runs every 15 minutes: a headless Chromium renders the suspect page, the engine computes perceptual hashes of the screenshot and favicon, a structural hash of the DOM tree, and a Jaccard similarity over key text strings, then compares each signal to the asset's stored baseline. A composite score (max of weighted-average and strongest-single-signal) buckets the match as critical / high / medium / low, with the suspect screenshot attached to the resulting finding so you can decide and act in one view.
```

### Additional scenarios

Append these two scenarios to the existing 3:

```ts
{
  title: "Site Mimic Watch confirms a page-clone phishing site",
  body: "DNSTwist surfaces nano-easm-login.com as a live lookalike. Site Mimic Watch renders the page, computes its screenshot, favicon, DOM, and text hashes, and compares them to your baseline. The favicon hash matches perfectly, the screenshot perceptual hash is within 6 bits of yours, the DOM structural hash matches the login template, and 'Sign in to Nano EASM' appears in the body. Composite score lands in the critical bucket. The finding includes both screenshots side by side — exactly what you attach to a registrar abuse notice and your customer-comms warning.",
},
{
  title: "Brand-keyword certificate caught off-pattern",
  body: "Someone registers nanoeasm-secure-account-verify.com — a phrase no DNSTwist family would generate. They issue a Let's Encrypt cert and the hostname lands in the CT logs. Site Mimic Watch's 15-minute CT poller flags the brand keyword 'nanoeasm', queues the hostname for rendering, and the visual + favicon match confirms it's a clone of your login page. You see it the same day, not the day a phishing email lands in customer inboxes.",
},
```

### Additional SEO keywords

Append to the existing keyword array:

```
"site mimic watch",
"phishing page detection",
"page clone detection",
"visual similarity matching",
"perceptual hash phishing",
"screenshot similarity phishing",
"brand keyword CT monitoring",
```

## Drop-in checklist (when the engine ships)

- [ ] Confirm `mimic_engine.py` + `mimic_analyzer.py` exist and are registered in `backend/app/scanner/engines/__init__.py` / `analyzers/__init__.py`
- [ ] Confirm the 15-minute CT-log poller job (`_run_ct_log_monitor`) is registered in `backend/app/scheduler.py`
- [ ] Confirm `MIMIC_ENABLED=true` and `MIMIC_S3_BUCKET` are set on production
- [ ] Confirm Playwright + Chromium are in the production backend image
- [ ] Replace the `lookalike` entry in `frontend/app/(unauthenticated)/coverage/category-content.ts` using the snippets above
- [ ] Update the label everywhere it appears (sidebar, plan-feature lists, marketing nav) — search for the literal string `"Lookalike Domains"` in `frontend/` to find the references
- [ ] Re-verify each claim against the shipped code — buckets (`≥0.85 critical / ≥0.70 high / ≥0.55 medium / ≥0.40 low`), weights (visual 0.45, favicon 0.30, structural 0.15, text 0.10), and the composite formula (`max(weighted_avg, max_single_signal)`) must all match what the spec described

## Out of scope for this draft

- Plan-tier feature-comparison table updates (Site Mimic Watch will inherit the existing `lookalike_watch_domains` cap per the spec — no new line item, but the description on each tier may want to mention it)
- Landing-page hero/feature-grid copy
- Anything in the `/changelog` or release-notes section
