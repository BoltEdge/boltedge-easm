# Resources Pages — Wording Review & Polish

**Date:** 2026-05-10
**Status:** Approved (pending user review of this spec)
**Pages:** `/resources/what-is-nano-easm`, `/faq`, `/api-docs`

## Goal

Surgical wording + accessibility pass on the three pages grouped under "Resources" in the landing nav. Each page keeps its own editorial voice — what-is-nano-easm stays educational, FAQ stays conversational, api-docs stays technical reference. No structural rewrites.

## Decisions made during brainstorming

1. **Voice:** Each page keeps its existing voice; no unification across pages.
2. **Billing-OFF FAQs:** Trial / refund / cancellation / upgrade-downgrade items get rewritten for current state ("free upgrades until further notice"), not gated behind `BILLING_ENABLED`. When billing flips on later, those four items will need another rewrite.
3. **Verilog disambiguation:** Already removed from `/resources/what-is-nano-easm` (separate commit). The shorter parenthetical version in `faq-data.tsx` gets the same treatment in this pass.

## Out of scope

- No structural rewrites of any page.
- No changes to `/api-docs` endpoint reference content (curl examples, response shapes, error tables).
- No changes to FAQ taxonomy / category list.
- Plan-model changes (`monitored_assets = assets`, credit-pool pricing) are parked under "Pending Redesigns" in `CLAUDE.md` — explicitly NOT touched here. FAQ wording reflects today's state, not the future redesign.

## Page 1 — `/resources/what-is-nano-easm`

**File:** `frontend/app/(unauthenticated)/resources/what-is-nano-easm/page.tsx`

### Wording

| Location | Change |
|---|---|
| Hero `<p>` (around line 109-115) | "small MSSPs" → "MSSPs" |
| "Who is Nano EASM for?" `<li>` (around line 258) | "Small MSSPs" → "MSSPs" |
| "What Nano EASM detects" `<p>` (around line 188-196) | Replace "you can toggle any of them on or off for your organisation, and override per asset group" with: "mute the categories you don't care about, dial in the ones you do" |
| "Get started" `<p>` (around line 278-283) | Append a sentence: "Every paid tier is also free to upgrade until further notice — no card required." |

### Mechanical

- Add `<LandingFooter />` import and render at end of `<main>`.
- Bump body text contrast: `text-white/60`, `text-white/55`, `text-white/50` → `text-white/65` (5 instances).

## Page 2 — `/faq`

**Files:** `frontend/app/(unauthenticated)/faq/page.tsx`, `frontend/app/(unauthenticated)/faq/FAQContent.tsx`, `frontend/app/(unauthenticated)/faq/faq-data.tsx`

### Wording (all in `faq-data.tsx`)

| Item | Change |
|---|---|
| "What is Nano EASM?" (around line 28-39) | "small MSSPs" → "MSSPs". Delete the parenthetical "(Not to be confused with the similarly-named open-source Verilog assembler — Nano EASM is a security platform for the modern web, not a hardware tool.)". |
| "How do trials work?" (around line 297-306) | Tighten: "Trials are request-only — click **Request free trial** on any paid plan card and we'll review manually. If approved, the requested plan is enabled at no charge for a defined period. No payment method needed. When the trial ends, your org reverts to Free unless you switch to another tier." |
| "What happens if I exceed my plan limits?" (around line 309-317) | Replace with: "You'll see a clear message in the app explaining which limit you hit. Actions are blocked rather than billed — we don't do overages. Upgrading unlocks more scans, monitored assets, and team seats. Every paid tier is currently free to switch into." |
| "Can I upgrade or downgrade later?" (around line 319-328) | Replace with: "Yes, anytime — open **Settings → Plans** and pick the tier you want. Every paid tier is free to upgrade into until further notice, and the change takes effect immediately. When billing returns later, downgrades will apply at the end of the billing period; there's no contract lock-in." |
| "How do refunds and cancellations work?" (around line 330-342) | Replace with: "Plans are currently free to upgrade — there's nothing to refund or cancel. Closing your account anytime keeps your data accessible until you delete it manually. When billing returns, cancellations will take effect at the end of the billing period and refund exceptions follow our [Refund & Cancellation Policy](/terms-and-policies/refund-cancellation-policy)." |
| "Where is my data stored?" (around line 363-372) | Replace with: "On AWS in the United States (us-east-1 region) — chosen for sub-processor availability and global low-latency. International transfers follow the safeguards in our Privacy Policy. If you have a data-residency requirement, contact us — we can discuss options under a custom contract." |

### Mechanical

- Add `<LandingFooter />` to `page.tsx`.
- `page.tsx:61` subhead `text-white/50` → `text-white/65`.
- `FAQContent.tsx:47` accordion-body `text-white/60` → `text-white/65`.
- `FAQContent.tsx:106` empty-results line `text-white/40` → `text-white/55` (small text, currently failing AA).

## Page 3 — `/api-docs`

**File:** `frontend/app/(unauthenticated)/api-docs/page.tsx`

### Wording

| Location | Change |
|---|---|
| Footer paragraph (around line 588-598) | Replace "Need something not in this list? The full UI runs on a JWT-only API that mirrors most of the surface — drop us a note via the contact form." with "Need an endpoint we haven't documented? Some surface is reachable only via the session API used by the UI — let us know what you're trying to do via the contact form." |
| Sign-in secondary link (around line 477-481) | Change "or sign in →" to "Sign in first →" — clearer ordering for unauthenticated visitors who'd otherwise click "Generate an API key" and hit a redirect. |

### Mechanical

- Add `<LandingFooter />` import + render.
- Body text contrast (across the file):
  - `text-white/60` → `text-white/65` (~9 instances — endpoint descriptions, section blurbs, body paragraphs)
  - `text-white/55` → `text-white/65` (3 instances — sidebar links, "What API keys can't do" paragraph)
  - `text-white/50` → `text-white/65` (1 instance — "or sign in →" link)
- Small-text contrast:
  - `text-white/40` → `text-white/55` (2 instances — summary toggle text, footer paragraph)
  - `text-white/30` → `text-white/45` (2 instances — sidebar uppercase labels). User accepted slightly stronger contrast on labels.

## Acceptance criteria

- All three pages render `<LandingFooter />`.
- No occurrence of "small MSSPs" or "small MSSP" remains on these three pages.
- No Verilog disambiguation copy remains on these three pages.
- All flagged contrast classes match the proposed values.
- Body text on all three pages reads at `text-white/65` or stronger.
- Page builds clean (`npx tsc --noEmit` reports no new errors attributable to these files).

## Risks

- **Trial / refund / cancel FAQ rewrites will need another rewrite when billing returns.** Acceptable cost — keeping the answers accurate today is more important than minimising future churn.
- **Sidebar uppercase labels at `/45` may still feel light.** If contrast feels off after the change, bump to `/55` (visually heavier but compliant for body-size text per WCAG).
