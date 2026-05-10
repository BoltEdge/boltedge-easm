# Resources Pages Wording Review Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the surgical wording + accessibility pass agreed in the spec across `/resources/what-is-nano-easm`, `/faq`, and `/api-docs`. Each page commits independently as its own PR.

**Architecture:** Three phases, one commit per page. Each phase touches only its own files (no cross-page refactors). All edits are concrete string replacements (no abstractions, no new components). The repo has no test framework; each phase ends with a manual-verification checklist + a TypeScript pass.

**Tech Stack:** Next.js 16 App Router (server components), TypeScript, Tailwind 4. Already-existing `LandingFooter` component is the only shared dependency added.

**Spec:** `docs/superpowers/specs/2026-05-10-resources-pages-wording-review-design.md`

**Note on testing:** The repo has no test framework committed. Each phase uses concrete `grep` / `tsc` checks plus a manual browser walkthrough.

**Note on commit / push posture:** Per user standing rule, never auto-push. Each phase commits and waits for explicit "push" instruction before pushing.

---

## Phase 1 — `/resources/what-is-nano-easm`

### Task 1.1: All edits + commit

**Files:**
- Modify: `frontend/app/(unauthenticated)/resources/what-is-nano-easm/page.tsx`

- [ ] **Step 1: Add `LandingFooter` import**

```tsx
// In the import block at the top of the file, after `import LandingNav from "../../LandingNav";`
import LandingFooter from "../../LandingFooter";
```

- [ ] **Step 2: Render `<LandingFooter />` after `<main>`**

Find the existing closing of `<main>` and the trailing `</>` fragment. Insert `<LandingFooter />` between them:

```tsx
        </div>
      </main>

      <LandingFooter />
    </>
```

- [ ] **Step 3: Replace "small MSSPs" in hero**

Old:
```tsx
            It helps IT teams, security generalists, and small MSSPs discover
```

New:
```tsx
            It helps IT teams, security generalists, and MSSPs discover
```

- [ ] **Step 4: Replace "Small MSSPs" in "Who is Nano EASM for?"**

Old:
```tsx
              <strong className="text-white/80">Small MSSPs</strong> managing multiple
```

New:
```tsx
              <strong className="text-white/80">MSSPs</strong> managing multiple
```

- [ ] **Step 5: Replace "toggle for your organisation" feature-talk**

Old:
```tsx
            Every alert the platform raises falls into one of five categories. You
            can toggle any of them on or off for your organisation, and override per
            asset group — see the{" "}
```

New:
```tsx
            Every alert the platform raises falls into one of five categories. Mute
            the ones you don&rsquo;t care about, dial in the ones you do — see the{" "}
```

- [ ] **Step 6: Append free-upgrade sentence to Get Started paragraph**

Old:
```tsx
            Nano EASM has a Free plan with no payment details required — add up to two
            assets, run up to five scans a month, and see what your external attack
            surface actually looks like. Upgrade tiers add more assets, monitoring,
            scheduled scans, integrations, and team seats.
```

New:
```tsx
            Nano EASM has a Free plan with no payment details required — add up to two
            assets, run up to five scans a month, and see what your external attack
            surface actually looks like. Every paid tier is also free to upgrade until
            further notice — no card required.
```

- [ ] **Step 7: Bump `text-white/60` → `text-white/65` (replace_all)**

Use Edit with `replace_all: true`. This affects multiple body paragraphs uniformly.

Old: `text-white/60`
New: `text-white/65`

- [ ] **Step 8: Bump `text-white/55` → `text-white/65` (replace_all)**

Old: `text-white/55`
New: `text-white/65`

- [ ] **Step 9: Bump `text-white/50` → `text-white/65` (replace_all)**

Old: `text-white/50`
New: `text-white/65`

- [ ] **Step 10: Verify no `small MSSP` strings remain**

```bash
grep -n "small MSSP" "frontend/app/(unauthenticated)/resources/what-is-nano-easm/page.tsx"
```

Expected: no output (exit 1).

- [ ] **Step 11: Verify TypeScript builds clean for this file**

```bash
cd frontend && npx tsc --noEmit 2>&1 | grep "resources/what-is-nano-easm" | head -5
```

Expected: no output. Pre-existing errors elsewhere are out of scope.

- [ ] **Step 12: Stage and commit**

```bash
git add "frontend/app/(unauthenticated)/resources/what-is-nano-easm/page.tsx"
git commit -m "$(cat <<'EOF'
content(what-is): wording polish + footer + contrast

- Drop 'small' from 'small MSSPs' (global market positioning).
- Soften the 'toggle for your organisation' feature-talk into buyer
  language: 'mute the ones you don't care about, dial in the ones
  you do'.
- Append a free-upgrade-until-further-notice line to Get Started so
  the page matches current billing posture.
- Render LandingFooter (was missing — inconsistent with /quick-scan,
  /quick-discovery, /look-up-tools, /coverage).
- Bump body text-white/50 / 55 / 60 to /65 to clear WCAG AA on body
  copy contrast.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 13: Wait for explicit "push" instruction.** Per user rule, do not auto-push.

---

## Phase 2 — `/faq`

### Task 2.1: Wording rewrites in `faq-data.tsx`

**Files:**
- Modify: `frontend/app/(unauthenticated)/faq/faq-data.tsx`

- [ ] **Step 1: Update "What is Nano EASM?" — drop "small" + delete parenthetical**

Old (the full `a:` JSX value for the first FAQ item):
```tsx
        a: (
          <p>
            Nano EASM is an{" "}
            <strong>External Attack Surface Management</strong> platform — a
            cybersecurity SaaS product that helps IT teams, security generalists, and
            small MSSPs discover internet-facing assets, scan for risk, monitor
            exposure changes, and prioritise remediation. (Not to be confused with the
            similarly-named open-source Verilog assembler — Nano EASM is a security
            platform for the modern web, not a hardware tool.)
          </p>
        ),
```

New:
```tsx
        a: (
          <p>
            Nano EASM is an{" "}
            <strong>External Attack Surface Management</strong> platform — a
            cybersecurity SaaS product that helps IT teams, security generalists, and
            MSSPs discover internet-facing assets, scan for risk, monitor exposure
            changes, and prioritise remediation.
          </p>
        ),
```

- [ ] **Step 2: Replace "How do trials work?" answer**

Old:
```tsx
        q: "How do trials work?",
        a: (
          <p>
            Trials are <strong>request-only</strong> — click <em>Request free trial</em> on
            any paid plan card and we&rsquo;ll review the request manually. If approved, the
            requested plan is enabled on your organisation for a defined period at no charge.
            No payment method is required during the trial. If you don&rsquo;t convert, your
            organisation reverts to the Free plan when the trial ends.
          </p>
        ),
```

New:
```tsx
        q: "How do trials work?",
        a: (
          <p>
            Trials are <strong>request-only</strong> — click <em>Request free trial</em> on
            any paid plan card and we&rsquo;ll review the request manually. If approved, the
            requested plan is enabled at no charge for a defined period. No payment method
            is needed. When the trial ends, your organisation reverts to Free unless you
            switch to another tier.
          </p>
        ),
```

- [ ] **Step 3: Replace "What happens if I exceed my plan limits?" answer**

Old:
```tsx
        q: "What happens if I exceed my plan limits?",
        a: (
          <p>
            You&rsquo;ll see a clear message in the app explaining which limit you hit. Most
            actions are blocked rather than charged as overages — we don&rsquo;t want surprise
            bills. To run more scans, monitor more assets, or invite more teammates, upgrade
            to a higher plan. Plan changes mid-cycle are pro-rated automatically.
          </p>
        ),
```

New:
```tsx
        q: "What happens if I exceed my plan limits?",
        a: (
          <p>
            You&rsquo;ll see a clear message in the app explaining which limit you hit.
            Actions are blocked rather than billed — we don&rsquo;t do overages. Upgrading
            unlocks more scans, more monitored assets, and more team seats. Every paid tier
            is currently free to switch into.
          </p>
        ),
```

- [ ] **Step 4: Replace "Can I upgrade or downgrade later?" answer**

Old:
```tsx
        q: "Can I upgrade or downgrade later?",
        a: (
          <p>
            Yes, anytime. Open <strong>Settings &rarr; Billing &rarr; Manage billing</strong>.
            Upgrades take effect immediately with pro-rated charges. Downgrades take effect
            at the end of your current billing period — you keep your current limits until
            then. There&rsquo;s no contract lock-in.
          </p>
        ),
```

New:
```tsx
        q: "Can I upgrade or downgrade later?",
        a: (
          <p>
            Yes, anytime — open <strong>Settings &rarr; Plans</strong> and pick the tier you
            want. Every paid tier is free to upgrade into until further notice, and the
            change takes effect immediately. When billing returns later, downgrades will
            apply at the end of the billing period; there&rsquo;s no contract lock-in.
          </p>
        ),
```

- [ ] **Step 5: Replace "How do refunds and cancellations work?" answer**

Old:
```tsx
        q: "How do refunds and cancellations work?",
        a: (
          <p>
            Cancellations take effect at the end of your current billing period — you keep
            paid features until then, and your data isn&rsquo;t deleted. Subscription fees
            are non-refundable for elapsed time, with exceptions for billing errors, material
            service failures on our side, and where consumer law requires (e.g. Australian
            Consumer Law guarantees). Full details in our{" "}
            <Link href="/terms-and-policies/refund-cancellation-policy" className="text-teal-400 hover:text-teal-300">Refund &amp; Cancellation Policy</Link>.
          </p>
        ),
```

New:
```tsx
        q: "How do refunds and cancellations work?",
        a: (
          <p>
            Plans are currently free to upgrade — there&rsquo;s nothing to refund or cancel.
            Closing your account anytime keeps your data accessible until you delete it
            manually. When billing returns, cancellations will take effect at the end of the
            billing period and refund exceptions follow our{" "}
            <Link href="/terms-and-policies/refund-cancellation-policy" className="text-teal-400 hover:text-teal-300">Refund &amp; Cancellation Policy</Link>.
          </p>
        ),
```

- [ ] **Step 6: Replace "Where is my data stored?" answer**

Old:
```tsx
        q: "Where is my data stored?",
        a: (
          <p>
            On AWS in the United States (us-east-1 region). Although Nano EASM is based in
            Australia, we host in the US for sub-processor availability and global
            low-latency. International transfers are governed by the safeguards described in
            our Privacy Policy. If you have a data-residency requirement, contact us — we can
            discuss options under a custom contract.
          </p>
        ),
```

New:
```tsx
        q: "Where is my data stored?",
        a: (
          <p>
            On AWS in the United States (us-east-1 region) — chosen for sub-processor
            availability and global low-latency. International transfers follow the
            safeguards described in our Privacy Policy. If you have a data-residency
            requirement, contact us — we can discuss options under a custom contract.
          </p>
        ),
```

- [ ] **Step 7: Verify**

```bash
grep -n "small MSSP\|Verilog assembler\|based in Australia\|Manage billing\|pro-rated charges" "frontend/app/(unauthenticated)/faq/faq-data.tsx"
```

Expected: no output. Each pattern targets a stale fragment that should now be gone.

### Task 2.2: Mechanical fixes in `page.tsx` and `FAQContent.tsx`

**Files:**
- Modify: `frontend/app/(unauthenticated)/faq/page.tsx`
- Modify: `frontend/app/(unauthenticated)/faq/FAQContent.tsx`

- [ ] **Step 1: Add `LandingFooter` import to `page.tsx`**

After the existing `import LandingNav from "../LandingNav";` line:

```tsx
import LandingFooter from "../LandingFooter";
```

- [ ] **Step 2: Render `<LandingFooter />`**

Find the closing of `<main>` and the trailing `</>` fragment. Insert:

```tsx
        </div>
      </main>

      <LandingFooter />
    </>
```

- [ ] **Step 3: Bump subhead contrast in `page.tsx`**

Old:
```tsx
          <p className="mt-3 text-white/50 text-base max-w-2xl leading-relaxed">
```

New:
```tsx
          <p className="mt-3 text-white/65 text-base max-w-2xl leading-relaxed">
```

- [ ] **Step 4: Bump accordion-body contrast in `FAQContent.tsx`**

Old:
```tsx
      <div className="px-5 pb-5 pt-1 text-sm text-white/60 leading-relaxed">
```

New:
```tsx
      <div className="px-5 pb-5 pt-1 text-sm text-white/65 leading-relaxed">
```

- [ ] **Step 5: Bump empty-results-line contrast in `FAQContent.tsx`**

Old:
```tsx
          <p className="mt-2 text-sm text-white/40">
```

New:
```tsx
          <p className="mt-2 text-sm text-white/55">
```

### Task 2.3: Verify + commit Phase 2

- [ ] **Step 1: TypeScript pass**

```bash
cd frontend && npx tsc --noEmit 2>&1 | grep "faq" | head
```

Expected: no output.

- [ ] **Step 2: Stage and commit**

```bash
git add "frontend/app/(unauthenticated)/faq/"
git commit -m "$(cat <<'EOF'
content(faq): rewrite billing-OFF answers + drop disambiguation

- Rewrite four FAQ items that described Stripe-style billing flows
  (trials, plan-limits, upgrade/downgrade, refunds-and-cancellations)
  for current 'free upgrades until further notice' state. They will
  need another rewrite when billing returns; that's deliberate.
- Drop the parenthetical Verilog disambiguation from 'What is Nano
  EASM?' — same defensive copy already removed from the standalone
  /resources/what-is-nano-easm page.
- 'Where is my data stored?' loses the 'based in Australia' aside —
  customer base is global; the AU fact is irrelevant to the answer.
- 'small MSSPs' → 'MSSPs' (global market positioning).
- Render LandingFooter on the FAQ page.
- Body text contrast bumped to /65 (subhead, accordion body, empty
  results) to clear WCAG AA.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 3: Wait for explicit "push" instruction.**

---

## Phase 3 — `/api-docs`

### Task 3.1: All edits + commit

**Files:**
- Modify: `frontend/app/(unauthenticated)/api-docs/page.tsx`

- [ ] **Step 1: Add `LandingFooter` import**

After the existing `import LandingNav from "../LandingNav";` line:

```tsx
import LandingFooter from "../LandingFooter";
```

- [ ] **Step 2: Render `<LandingFooter />`**

The page returns a deeply-nested structure ending with several closing `</div>` tags. Find the outermost closing `</div>` of the component-return and insert `<LandingFooter />` immediately before it.

The exact target (last few lines of the component return):

Old:
```tsx
          </main>
        </div>
      </div>
    </div>
  );
}
```

New:
```tsx
          </main>
        </div>
      </div>
      <LandingFooter />
    </div>
  );
}
```

(Inserts `<LandingFooter />` between the second-to-last `</div>` and the outermost `</div>`.)

- [ ] **Step 3: Replace footer paragraph copy**

Old:
```tsx
            <section className="pt-8 border-t border-white/[0.06] text-sm text-white/40">
              Need something not in this list? The full UI runs on a JWT-only API
              that mirrors most of the surface — drop us a note via the{" "}
              <a
                href="/#contact"
                className="text-teal-300 hover:text-teal-200"
              >
                contact form
              </a>
              .
            </section>
```

New:
```tsx
            <section className="pt-8 border-t border-white/[0.06] text-sm text-white/55">
              Need an endpoint we haven&rsquo;t documented? Some surface is reachable
              only via the session API used by the UI — let us know what you&rsquo;re
              trying to do via the{" "}
              <a
                href="/#contact"
                className="text-teal-300 hover:text-teal-200"
              >
                contact form
              </a>
              .
            </section>
```

(Note: this also bumps the section's `text-white/40` → `text-white/55`, satisfying the small-text contrast requirement for this paragraph.)

- [ ] **Step 4: Replace "or sign in →" copy**

Old:
```tsx
                <Link
                  href="/login"
                  className="text-sm text-white/50 hover:text-white transition-colors"
                >
                  or sign in →
                </Link>
```

New:
```tsx
                <Link
                  href="/login"
                  className="text-sm text-white/65 hover:text-white transition-colors"
                >
                  Sign in first →
                </Link>
```

(Class bump folds in here too.)

- [ ] **Step 5: Bump `text-white/60` → `text-white/65` (replace_all)**

Affects the 9 instances at lines 394, 463, 489, 494, 521, 543, 552, 577 (and any I might have missed). Edit with `replace_all: true`.

Old: `text-white/60`
New: `text-white/65`

- [ ] **Step 6: Bump `text-white/55` → `text-white/65` (replace_all)**

Affects sidebar links (lines 436, 448) and the "What API keys can't do" paragraph (509). Note: Step 3 ALREADY changed the footer's `text-white/40` to `text-white/55` — running this replace_all AFTER Step 3 would inadvertently bump the footer to `/65`. **Order matters: do this step BEFORE Step 3 if doing manually.**

Actually since Step 3's new value (`text-white/55`) was a deliberate small-text choice, doing the replace_all at this step (before Step 3) won't hit it because Step 3 hasn't run yet — the footer is still at `/40`. And the existing `/55` instances (sidebar links, "What API keys can't do") get bumped to `/65`. Then Step 3 establishes the footer at `/55`. Order works in plan order.

Old: `text-white/55`
New: `text-white/65`

**RE-ORDER NOTE FOR IMPLEMENTER:** If you've already run Step 3, skip this step's replace_all and instead do targeted Edits at lines 436, 448, and 509 only. The footer paragraph should remain at `/55`.

- [ ] **Step 7: Bump remaining `text-white/40` → `text-white/55` (targeted edit)**

Step 3 covers the footer's `/40` → `/55` already. The other instance is the summary toggle text:

Old:
```tsx
          <summary className="cursor-pointer text-xs text-white/40 hover:text-white/70 transition-colors">
```

New:
```tsx
          <summary className="cursor-pointer text-xs text-white/55 hover:text-white/70 transition-colors">
```

- [ ] **Step 8: Bump `text-white/30` → `text-white/45` (replace_all)**

Affects sidebar uppercase labels at lines 424 and 441.

Old: `text-white/30`
New: `text-white/45`

- [ ] **Step 9: Verify all targeted contrast classes are gone**

```bash
grep -nE 'text-white/(30|40|50|60)' "frontend/app/(unauthenticated)/api-docs/page.tsx"
```

Expected: no output. Acceptable remaining classes are `/45`, `/55`, `/65`, `/70`, `/80`, `/[0.06]`.

- [ ] **Step 10: Verify wording changes landed**

```bash
grep -n "Sign in first\|Need an endpoint we haven" "frontend/app/(unauthenticated)/api-docs/page.tsx"
```

Expected: 2 matches (one for each new phrase).

- [ ] **Step 11: TypeScript pass**

```bash
cd frontend && npx tsc --noEmit 2>&1 | grep "api-docs" | head
```

Expected: no output.

- [ ] **Step 12: Stage and commit**

```bash
git add "frontend/app/(unauthenticated)/api-docs/page.tsx"
git commit -m "$(cat <<'EOF'
content(api-docs): footer + contrast pass + small wording polish

- Render LandingFooter (was missing — inconsistent with siblings).
- Tighten the trailing paragraph: drop 'JWT-only API that mirrors
  most of the surface' jargon for non-employees.
- 'or sign in →' → 'Sign in first →' so unauthenticated visitors
  reading the docs don't click 'Generate an API key' and bounce.
- Body text contrast bumped (white/50 / 55 / 60 → /65) to clear
  WCAG AA. Small text bumped white/30 → /45 (sidebar labels) and
  white/40 → /55 (summary toggle, footer paragraph).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 13: Wait for explicit "push" instruction.**

---

## Self-review

**Spec coverage:**
- Each-page-keeps-voice → preserved (no structural rewrites).
- Billing-OFF FAQs rewritten → Phase 2 Steps 2-5.
- Verilog disambiguation removed from FAQ → Phase 2 Step 1.
- "small MSSPs" → "MSSPs" → Phase 1 Steps 3-4, Phase 2 Step 1.
- "based in Australia" aside dropped → Phase 2 Step 6.
- "Toggle for your organisation" feature-talk softened → Phase 1 Step 5.
- Free-upgrade sentence appended → Phase 1 Step 6.
- LandingFooter on all 3 pages → Phase 1 Step 2, Phase 2 Task 2.2 Steps 1-2, Phase 3 Steps 1-2.
- Body contrast bumps → Phase 1 Steps 7-9, Phase 2 Task 2.2 Steps 3-5, Phase 3 Steps 5-6.
- Small-text contrast bumps on `/api-docs` → Phase 3 Steps 7-8.
- API-docs footer wording → Phase 3 Step 3.
- "Sign in first →" copy → Phase 3 Step 4.

All spec items have a corresponding task.

**Placeholder scan:** No "TBD", "TODO", "implement later", or vague directives. Every step shows exact old/new strings or exact commands.

**Type/name consistency:** N/A — no new types, components, or function names introduced. All edits target existing strings within existing files.

**Order-of-operations risk:** Phase 3 Step 6 (`/55` → `/65` replace_all) runs BEFORE Step 3's `/40` → `/55` change to the footer. Plan order is safe; the in-step note alerts the implementer to the ordering constraint.
