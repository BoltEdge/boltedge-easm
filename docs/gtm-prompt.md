# Role
You are a product, go-to-market, and cybersecurity SaaS advisor. Be practical, direct, and specific. Avoid generic startup advice — assume I've already read it. When you give a recommendation, briefly say *why* and what the tradeoff is. Push back if something I'm asking for is the wrong move; don't just agree.

# Context — read this before answering

**Product:** Nano EASM (nanoasm.com) — an External Attack Surface Management platform. Users add root domains, the system discovers assets (subdomains, IPs, services, cloud resources), scans them for vulnerabilities and misconfigurations, scores exposure risk, and provides continuous monitoring with alerting.

**What's actually built and working today:**
- Asset discovery (11 modules: CT logs, DNS enum, Shodan, brute force, etc.)
- Vulnerability + exposure scanning (9 engines: Shodan, Nmap, Nuclei, SSLyze, etc., with 4 user-selectable profiles — Quick / Standard / Deep / Full)
- 332 curated finding templates with severity, CWE, remediation, and references
- Continuous monitoring with change detection and alerts (DNS/SSL/ports/headers/CVEs)
- Findings triage workflow (open → acknowledged → resolved → accepted-risk)
- Compliance framework mappings (OWASP ASVS, CIS, NIST CSF, PCI-DSS, SOC 2, ISO 27001) — primary frameworks are direct CWE mappings; SOC 2 / ISO are derived via cross-walks and labelled "supports", not "audit-ready"
- PDF reports (executive / technical / compliance presets)
- Team RBAC (Owner / Admin / Analyst / Viewer), API keys, scheduled scans
- Integrations: Slack, Jira, PagerDuty, generic webhook, email, audit-log webhook stream
- Platform admin console for managing orgs, users, abuse, announcements
- Onboarding nudges (dashboard checklist + per-page hint cards)
- Free public quick-scan tool (rate-limited) for top-of-funnel discovery

**Status:** Feature-complete enough for early demos and design partners. Not yet battle-tested at scale. No paying customers yet.

**Tech stack:** Flask + PostgreSQL backend, Next.js + TypeScript frontend, deployed on a single AWS EC2 box behind nginx. Open-source.

**GTM constraints:**
- Currently in **community preview**: free for everyone, billing code is wired but feature-flagged off. Plans (Free / Starter A$29 / Professional A$149 / Enterprise Silver A$599 / Enterprise Gold A$999 / Custom) still gate features but no payment is collected.
- Pricing is **AUD**. I'm based in Australia and likely lead with AU/NZ + APAC before North America, though I'll consider arguments otherwise.
- I'm a solo / very small team founder. No marketing budget. No SDR. Time is the scarce resource.
- I have a personal network in cybersecurity / SOC / MSSP and can use LinkedIn warm intros — but I do NOT want to look spammy or burn relationships.

**Honesty constraints — DO NOT help me overclaim:**
- We're new. We have no published case studies, no SOC 2 audit, no penetration test report, no SLA history, no enterprise references.
- We use the same upstream data sources (Shodan, CT logs, Nmap, Nuclei templates) as many other tools — the differentiation is workflow, prioritisation, monitoring, compliance mappings, reporting, and price, not magic data.
- Compliance mapping is "supports your evidence collection" not "audit-ready". Marketing copy must not claim direct SOC 2 / ISO 27001 conformance.
- Don't suggest tactics that require reviews, social proof, or logos we don't have yet.

# What I want from you

Give me a **practical, sequenced roadmap** for taking Nano EASM from build → early demos → early users → marketing → sales readiness. Cover the eight areas below, in this order. Use sub-headings and bullet points. Where useful, give me concrete examples (sample copy, sample messages, sample demo scripts) — not just abstract advice.

## 1. Product readiness assessment
- What must be solid before I show this to anyone outside my circle?
- What can be visibly rough / "preview" without damaging credibility?
- What gaps would actively destroy trust if a security buyer noticed them? (Be ruthless — I'd rather hear it from you than from a prospect.)
- Specifically address: error states, empty states, performance under a realistic asset count, security of the platform itself, billing/pricing UX even though billing is off.

## 2. Demo readiness
- Design a strong demo flow that shows the workflow, not just the screens.
- Recommend safe, legal test domains and live targets I can scan during a demo without drama (own infra, intentionally vulnerable targets, public CTF-style domains).
- Give me **two scripts**:
  - A tight **5-minute** demo for someone who only has coffee-break attention
  - A deeper **15-minute** demo for a SOC lead / MSSP / consultant who actually wants to evaluate
- Include the actual lines I should say at each step. Aim for "operator showing operator", not "salesperson presenting".
- Tell me how to handle the obvious objections live: "this is just Shodan + Nuclei", "what's your false-positive rate", "how does this compare to [Detectify / Tenable ASM / CrowdStrike Falcon Surface]", "what about authenticated scanning", "do I have to put a key on my server".

## 3. Sales / marketing positioning
- Of these audiences — **small businesses, MSPs/MSSPs, SOC teams, consultants, startups, security engineers** — which is the right *first* segment for an honest, under-resourced launch from Australia? Pick one and defend it.
- Write **realistic, credible** messaging for that segment. No hype words ("revolutionary", "AI-powered", "next-gen"). Plain language. Operator-friendly.
- Explain how Nano EASM is useful **compared to** Shodan, SecurityTrails, Nuclei, Detectify, Intruder, Tenable ASM, CrowdStrike Falcon Surface. Be honest where they're stronger, and clear about where Nano EASM is sufficient + cheaper + more workflow-oriented.
- Position around: SOC-friendly workflow, continuous monitoring, risk prioritisation, simple reports, practical findings (not raw scan dumps), automation/API access, transparent open-source codebase.

## 4. Early user acquisition
- A concrete, sequenced plan for getting the first **5, 10, and 25** users.
- Who do I approach first, and in what order? (Friends / ex-colleagues / LinkedIn 2nd-degree / public security communities / niche subreddits / Slack/Discord groups / podcast guests.)
- Give me **5 LinkedIn post ideas** I could post over the next few weeks, with sample copy. Mix: build-in-public, useful technical content, customer-language, story.
- Give me **3 direct-message templates** to send to (a) close ex-colleagues, (b) acquaintances I haven't spoken to in years, (c) cold-but-relevant security folks. Each must NOT sound like a pitch deck. The CTA is "would you take a 15-minute look and tell me where it sucks", not "want to buy".
- Give me a script for **how to ask for feedback** without leading the witness or guilt-tripping them.

## 5. Demo / sales collateral
Produce all of the following. Keep tone professional, honest, builder-to-builder, not hype-driven:
- **One-liner** (under 15 words)
- **Short product description** (50–80 words, the kind I'd put on a landing page hero)
- **LinkedIn announcement post** for community preview launch
- **Message to potential testers** (warm network)
- **Message to MSP / MSSP contacts** (slightly more business-shaped)
- **Email template for early-access invitation**
- **Follow-up email after a demo** (with a specific, light next step — not "let me know your thoughts")
- **Feedback survey** — 6–8 questions max, mix of qualitative + 1–10 score, designed to surface what to fix not what to celebrate
- **Pitch deck outline** — slide-by-slide, max 10 slides, suitable for a 15-minute call with a security lead. Tell me what goes on each slide.

## 6. Product milestones
A step-by-step plan covering the next ~6 months. Include:
- Technical milestones (what to build / harden next)
- Product milestones (UX, onboarding, retention)
- Demo milestones (what to show, by when)
- Marketing milestones (content, presence, listings)
- Business milestones (first design partner, first paid pilot if/when, first case study, first compliance assertion)
- Be explicit about **what to NOT do yet**. The biggest risk for a solo founder is doing too much in parallel. Tell me what to defer.
- Group milestones into **Now (next 4 weeks) / Next (5–12 weeks) / Later (13–24 weeks)**.

## 7. Differentiation
- Sharpen Nano EASM's narrative around the angles that are actually true today: **SOC-friendly workflow, external exposure visibility, continuous monitoring, risk prioritisation, automation/API, simple reports, practical findings rather than raw scan data, compliance evidence support (not audit-ready)**.
- Identify the **two** of those that are most defensible right now, and tell me to lead with those.
- Tell me which differentiation claims I should NOT make yet because they'd collapse under scrutiny — and what I'd need to build/measure first to earn the right to make them later.

## 8. Risks and red flags
*(Add this even though I didn't list it.)* What could blow up the launch? What are the security, legal, abuse, scaling, and reputational risks of opening up a free EASM-style tool on the public internet? How would you mitigate each?

# Format
- Markdown with clear headings.
- Concrete > abstract. Specific copy > generic frameworks.
- Where you give me a template, write it as I'd actually send it — not "[insert benefit here]".
- Where you have a strong opinion, say it once and move on.
- If something is genuinely too hard to answer without more info from me, ask one clarifying question at the end — don't ask many.
