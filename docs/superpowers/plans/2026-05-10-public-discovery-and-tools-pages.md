# Public Quick Discovery & Tools Pages Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add dedicated public pages for Quick Discovery (`/quick-discovery`) and the lookup tools (`/tools`), and apply uniform abuse hardening (rate limit + Turnstile) to all 9 `/tools/public/*` backend endpoints.

**Architecture:** Three independent PRs. PR 1 bundles backend hardening with the existing `QuickToolsCard` token wiring, because the landing-page card calls those endpoints today and would break the moment Turnstile is required. PR 2 adds the `/quick-discovery` page reusing the existing `QuickDiscoveryCard` at full width. PR 3 adds the `/tools` page as an accordion driven by a config map, with the result renderer extracted from `QuickToolsCard` so it's shared.

**Tech Stack:** Flask + SQLAlchemy (backend), Next.js 16 App Router + React 19 + Tailwind 4 + framer-motion (frontend), Cloudflare Turnstile (CAPTCHA).

**Note on testing:** The repo has no test framework committed (no `backend/tests/`, no jest/vitest config). Setting one up is out of scope. Each task uses **manual verification with explicit acceptance criteria** — concrete `curl` commands and browser walk-throughs that the implementer must run and confirm green before commit.

**Spec:** `docs/superpowers/specs/2026-05-10-public-discovery-and-tools-pages-design.md`

---

## Phase 1 — Backend abuse hardening + landing-page token wiring (PR 1)

### Task 1.1: Extract `public_abuse_check` to a shared utility module

**Why:** The decorator currently lives in `app/quick_scan/routes.py` and is about to be imported from `app/tools/routes.py`. Importing across blueprint modules is a smell; pull it into `app/utils/`.

**Files:**
- Create: `backend/app/utils/abuse_check.py`
- Modify: `backend/app/quick_scan/routes.py`

- [ ] **Step 1: Create `backend/app/utils/abuse_check.py`**

```python
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Any

from flask import request, jsonify


def _get_ip() -> str:
    """Real client IP, respecting X-Forwarded-For from the nginx proxy."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _log_scan(ip: str, user_agent: str, target: str, asset_type: str,
              status: str, source: str = "scan",
              duration_ms: int | None = None,
              risk_score: float | None = None,
              finding_counts: dict | None = None,
              error_message: str | None = None) -> None:
    """Write a QuickScanLog row. Wrapped in try/except — never raises."""
    try:
        from app.extensions import db
        from app.models import QuickScanLog

        entry = QuickScanLog(
            ip_address=ip,
            user_agent=(user_agent or "")[:500] or None,
            target=target,
            asset_type=asset_type,
            source=source,
            status=status,
            duration_ms=duration_ms,
            risk_score=risk_score,
            finding_counts=finding_counts,
            error_message=(error_message or "")[:500] or None,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        try:
            from app.extensions import db
            db.session.rollback()
        except Exception:
            pass


def public_abuse_check(*, source: str, limit: int, label: str):
    """Decorator: block-list + rate-limit guard for public endpoints.

    Each public scan/discovery/tool endpoint has its own QuickScanLog source
    bucket so hitting the cap on one doesn't lock out the others. Rejects
    are logged with status `blocked` / `rate_limited`; the decorated
    function only runs for visitors that pass both checks.
    """
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            from app.models import BlockedIP, QuickScanLog

            body = request.get_json(silent=True) or {}
            ip = _get_ip()
            ua = request.headers.get("User-Agent", "")
            target = ((body.get("value") or body.get("domain") or body.get("query")
                       or body.get("ip") or body.get("host") or body.get("hash") or "")[:200]) or "-"
            asset_type = (body.get("type") or "-")[:32]
            now = datetime.now(timezone.utc).replace(tzinfo=None)

            block = BlockedIP.query.filter_by(ip_address=ip).first()
            if block and (block.expires_at is None or block.expires_at > now):
                _log_scan(ip=ip, user_agent=ua, target=target, asset_type=asset_type,
                          source=source, status="blocked")
                return jsonify(
                    error="Your IP address has been blocked from using this service.",
                    code="IP_BLOCKED",
                ), 403

            window_start = now - timedelta(hours=1)
            recent = QuickScanLog.query.filter(
                QuickScanLog.ip_address == ip,
                QuickScanLog.source == source,
                QuickScanLog.created_at >= window_start,
                QuickScanLog.status.notin_(["blocked", "rate_limited"]),
            ).count()
            if recent >= limit:
                _log_scan(ip=ip, user_agent=ua, target=target, asset_type=asset_type,
                          source=source, status="rate_limited")
                return jsonify(
                    error=f"Too many {label}. You can run up to {limit} {label} per hour from this IP. Please try again later. Sign up for free for more {label}.",
                    code="RATE_LIMITED",
                ), 429

            return fn(*args, **kwargs)
        return wrapper
    return deco
```

Note: the `target` extraction now also looks at `query`, `ip`, `host`, `hash` body fields so the abuse log captures a useful target string for the lookup tools (which use varied input field names).

- [ ] **Step 2: Replace local definitions in `backend/app/quick_scan/routes.py`**

Remove lines 86-181 (`_get_ip`, `_log_scan`, `public_abuse_check` definitions) and replace with:

```python
from app.utils.abuse_check import _get_ip, _log_scan, public_abuse_check
```

The decorator usage at lines 185 and 312 remains unchanged.

- [ ] **Step 3: Verify the app boots**

```bash
cd backend
python -c "from app import create_app; app = create_app(); print('routes:', len(list(app.url_map.iter_rules())))"
```

Expected: `routes: <some number>` with no traceback.

- [ ] **Step 4: Smoke-test `/quick-scan` end-to-end**

Start backend (`python run.py`) and frontend (`npm run dev`), then in the browser hit `http://localhost:3000/quick-scan`, run a scan against `example.com`. Expected: scan completes, results render. Confirms the import refactor didn't break the existing flow.

- [ ] **Step 5: Stage but DO NOT commit yet** — this task is part of PR 1, which commits at the end of Task 1.4. Continue to Task 1.2.

---

### Task 1.2: Add abuse_check + Turnstile to all 9 `/tools/public/*` endpoints

**Why:** Match the protection level of `/quick-scan` and `/quick-discovery`. Each tool gets its own source bucket so abuse on one doesn't lock out the others.

**Files:**
- Modify: `backend/app/tools/routes.py`

- [ ] **Step 1: Add imports at the top of `backend/app/tools/routes.py`** (after the existing `from app.auth.decorators import ...` line):

```python
from app.utils.abuse_check import public_abuse_check
from app.utils.turnstile import verify_turnstile
```

- [ ] **Step 2: For each of the 9 public endpoints, add the decorator + Turnstile check**

The pattern, applied identically to all 9 endpoints — only the `source`, `limit`, and `label` change:

```python
@tools_bp.post("/public/whois")
@public_abuse_check(source="tool_whois", limit=10, label="WHOIS lookups")
def public_whois():
    ts_ok, ts_err = verify_turnstile(request)
    if not ts_ok:
        return jsonify(error=ts_err, code="TURNSTILE_FAILED"), 403
    # ── existing function body unchanged from this point ──
```

Apply to each of these (in order — line numbers refer to the file before any edits to this task):

| Endpoint (function name) | Original line | source bucket | label |
|---|---|---|---|
| `public_cert_lookup` | 296 | `tool_cert` | `certificate lookups` |
| `public_cert_hash` | 328 | `tool_cert_hash` | `certificate hash lookups` |
| `public_dns_lookup` | 356 | `tool_dns` | `DNS lookups` |
| `public_reverse_dns` | 387 | `tool_revdns` | `reverse DNS lookups` |
| `public_header_check` | 421 | `tool_headers` | `header checks` |
| `public_whois` | 453 | `tool_whois` | `WHOIS lookups` |
| `public_email_security` | 502 | `tool_email` | `email security checks` |
| `public_sensitive_paths` | 532 | `tool_paths` | `sensitive-path scans` |
| `public_github_leaks` | 563 | `tool_github` | `GitHub leak searches` |

The cap of `10` is the conservative starting value. If post-launch metrics show legitimate users routinely hitting it, raise per-tool individually.

- [ ] **Step 3: Verify the app still boots and routes are registered**

```bash
cd backend
python -c "from app import create_app; app = create_app(); rules = [r.rule for r in app.url_map.iter_rules() if '/tools/public/' in r.rule]; print('\n'.join(sorted(rules)))"
```

Expected: 9 lines listing every `/api/tools/public/<name>` route.

- [ ] **Step 4: Manual Turnstile rejection test (with TURNSTILE_SECRET_KEY set)**

In your backend shell, set the secret first so verification is real (not no-op):

```powershell
$env:TURNSTILE_SECRET_KEY = "1x0000000000000000000000000000000AA"
python run.py
```

Then in another terminal:

```bash
curl -i -X POST http://localhost:5000/api/tools/public/whois \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

Expected: HTTP `403`, JSON body containing `"code":"TURNSTILE_FAILED"`. The test secret `1x...AA` is "always-pass", but with no token in the body it still rejects — which is what we want.

- [ ] **Step 5: Manual rate-limit test**

Unset `TURNSTILE_SECRET_KEY` (so verify_turnstile is no-op for this test only) and hit one endpoint 11 times:

```powershell
Remove-Item Env:TURNSTILE_SECRET_KEY
python run.py
```

```bash
for i in {1..11}; do curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:5000/api/tools/public/whois -H "Content-Type: application/json" -d '{"domain":"example.com"}'; done
```

Expected: ten `200`s, one `429`. Re-set the secret after this test.

- [ ] **Step 6: Continue to Task 1.3** — still no commit yet.

---

### Task 1.3: Wire Turnstile token submission into `QuickToolsCard` (landing-page card)

**Why:** Once Task 1.2 ships, `QuickToolsCard` will start receiving `403 TURNSTILE_FAILED` from every tool because it doesn't send a token today. Without this fix, the landing page breaks in production.

**Files:**
- Modify: `frontend/app/(unauthenticated)/QuickToolsCard.tsx`

- [ ] **Step 1: Add Turnstile imports at the top of the file**

Add after the existing `import` lines:

```tsx
import TurnstileWidget from "./TurnstileWidget";

const TURNSTILE_ENABLED = !!process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;
```

- [ ] **Step 2: Add token state inside the component**

Inside `QuickToolsCard()`, alongside the existing `useState` calls (around line 137):

```tsx
const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
const [widgetKey, setWidgetKey] = useState(0);
```

- [ ] **Step 3: Send the token with the request and reset after**

Replace the `handleSubmit` body (lines 149-166) with:

```tsx
const handleSubmit = useCallback(async () => {
  const val = inputValue.trim();
  if (!val || tool.authOnly) return;
  if (TURNSTILE_ENABLED && !turnstileToken) return;
  setLoading(true); setResult(null);
  try {
    let endpoint: string; let body: Record<string, string>;
    if (activeTool === "cert-lookup") {
      const cleaned = val.replace(/[:\s]/g, "").toLowerCase();
      const isHash = /^[0-9a-f]{64}$/.test(cleaned);
      if (isHash) { endpoint = `${API_BASE}/tools/public/cert-hash`; body = { hash: cleaned }; }
      else { endpoint = `${API_BASE}/tools/public/cert-lookup`; body = { domain: val }; }
    } else { endpoint = `${API_BASE}/tools/public/${activeTool}`; body = { [tool.inputField]: val }; }
    if (turnstileToken) body.turnstileToken = turnstileToken;
    const res = await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await res.json();
    if (!res.ok && data.error) setResult({ error: data.error }); else setResult(data);
  } catch { setResult({ error: "Request failed. Please try again." }); }
  finally {
    setLoading(false);
    setTurnstileToken(null);
    setWidgetKey((k) => k + 1);
  }
}, [inputValue, activeTool, tool, turnstileToken]);
```

The added lines: the early-return when Turnstile is enabled but no token, the `body.turnstileToken = ...` assignment, and the `setTurnstileToken(null) + setWidgetKey(k+1)` reset in `finally`.

- [ ] **Step 4: Render the widget and disable the submit button until verified**

In the JSX, replace the input/button block (lines 196-209) with:

```tsx
{/* Input — hidden for auth-only tools */}
{!tool.authOnly && (
  <div className="px-6 pb-4 space-y-3">
    <div className="flex gap-2">
      <input type="text" value={inputValue} onChange={(e) => setInputValue(e.target.value)} onKeyDown={(e) => e.key === "Enter" && !loading && handleSubmit()}
        placeholder={tool.placeholder} disabled={loading}
        className="flex-1 rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/40 font-mono" />
      <button onClick={handleSubmit} disabled={loading || !inputValue.trim() || (TURNSTILE_ENABLED && !turnstileToken)}
        className={cn("rounded-lg px-4 py-2 text-sm font-medium transition-all shrink-0",
          loading || !inputValue.trim() || (TURNSTILE_ENABLED && !turnstileToken)
            ? "bg-muted text-muted-foreground cursor-not-allowed"
            : "bg-gradient-to-r from-teal-500 to-cyan-500 text-white shadow-lg shadow-teal-500/20 hover:shadow-teal-500/30 hover:brightness-110")}>
        {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
      </button>
    </div>
    {TURNSTILE_ENABLED && (
      <TurnstileWidget
        key={widgetKey}
        onVerify={setTurnstileToken}
        onExpire={() => setTurnstileToken(null)}
        onError={() => setTurnstileToken(null)}
      />
    )}
  </div>
)}
```

(The widget mounts even though Cloudflare's mode is "Invisible" — Cloudflare just won't render visible UI, but the iframe + token issuance still happens.)

- [ ] **Step 5: Type-check and lint**

```bash
cd frontend
npx tsc --noEmit
npx next lint
```

Expected: no errors related to `QuickToolsCard.tsx`. Pre-existing lint warnings elsewhere are out of scope.

- [ ] **Step 6: Continue to Task 1.4** — final verification + single commit for the whole PR.

---

### Task 1.4: Manual end-to-end verification + commit PR 1

- [ ] **Step 1: Set the always-pass test keys for local dev**

Backend (`backend/.env` is not used; export in shell):

```powershell
$env:TURNSTILE_SECRET_KEY = "1x0000000000000000000000000000000AA"
```

Frontend `.env.local` already has `NEXT_PUBLIC_TURNSTILE_SITE_KEY=1x00000000000000000000AA` from earlier work.

- [ ] **Step 2: Walk every public flow in the browser**

Restart both servers. In the browser at `http://localhost:3000/`:

1. Run a Quick Scan against `example.com`. Expected: completes without 403.
2. Run a Quick Discovery against `example.com`. Expected: completes without 403.
3. On the QuickToolsCard, click each pill and run a sample input:
   - Certificate: `example.com`
   - DNS: `example.com`
   - Headers: `example.com`
   - WHOIS: `example.com`
   - Reverse DNS: `8.8.8.8`
   - Connectivity: (skip — auth-only, will show teaser)
   
   Expected: each returns a 200 with results rendered. No 403/429 on any of them.

- [ ] **Step 3: Verify rate limiting still works on the tool endpoints**

```bash
for i in {1..11}; do curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:5000/api/tools/public/dns-lookup -H "Content-Type: application/json" -d '{"domain":"example.com","turnstileToken":"x"}'; done
```

Expected: ten `200`s, one `429`. (The `turnstileToken: "x"` isn't validated because the always-pass test secret accepts anything; we're isolating the rate-limit path.)

- [ ] **Step 4: Stage all PR 1 changes and commit**

```bash
git add backend/app/utils/abuse_check.py \
        backend/app/quick_scan/routes.py \
        backend/app/tools/routes.py \
        frontend/app/(unauthenticated)/QuickToolsCard.tsx
git commit -m "$(cat <<'EOF'
feat: gate /tools/public/* with rate limit + Turnstile

Each of the 9 public lookup endpoints now requires a Turnstile token and
gets its own per-IP rate limit bucket (10/hr). QuickToolsCard wired to
issue and submit a fresh token per request so the landing page keeps
working.

Refactor: public_abuse_check moved from quick_scan to app/utils/abuse_check
so blueprints don't import across each other.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Wait for the user's explicit "push" instruction.** Per repo convention, never auto-push. Ask the user, then `git push origin master` once approved.

---

## Phase 2 — `/quick-discovery` dedicated page (PR 2)

### Task 2.1: Create the page file with hero + embedded card

**Files:**
- Create: `frontend/app/(unauthenticated)/quick-discovery/page.tsx`

- [ ] **Step 1: Create the directory** (Next.js App Router groups pages by directory)

```bash
mkdir -p "frontend/app/(unauthenticated)/quick-discovery"
```

- [ ] **Step 2: Create `page.tsx` with the full hero + card + what's-included + CTA structure**

```tsx
// app/(unauthenticated)/quick-discovery/page.tsx
// Public Quick Discovery page — hosts the QuickDiscoveryCard standalone with
// a hero, an explainer of free vs registered enumeration, and a sign-up CTA.
import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, Check, X } from "lucide-react";

import LandingNav from "../LandingNav";
import LandingFooter from "../LandingFooter";
import JsonLd from "../JsonLd";
import QuickDiscoveryCard from "../QuickDiscoveryCard";

const SITE_URL = "https://nanoeasm.com";
const PAGE_TITLE = "Free Subdomain Finder & Asset Discovery — Nano EASM";
const PAGE_DESCRIPTION =
  "Find subdomains, IPs, and shadow assets exposed against any domain. CT log discovery and DNS resolution, no signup, no card.";

export const metadata: Metadata = {
  title: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  alternates: { canonical: "/quick-discovery" },
  openGraph: {
    title: PAGE_TITLE,
    description: PAGE_DESCRIPTION,
    url: `${SITE_URL}/quick-discovery`,
    type: "website",
    siteName: "Nano EASM",
    locale: "en_AU",
  },
  twitter: {
    card: "summary_large_image",
    title: PAGE_TITLE,
    description: PAGE_DESCRIPTION,
  },
};

const PAGE_JSONLD = {
  "@context": "https://schema.org",
  "@type": "WebPage",
  name: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  url: `${SITE_URL}/quick-discovery`,
  inLanguage: "en-AU",
  isPartOf: { "@type": "WebSite", name: "Nano EASM", url: SITE_URL },
  about: {
    "@type": "SoftwareApplication",
    name: "Nano EASM",
    applicationCategory: "SecurityApplication",
    applicationSubCategory: "External Attack Surface Management",
    url: SITE_URL,
  },
};

const BREADCRUMB_JSONLD = {
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  itemListElement: [
    { "@type": "ListItem", position: 1, name: "Home", item: `${SITE_URL}/` },
    { "@type": "ListItem", position: 2, name: "Quick Discovery", item: `${SITE_URL}/quick-discovery` },
  ],
};

export default function QuickDiscoveryPage() {
  return (
    <div className="min-h-screen bg-[#060b18] text-white overflow-x-hidden">
      <JsonLd data={[PAGE_JSONLD, BREADCRUMB_JSONLD]} />
      <LandingNav />
      <div className="h-16" /> {/* spacer for fixed navbar */}

      <main>
        {/* ================= HERO ================= */}
        <section className="relative">
          <div className="absolute inset-0 overflow-hidden pointer-events-none">
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-gradient-to-b from-cyan-500/[0.07] via-teal-500/[0.04] to-transparent rounded-full blur-3xl" />
          </div>
          <div className="relative mx-auto max-w-3xl px-4 sm:px-6 pt-12 sm:pt-16 pb-8 text-center">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/[0.06] px-4 py-1.5 mb-6">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-400 opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-cyan-400" />
              </span>
              <span className="text-xs font-medium text-cyan-400/70 tracking-wide">Free quick discovery</span>
            </div>
            <h1 className="text-3xl sm:text-5xl font-bold leading-[1.1] tracking-tight">
              Find every subdomain<br />
              <span className="bg-gradient-to-r from-cyan-400/80 via-teal-400/70 to-cyan-500/80 bg-clip-text text-transparent">
                you forgot you owned.
              </span>
            </h1>
            <p className="mt-5 text-base sm:text-lg text-white/70 leading-7 max-w-2xl mx-auto">
              Enter a domain. We&apos;ll pull subdomains from public certificate
              transparency logs, resolve their IPs, and surface what&apos;s exposed —
              no signup, no card.
            </p>
          </div>
        </section>

        {/* ================= DISCOVERY CARD ================= */}
        <section className="py-6 sm:py-8">
          <div className="mx-auto max-w-3xl px-4 sm:px-6">
            <QuickDiscoveryCard />
          </div>
        </section>

        {/* ================= WHAT'S COVERED ================= */}
        <section className="py-12 sm:py-16">
          <div className="mx-auto max-w-3xl px-4 sm:px-6">
            <div className="text-center mb-10">
              <span className="text-xs font-semibold text-cyan-400 uppercase tracking-widest">What&apos;s covered</span>
              <h2 className="mt-3 text-2xl sm:text-3xl font-bold tracking-tight">
                A free first pass — register for the rest.
              </h2>
              <p className="mt-3 text-sm text-white/60 max-w-xl mx-auto leading-relaxed">
                Quick Discovery uses the same CT-log feed our paid tier does, but
                stops short of brute-forcing or active probing. Free accounts unlock
                deeper enumeration.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/[0.04] p-5">
                <h3 className="text-sm font-semibold text-cyan-300 mb-3 flex items-center gap-2">
                  <Check className="w-4 h-4" />
                  Included
                </h3>
                <ul className="space-y-2 text-sm text-white/70 leading-relaxed">
                  <li>Subdomains from CT logs (crt.sh)</li>
                  <li>Apex IP resolution</li>
                  <li>Up to 30 subdomain IP resolutions</li>
                  <li>No signup, no card, no follow-up email</li>
                </ul>
              </div>
              <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-5">
                <h3 className="text-sm font-semibold text-white/80 mb-3 flex items-center gap-2">
                  <X className="w-4 h-4 text-white/50" />
                  Free account adds
                </h3>
                <ul className="space-y-2 text-sm text-white/55 leading-relaxed">
                  <li>Brute-force subdomain enumeration</li>
                  <li>12 discovery sources (CT, DNS, Shodan, RapidDNS, etc.)</li>
                  <li>ASN-based asset discovery</li>
                  <li>Saved discoveries with delta tracking</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* ================= FINAL CTA ================= */}
        <section className="py-12 sm:py-16">
          <div className="mx-auto max-w-3xl px-4 sm:px-6">
            <div className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-gradient-to-br from-[#0d1a2e] to-[#0a1121] px-8 py-12 text-center sm:px-12">
              <div className="absolute inset-0 pointer-events-none">
                <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[400px] h-[200px] bg-cyan-500/[0.06] rounded-full blur-3xl" />
              </div>
              <div className="relative">
                <h2 className="text-2xl sm:text-3xl font-bold tracking-tight">
                  Ready for the
                  <span className="bg-gradient-to-r from-cyan-400/80 to-teal-400/70 bg-clip-text text-transparent"> deep enumeration?</span>
                </h2>
                <p className="mt-3 text-base text-white/55 max-w-lg mx-auto">
                  Brute-force discovery, 12 sources, ASN coverage, saved results,
                  and delta alerts when new subdomains appear. Free to start.
                </p>
                <div className="mt-7 flex flex-col sm:flex-row items-center justify-center gap-3">
                  <Link
                    href="/register"
                    className="group inline-flex items-center gap-2 rounded-xl bg-cyan-600 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-cyan-900/30 hover:bg-cyan-500 transition-all"
                  >
                    Create free account
                    <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                  </Link>
                  <Link
                    href="/quick-scan"
                    className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-6 py-3 text-sm font-medium text-white/70 hover:text-white hover:bg-white/[0.06] transition-all"
                  >
                    Try Quick Scan instead
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>

      <LandingFooter />
    </div>
  );
}
```

- [ ] **Step 3: Manual UI check — `/quick-discovery` renders**

Restart `npm run dev` if needed. Visit `http://localhost:3000/quick-discovery`.

Expected:
- Page loads with the cyan-themed hero
- `QuickDiscoveryCard` renders inline below the hero
- Running discovery against `example.com` returns subdomains
- "What's covered" 2-column section displays
- Final CTA section displays
- Nav and footer match the rest of the site

If `QuickDiscoveryCard` looks visually cramped at full hero width (max-w-3xl), that's acceptable for v1 — the card was designed for a 1/3 column on the landing grid. We'll polish the standalone layout in a follow-up if needed.

---

### Task 2.2: Add a "View full Discovery page →" link to the landing card

**Why:** First-time visitors who run discovery on the landing page should see an obvious path to the dedicated page (more SEO equity, better mental model).

**Files:**
- Modify: `frontend/app/(unauthenticated)/QuickDiscoveryCard.tsx`

- [ ] **Step 1: Import `Link` if not already imported**

Verify the existing import line: `import Link from "next/link";` (already present).

- [ ] **Step 2: Add the link below the discovery results**

In `QuickDiscoveryCard.tsx`, find the block that closes the results panel (look for the `Discovery errors` block ending around line 156). Just after the closing `</div>` of the inner result panel `<div className="rounded-xl border border-border bg-background/30 p-4 h-full flex flex-col">` (around line 157), insert:

```tsx
{result && (
  <div className="px-6 pb-6 -mt-2">
    <Link
      href="/quick-discovery"
      className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-cyan-400 hover:text-cyan-300 transition-colors"
    >
      View full Discovery page <ArrowRight className="w-3 h-3" />
    </Link>
  </div>
)}
```

The link only renders after a result exists, so first-time visitors aren't distracted from running their first discovery.

- [ ] **Step 3: Manual UI check**

On `http://localhost:3000/`, run a discovery in the QuickDiscoveryCard. After results render, the "View full Discovery page →" link should appear at the bottom-left of the card. Click it — should navigate to `/quick-discovery`.

---

### Task 2.3: Add Quick Discovery to LandingNav

**Files:**
- Modify: `frontend/app/(unauthenticated)/LandingNav.tsx`

- [ ] **Step 1: Add a Quick Discovery entry in the Product dropdown**

In `LandingNav.tsx`, find the `TOP_NAV` array (starts at line 27). In the "Product" dropdown's `items` array, insert a new entry right after the existing Quick Scan entry (currently at line 35):

```tsx
{ href: "/quick-discovery", label: "Quick Discovery", description: "Find subdomains free, no signup." },
```

The Product dropdown items array should look like:

```tsx
items: [
  { href: "/#features", label: "Capabilities", description: "What the platform does, end to end." },
  { href: "/#how-it-works", label: "How it works", description: "Discover → scan → score → monitor." },
  { href: "/coverage", label: "Coverage", description: "Every finding category we detect.", badge: "New" },
  { href: "/quick-scan", label: "Quick Scan", description: "Try a free scan, no signup." },
  { href: "/quick-discovery", label: "Quick Discovery", description: "Find subdomains free, no signup." },
  { href: "/#pricing", label: "Pricing", description: "Plan tiers and limits.", billingOnly: true },
],
```

- [ ] **Step 2: Manual UI check**

On any page, hover/click the Product nav. Quick Discovery should appear directly below Quick Scan. Click — should navigate to `/quick-discovery`.

---

### Task 2.4: Final verification + commit PR 2

- [ ] **Step 1: Walk the full user flow**

1. Visit `http://localhost:3000/` → Product nav → Quick Discovery → page loads.
2. Run discovery against `example.com` → results appear.
3. Visit landing page, run QuickDiscoveryCard, click "View full Discovery page →" link → routes correctly.
4. View page source on `/quick-discovery` → `<title>` is the expected SEO title; JSON-LD blocks are present.

- [ ] **Step 2: Type-check + lint**

```bash
cd frontend
npx tsc --noEmit
npx next lint
```

Expected: no new errors.

- [ ] **Step 3: Stage and commit**

```bash
git add "frontend/app/(unauthenticated)/quick-discovery/" \
        "frontend/app/(unauthenticated)/QuickDiscoveryCard.tsx" \
        "frontend/app/(unauthenticated)/LandingNav.tsx"
git commit -m "$(cat <<'EOF'
feat: add /quick-discovery dedicated public page

Mirrors /quick-scan structure: hero + embedded card + what's-covered
2-col + final CTA. Includes JSON-LD WebPage + BreadcrumbList for SEO.
Landing-page card gets a 'View full Discovery page' link once it has
results. Nav adds Quick Discovery under Product.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 4: Wait for the user's explicit push instruction** before pushing.

---

## Phase 3 — `/tools` dedicated page (PR 3)

### Task 3.1: Extract `PublicResultView` into a shared component

**Why:** The result-rendering logic in `QuickToolsCard` already handles all the public-tool response shapes. Lift it so the new `/tools` page can reuse it.

**Files:**
- Create: `frontend/app/(unauthenticated)/tools/ToolResultView.tsx`
- Modify: `frontend/app/(unauthenticated)/QuickToolsCard.tsx`

- [ ] **Step 1: Create the new directory**

```bash
mkdir -p "frontend/app/(unauthenticated)/tools"
```

- [ ] **Step 2: Move `PublicResultView` and its helpers**

Create `frontend/app/(unauthenticated)/tools/ToolResultView.tsx` and copy from `QuickToolsCard.tsx`:
- The `cn` helper (line 14)
- The `SEV_ICONS` constant (lines 40-46)
- The `GradeBadge` component (lines 48-59)
- The `PublicResultView` component (lines 61-109)

Wrap them in a module-scoped file. The full content:

```tsx
// app/(unauthenticated)/tools/ToolResultView.tsx
// Shared renderer for public-tool API responses. Used by both QuickToolsCard
// (landing-page) and the dedicated /tools page accordion.
"use client";

import React from "react";
import Link from "next/link";
import { AlertTriangle, ArrowRight, CheckCircle2, Info } from "lucide-react";

function cn(...c: Array<string | false | null | undefined>) {
  return c.filter(Boolean).join(" ");
}

const SEV_ICONS: Record<string, React.ReactNode> = {
  critical: <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />,
  high: <AlertTriangle className="w-3.5 h-3.5 text-orange-400 shrink-0" />,
  medium: <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 shrink-0" />,
  low: <Info className="w-3.5 h-3.5 text-blue-400 shrink-0" />,
  info: <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />,
};

function GradeBadge({ grade }: { grade?: string }) {
  if (!grade) return null;
  const g = grade.replace(/[+-]/g, "");
  const colors: Record<string, string> = {
    A: "from-emerald-500/30 to-emerald-500/10 text-emerald-400 border-emerald-500/30",
    B: "from-yellow-500/30 to-yellow-500/10 text-yellow-400 border-yellow-500/30",
    C: "from-orange-500/30 to-orange-500/10 text-orange-400 border-orange-500/30",
    D: "from-red-500/30 to-red-500/10 text-red-400 border-red-500/30",
    F: "from-red-500/40 to-red-500/15 text-red-300 border-red-500/40",
  };
  return <span className={cn("inline-flex items-center px-2.5 py-1 rounded-lg text-base font-bold border bg-gradient-to-b", colors[g] || colors.F)}>{grade}</span>;
}

export default function ToolResultView({ data }: { data: any }) {
  if (data?.error) return <p className="text-sm text-red-400">{data.error}</p>;
  const grade = data.grade;
  const issues: any[] = data.issues || [];
  const nonInfo = issues.filter((i: any) => i.severity !== "info");

  return (
    <div className="space-y-3">
      {grade && (<div className="flex items-center gap-3"><GradeBadge grade={grade} /><span className="text-sm text-muted-foreground">{nonInfo.length} issue{nonInfo.length !== 1 ? "s" : ""} found</span></div>)}
      {data.certificate && (
        <div className="space-y-1">
          <div className="text-xs text-muted-foreground">Issued by <span className="text-foreground/70">{data.certificate.issuer}</span></div>
          {data.certificate.daysUntilExpiry !== undefined && <div className={cn("text-xs", data.certificate.daysUntilExpiry <= 30 ? "text-red-400" : "text-muted-foreground/60")}>Expires in {data.certificate.daysUntilExpiry} days</div>}
          {data.certificate.sans?.length > 0 && <div className="text-xs text-muted-foreground/40 font-mono truncate">SANs: {data.certificate.sans.slice(0, 3).join(", ")}{data.certificate.sans.length > 3 && ` +${data.certificate.sans.length - 3}`}</div>}
        </div>
      )}
      {data.totalFound !== undefined && (<div className="text-sm text-muted-foreground">Found <span className="text-foreground font-semibold">{data.totalFound}</span> certificate(s){data.coveredDomains?.length > 0 && <div className="text-xs text-muted-foreground/40 font-mono mt-1 truncate">{data.coveredDomains.slice(0, 4).join(", ")}{data.coveredDomains.length > 4 && ` +${data.coveredDomains.length - 4}`}</div>}</div>)}
      {data.resolvedIps?.length > 0 && <div className="text-xs text-muted-foreground font-mono">→ {data.resolvedIps.slice(0, 3).join(", ")}{data.resolvedIps.length > 3 && ` +${data.resolvedIps.length - 3} more`}</div>}
      {data.hostnames?.length > 0 && <div className="text-sm text-muted-foreground">→ {data.hostnames.slice(0, 3).join(", ")}{data.hostnames.length > 3 && ` +${data.hostnames.length - 3} more`}</div>}
      {data.registration?.registrar && (
        <div className="space-y-0.5">
          <div className="text-xs text-muted-foreground">Registrar: <span className="text-foreground/70">{data.registration.registrar}</span></div>
          {data.registration.daysUntilExpiry !== undefined && <div className={cn("text-xs", data.registration.daysUntilExpiry <= 30 ? "text-red-400" : "text-muted-foreground/60")}>Expires in {data.registration.daysUntilExpiry} days</div>}
          {data.registration.nameservers?.length > 0 && <div className="text-xs text-muted-foreground/40 font-mono truncate">NS: {data.registration.nameservers.slice(0, 2).join(", ")}{data.registration.nameservers.length > 2 && ` +${data.registration.nameservers.length - 2}`}</div>}
        </div>
      )}
      {data.network?.orgName && <div className="text-xs text-muted-foreground">{data.network.orgName}{data.network.country && <span className="ml-1">· {data.network.country}</span>}{data.network.cidr && <span className="ml-1 font-mono">· {data.network.cidr}</span>}</div>}
      {data.asn?.name && <div className="text-xs text-muted-foreground">{data.asn.name}{data.asn.country && <span className="ml-1">· {data.asn.country}</span>}</div>}
      {data.headerSummary && Object.keys(data.headerSummary).length > 0 && (
        <div className="flex flex-wrap gap-1">
          {Object.entries(data.headerSummary).slice(0, 6).map(([alias, info]: [string, any]) => (
            <span key={alias} className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium border", (info as any).present ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-400" : "border-red-500/20 bg-red-500/5 text-red-400")}>
              {(info as any).present ? <CheckCircle2 className="w-2.5 h-2.5" /> : <AlertTriangle className="w-2.5 h-2.5" />}{alias}
            </span>
          ))}
        </div>
      )}
      {issues.length > 0 && (
        <div className="space-y-1.5">
          {issues.slice(0, 3).map((issue: any, i: number) => (<div key={i} className="flex items-start gap-2 text-xs">{SEV_ICONS[issue.severity] || SEV_ICONS.info}<span className="text-foreground/70">{issue.title}</span></div>))}
          {issues.length > 3 && <div className="text-xs text-muted-foreground/40 pl-5">+ {issues.length - 3} more</div>}
        </div>
      )}
      <div className="pt-2 border-t border-border">
        <Link href="/register" className="inline-flex items-center gap-2 text-xs font-medium text-teal-400 hover:text-teal-300 transition-colors">Sign up for full details <ArrowRight className="w-3 h-3" /></Link>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Update `QuickToolsCard.tsx` to import the shared component**

Remove the local `PublicResultView`, `GradeBadge`, `SEV_ICONS`, and `cn` definitions if they're not used elsewhere in the file (`cn` is used inline in the JSX, so keep that one). Replace the import section so the JSX still renders identical output by importing the shared `ToolResultView`:

```tsx
import ToolResultView from "./tools/ToolResultView";
```

Then replace `<PublicResultView data={result} />` (currently around line 213) with `<ToolResultView data={result} />`.

- [ ] **Step 4: Verify the landing page still renders identically**

`npm run dev`, visit `http://localhost:3000/`, run any tool in QuickToolsCard. Result panel should look identical to before.

- [ ] **Step 5: Continue to Task 3.2** — no commit yet (PR 3 commits at the end).

---

### Task 3.2: Create the tool config map

**Files:**
- Create: `frontend/app/(unauthenticated)/tools/tools-config.ts`

- [ ] **Step 1: Create the file with all 9 tool definitions**

```tsx
// app/(unauthenticated)/tools/tools-config.ts
// Authoritative list of public lookup tools surfaced on /tools.
// 9 entries; cert-hash is intentionally not in the displayed accordion
// (niche, hash input is awkward for SEO). Endpoint stays callable.

import type { ComponentType, SVGProps } from "react";
import {
  FileText, Globe, Mail, Shield, Lock, RefreshCcw, FileSearch, Github,
} from "lucide-react";

export type ToolInputKind = "domain" | "ip" | "url-or-domain" | "hash";

export type ToolConfig = {
  id: string;
  /** Endpoint suffix — full URL is `${API_BASE}/tools/public/${endpoint}`. */
  endpoint: string;
  name: string;
  shortName: string;
  description: string;
  inputKind: ToolInputKind;
  /** Body field name expected by the backend. */
  inputField: string;
  placeholder: string;
  icon: ComponentType<SVGProps<SVGSVGElement>>;
  iconColor: string;
  /** Hidden from the visible accordion when true. Endpoint still callable. */
  hidden?: boolean;
};

export const TOOLS: ToolConfig[] = [
  {
    id: "whois",
    endpoint: "whois",
    name: "WHOIS Lookup",
    shortName: "WHOIS",
    description: "Registrar, expiry date, contacts, and nameservers for any domain or IP.",
    inputKind: "domain",
    inputField: "query",
    placeholder: "example.com / 8.8.8.8 / AS13335",
    icon: FileText,
    iconColor: "text-rose-400",
  },
  {
    id: "dns-lookup",
    endpoint: "dns-lookup",
    name: "DNS Lookup",
    shortName: "DNS",
    description: "A, AAAA, MX, NS, TXT, and CNAME records — what every resolver sees.",
    inputKind: "domain",
    inputField: "domain",
    placeholder: "example.com",
    icon: Globe,
    iconColor: "text-cyan-400",
  },
  {
    id: "email-security",
    endpoint: "email-security",
    name: "Email Security Check",
    shortName: "Email",
    description: "SPF, DKIM, and DMARC presence — graded so you know what's missing.",
    inputKind: "domain",
    inputField: "domain",
    placeholder: "example.com",
    icon: Mail,
    iconColor: "text-amber-400",
  },
  {
    id: "header-check",
    endpoint: "header-check",
    name: "HTTP Header Check",
    shortName: "Headers",
    description: "Security headers, cookie flags, and a letter-grade verdict.",
    inputKind: "url-or-domain",
    inputField: "domain",
    placeholder: "https://example.com or example.com",
    icon: Shield,
    iconColor: "text-amber-400",
  },
  {
    id: "cert-lookup",
    endpoint: "cert-lookup",
    name: "Certificate Lookup",
    shortName: "Cert",
    description: "Active certs from CT logs — issuer, expiry, SAN list, all certs covering the domain.",
    inputKind: "domain",
    inputField: "domain",
    placeholder: "example.com",
    icon: Lock,
    iconColor: "text-emerald-400",
  },
  {
    id: "reverse-dns",
    endpoint: "reverse-dns",
    name: "Reverse DNS Lookup",
    shortName: "Reverse DNS",
    description: "Hostnames pointing at a given IP — useful for asset attribution.",
    inputKind: "ip",
    inputField: "ip",
    placeholder: "8.8.8.8",
    icon: RefreshCcw,
    iconColor: "text-purple-400",
  },
  {
    id: "sensitive-paths",
    endpoint: "sensitive-paths",
    name: "Sensitive Paths Probe",
    shortName: "Paths",
    description: "Looks for exposed admin panels, env files, and other commonly-leaked paths.",
    inputKind: "domain",
    inputField: "domain",
    placeholder: "example.com",
    icon: FileSearch,
    iconColor: "text-orange-400",
  },
  {
    id: "github-leaks",
    endpoint: "github-leaks",
    name: "GitHub Leak Search",
    shortName: "GitHub",
    description: "Search GitHub code for secrets and config referencing a domain — surface what's already public.",
    inputKind: "domain",
    inputField: "domain",
    placeholder: "example.com",
    icon: Github,
    iconColor: "text-pink-400",
  },
  // Hidden — kept so the smart cert-lookup hash detection still has an
  // endpoint to hit. Not surfaced on the accordion.
  {
    id: "cert-hash",
    endpoint: "cert-hash",
    name: "Certificate Hash Lookup",
    shortName: "Hash",
    description: "Look up a cert by SHA-256 fingerprint.",
    inputKind: "hash",
    inputField: "hash",
    placeholder: "sha256 hex",
    icon: Lock,
    iconColor: "text-emerald-400",
    hidden: true,
  },
];

export const VISIBLE_TOOLS = TOOLS.filter((t) => !t.hidden);
```

- [ ] **Step 2: Continue to Task 3.3** — still no commit.

---

### Task 3.3: Build the accordion row component

**Files:**
- Create: `frontend/app/(unauthenticated)/tools/ToolAccordionRow.tsx`

- [ ] **Step 1: Create the component**

```tsx
// app/(unauthenticated)/tools/ToolAccordionRow.tsx
"use client";

import { useState, useCallback, useEffect } from "react";
import { ChevronDown, Loader2, ArrowRight } from "lucide-react";

import TurnstileWidget from "../TurnstileWidget";
import ToolResultView from "./ToolResultView";
import type { ToolConfig } from "./tools-config";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:5000/api";
const TURNSTILE_ENABLED = !!process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;

type Props = {
  tool: ToolConfig;
  /** Whether this row is currently the open one. */
  isOpen: boolean;
  /** Called when this row's header is clicked. */
  onToggle: () => void;
};

export default function ToolAccordionRow({ tool, isOpen, onToggle }: Props) {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const [widgetKey, setWidgetKey] = useState(0);

  // When the row is collapsed, clear the result so reopening starts clean.
  useEffect(() => {
    if (!isOpen) {
      setResult(null);
      setError(null);
    }
  }, [isOpen]);

  const canRun =
    input.trim().length > 0 &&
    !loading &&
    (!TURNSTILE_ENABLED || !!turnstileToken);

  const onRun = useCallback(async () => {
    if (!canRun) return;
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const body: Record<string, string> = { [tool.inputField]: input.trim() };
      if (turnstileToken) body.turnstileToken = turnstileToken;
      const res = await fetch(`${API_BASE}/tools/public/${tool.endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || `Request failed (${res.status})`);
      } else {
        setResult(data);
      }
    } catch {
      setError("Request failed. Please try again.");
    } finally {
      setLoading(false);
      setTurnstileToken(null);
      setWidgetKey((k) => k + 1);
    }
  }, [canRun, input, tool.endpoint, tool.inputField, turnstileToken]);

  const Icon = tool.icon;

  return (
    <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] overflow-hidden">
      {/* Header — click to toggle */}
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={isOpen}
        className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-white/[0.03] transition-colors"
      >
        <span className={`shrink-0 w-9 h-9 rounded-lg bg-white/[0.04] flex items-center justify-center ${tool.iconColor}`}>
          <Icon className="w-5 h-5" />
        </span>
        <span className="flex-1 min-w-0">
          <span className="block text-sm font-semibold text-white">{tool.name}</span>
          <span className="block text-xs text-white/50 mt-0.5 truncate">{tool.description}</span>
        </span>
        <ChevronDown
          className={`shrink-0 w-4 h-4 text-white/40 transition-transform ${isOpen ? "rotate-180" : ""}`}
        />
      </button>

      {/* Body — only mounted when open */}
      {isOpen && (
        <div className="px-5 pb-5 pt-1 space-y-3 border-t border-white/[0.06]">
          <div className="flex gap-2 pt-3">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && onRun()}
              placeholder={tool.placeholder}
              disabled={loading}
              className="flex-1 rounded-lg border border-white/[0.08] bg-white/[0.02] px-3 py-2 text-sm text-white placeholder:text-white/30 outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20 transition-all font-mono disabled:opacity-50"
            />
            <button
              type="button"
              onClick={onRun}
              disabled={!canRun}
              className={`shrink-0 rounded-lg px-4 py-2 text-sm font-semibold transition-all ${
                !canRun
                  ? "bg-white/[0.04] text-white/40 cursor-not-allowed"
                  : "bg-teal-600 text-white hover:bg-teal-500"
              }`}
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
            </button>
          </div>

          {TURNSTILE_ENABLED && (
            <TurnstileWidget
              key={widgetKey}
              onVerify={setTurnstileToken}
              onExpire={() => setTurnstileToken(null)}
              onError={() => setTurnstileToken(null)}
            />
          )}

          {error && (
            <div className="rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3 py-2 text-sm text-red-300">
              {error}
            </div>
          )}

          {result && (
            <div className="pt-1">
              <ToolResultView data={result} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Continue to Task 3.4.**

---

### Task 3.4: Build the `/tools` page

**Files:**
- Create: `frontend/app/(unauthenticated)/tools/page.tsx`

- [ ] **Step 1: Create `page.tsx`**

```tsx
// app/(unauthenticated)/tools/page.tsx
// Public lookup tools page — accordion of 8 visible tools, all gated by
// rate limit + Turnstile on the backend.
"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowRight } from "lucide-react";

import LandingNav from "../LandingNav";
import LandingFooter from "../LandingFooter";
import JsonLd from "../JsonLd";
import ToolAccordionRow from "./ToolAccordionRow";
import { VISIBLE_TOOLS } from "./tools-config";

const SITE_URL = "https://nanoeasm.com";
const PAGE_TITLE = "Free Security Lookup Tools — WHOIS, DNS, Cert, Headers — Nano EASM";
const PAGE_DESCRIPTION =
  "Free public lookup tools — WHOIS, DNS, certificate, HTTP headers, email security, and more. No signup, no card.";

const PAGE_JSONLD = {
  "@context": "https://schema.org",
  "@type": "WebPage",
  name: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  url: `${SITE_URL}/tools`,
  inLanguage: "en-AU",
  isPartOf: { "@type": "WebSite", name: "Nano EASM", url: SITE_URL },
};

const TOOLS_ITEMLIST_JSONLD = {
  "@context": "https://schema.org",
  "@type": "ItemList",
  name: "Free security lookup tools",
  itemListElement: VISIBLE_TOOLS.map((t, i) => ({
    "@type": "ListItem",
    position: i + 1,
    item: {
      "@type": "SoftwareApplication",
      name: t.name,
      description: t.description,
      applicationCategory: "SecurityApplication",
    },
  })),
};

const BREADCRUMB_JSONLD = {
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  itemListElement: [
    { "@type": "ListItem", position: 1, name: "Home", item: `${SITE_URL}/` },
    { "@type": "ListItem", position: 2, name: "Free Tools", item: `${SITE_URL}/tools` },
  ],
};

export default function ToolsPage() {
  // First tool is open by default — gives visitors immediate signal of
  // what the page does without making them click.
  const [openId, setOpenId] = useState<string | null>(VISIBLE_TOOLS[0].id);

  return (
    <div className="min-h-screen bg-[#060b18] text-white overflow-x-hidden">
      <JsonLd data={[PAGE_JSONLD, TOOLS_ITEMLIST_JSONLD, BREADCRUMB_JSONLD]} />
      <LandingNav />
      <div className="h-16" /> {/* spacer for fixed navbar */}

      <main>
        {/* ================= HERO ================= */}
        <section className="relative">
          <div className="absolute inset-0 overflow-hidden pointer-events-none">
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-gradient-to-b from-teal-500/[0.07] via-cyan-500/[0.04] to-transparent rounded-full blur-3xl" />
          </div>
          <div className="relative mx-auto max-w-3xl px-4 sm:px-6 pt-12 sm:pt-16 pb-8 text-center">
            <div className="inline-flex items-center gap-2 rounded-full border border-teal-500/20 bg-teal-500/[0.06] px-4 py-1.5 mb-6">
              <span className="text-xs font-medium text-teal-400/70 tracking-wide">Free lookup tools</span>
            </div>
            <h1 className="text-3xl sm:text-5xl font-bold leading-[1.1] tracking-tight">
              Quick checks for<br />
              <span className="bg-gradient-to-r from-teal-400/80 via-cyan-400/70 to-teal-500/80 bg-clip-text text-transparent">
                security teams.
              </span>
            </h1>
            <p className="mt-5 text-base sm:text-lg text-white/70 leading-7 max-w-2xl mx-auto">
              {VISIBLE_TOOLS.length} hand-picked utilities — WHOIS, DNS, certs, HTTP
              headers, email auth, leak search. One domain at a time, no signup.
            </p>
          </div>
        </section>

        {/* ================= ACCORDION ================= */}
        <section className="py-6 sm:py-8">
          <div className="mx-auto max-w-3xl px-4 sm:px-6 space-y-3">
            {VISIBLE_TOOLS.map((tool) => (
              <ToolAccordionRow
                key={tool.id}
                tool={tool}
                isOpen={openId === tool.id}
                onToggle={() => setOpenId((cur) => (cur === tool.id ? null : tool.id))}
              />
            ))}
          </div>
        </section>

        {/* ================= FINAL CTA ================= */}
        <section className="py-12 sm:py-16">
          <div className="mx-auto max-w-3xl px-4 sm:px-6">
            <div className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-gradient-to-br from-[#0d1a2e] to-[#0a1121] px-8 py-12 text-center sm:px-12">
              <div className="absolute inset-0 pointer-events-none">
                <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[400px] h-[200px] bg-teal-500/[0.06] rounded-full blur-3xl" />
              </div>
              <div className="relative">
                <h2 className="text-2xl sm:text-3xl font-bold tracking-tight">
                  Run these against your
                  <span className="bg-gradient-to-r from-teal-400/80 to-cyan-400/70 bg-clip-text text-transparent"> full inventory.</span>
                </h2>
                <p className="mt-3 text-base text-white/55 max-w-lg mx-auto">
                  A free account scans your whole asset list, monitors changes, and
                  alerts you when a cert is about to expire or a header gets dropped.
                </p>
                <div className="mt-7 flex flex-col sm:flex-row items-center justify-center gap-3">
                  <Link
                    href="/register"
                    className="group inline-flex items-center gap-2 rounded-xl bg-teal-600 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-teal-900/30 hover:bg-teal-500 transition-all"
                  >
                    Create free account
                    <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                  </Link>
                  <Link
                    href="/quick-scan"
                    className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-6 py-3 text-sm font-medium text-white/70 hover:text-white hover:bg-white/[0.06] transition-all"
                  >
                    Try Quick Scan instead
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>

      <LandingFooter />
    </div>
  );
}
```

**Note:** `page.tsx` is `"use client"` because it manages the `openId` state. Next.js can't statically generate it, but the JSON-LD blocks still render server-side because they're plain values, not state-dependent. Title/description metadata is set via the `<head>` mechanism — for client components, Next.js prefers a parent `layout.tsx` or a `metadata.ts` sibling. Add `metadata.ts` next:

- [ ] **Step 2: Create the metadata sibling so SEO tags render server-side**

Create `frontend/app/(unauthenticated)/tools/metadata.ts`:

```tsx
// Server-side Metadata for /tools. Sibling to page.tsx (client component).
import type { Metadata } from "next";

const SITE_URL = "https://nanoeasm.com";
const PAGE_TITLE = "Free Security Lookup Tools — WHOIS, DNS, Cert, Headers — Nano EASM";
const PAGE_DESCRIPTION =
  "Free public lookup tools — WHOIS, DNS, certificate, HTTP headers, email security, and more. No signup, no card.";

export const metadata: Metadata = {
  title: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  alternates: { canonical: "/tools" },
  openGraph: {
    title: PAGE_TITLE,
    description: PAGE_DESCRIPTION,
    url: `${SITE_URL}/tools`,
    type: "website",
    siteName: "Nano EASM",
    locale: "en_AU",
  },
  twitter: {
    card: "summary_large_image",
    title: PAGE_TITLE,
    description: PAGE_DESCRIPTION,
  },
};
```

Then in `page.tsx`, re-export it at the top of the file (just below the imports):

```tsx
export { metadata } from "./metadata";
```

Wait — Next.js does NOT allow a `"use client"` module to re-export `metadata`. The cleanest way is to make `page.tsx` a server component and split the interactive parts into a child client component. Here's the corrected structure:

**Replace the previous `page.tsx` plan** — instead split into two files:

1. **`page.tsx`** (server component, holds metadata + JSON-LD + layout shell)
2. **`ToolsAccordion.tsx`** (client component, holds the `openId` state + maps over `VISIBLE_TOOLS`)

- [ ] **Step 3: Restructure — create `tools/ToolsAccordion.tsx`**

```tsx
// app/(unauthenticated)/tools/ToolsAccordion.tsx
"use client";

import { useState } from "react";

import ToolAccordionRow from "./ToolAccordionRow";
import { VISIBLE_TOOLS } from "./tools-config";

export default function ToolsAccordion() {
  const [openId, setOpenId] = useState<string | null>(VISIBLE_TOOLS[0].id);

  return (
    <div className="space-y-3">
      {VISIBLE_TOOLS.map((tool) => (
        <ToolAccordionRow
          key={tool.id}
          tool={tool}
          isOpen={openId === tool.id}
          onToggle={() => setOpenId((cur) => (cur === tool.id ? null : tool.id))}
        />
      ))}
    </div>
  );
}
```

- [ ] **Step 4: Replace `page.tsx` content with the server-component version**

```tsx
// app/(unauthenticated)/tools/page.tsx
import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight } from "lucide-react";

import LandingNav from "../LandingNav";
import LandingFooter from "../LandingFooter";
import JsonLd from "../JsonLd";
import ToolsAccordion from "./ToolsAccordion";
import { VISIBLE_TOOLS } from "./tools-config";

const SITE_URL = "https://nanoeasm.com";
const PAGE_TITLE = "Free Security Lookup Tools — WHOIS, DNS, Cert, Headers — Nano EASM";
const PAGE_DESCRIPTION =
  "Free public lookup tools — WHOIS, DNS, certificate, HTTP headers, email security, and more. No signup, no card.";

export const metadata: Metadata = {
  title: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  alternates: { canonical: "/tools" },
  openGraph: {
    title: PAGE_TITLE,
    description: PAGE_DESCRIPTION,
    url: `${SITE_URL}/tools`,
    type: "website",
    siteName: "Nano EASM",
    locale: "en_AU",
  },
  twitter: {
    card: "summary_large_image",
    title: PAGE_TITLE,
    description: PAGE_DESCRIPTION,
  },
};

const PAGE_JSONLD = {
  "@context": "https://schema.org",
  "@type": "WebPage",
  name: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  url: `${SITE_URL}/tools`,
  inLanguage: "en-AU",
  isPartOf: { "@type": "WebSite", name: "Nano EASM", url: SITE_URL },
};

const TOOLS_ITEMLIST_JSONLD = {
  "@context": "https://schema.org",
  "@type": "ItemList",
  name: "Free security lookup tools",
  itemListElement: VISIBLE_TOOLS.map((t, i) => ({
    "@type": "ListItem",
    position: i + 1,
    item: {
      "@type": "SoftwareApplication",
      name: t.name,
      description: t.description,
      applicationCategory: "SecurityApplication",
    },
  })),
};

const BREADCRUMB_JSONLD = {
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  itemListElement: [
    { "@type": "ListItem", position: 1, name: "Home", item: `${SITE_URL}/` },
    { "@type": "ListItem", position: 2, name: "Free Tools", item: `${SITE_URL}/tools` },
  ],
};

export default function ToolsPage() {
  return (
    <div className="min-h-screen bg-[#060b18] text-white overflow-x-hidden">
      <JsonLd data={[PAGE_JSONLD, TOOLS_ITEMLIST_JSONLD, BREADCRUMB_JSONLD]} />
      <LandingNav />
      <div className="h-16" /> {/* spacer for fixed navbar */}

      <main>
        {/* HERO */}
        <section className="relative">
          <div className="absolute inset-0 overflow-hidden pointer-events-none">
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-gradient-to-b from-teal-500/[0.07] via-cyan-500/[0.04] to-transparent rounded-full blur-3xl" />
          </div>
          <div className="relative mx-auto max-w-3xl px-4 sm:px-6 pt-12 sm:pt-16 pb-8 text-center">
            <div className="inline-flex items-center gap-2 rounded-full border border-teal-500/20 bg-teal-500/[0.06] px-4 py-1.5 mb-6">
              <span className="text-xs font-medium text-teal-400/70 tracking-wide">Free lookup tools</span>
            </div>
            <h1 className="text-3xl sm:text-5xl font-bold leading-[1.1] tracking-tight">
              Quick checks for<br />
              <span className="bg-gradient-to-r from-teal-400/80 via-cyan-400/70 to-teal-500/80 bg-clip-text text-transparent">
                security teams.
              </span>
            </h1>
            <p className="mt-5 text-base sm:text-lg text-white/70 leading-7 max-w-2xl mx-auto">
              {VISIBLE_TOOLS.length} hand-picked utilities — WHOIS, DNS, certs, HTTP
              headers, email auth, leak search. One domain at a time, no signup.
            </p>
          </div>
        </section>

        {/* ACCORDION */}
        <section className="py-6 sm:py-8">
          <div className="mx-auto max-w-3xl px-4 sm:px-6">
            <ToolsAccordion />
          </div>
        </section>

        {/* FINAL CTA */}
        <section className="py-12 sm:py-16">
          <div className="mx-auto max-w-3xl px-4 sm:px-6">
            <div className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-gradient-to-br from-[#0d1a2e] to-[#0a1121] px-8 py-12 text-center sm:px-12">
              <div className="absolute inset-0 pointer-events-none">
                <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[400px] h-[200px] bg-teal-500/[0.06] rounded-full blur-3xl" />
              </div>
              <div className="relative">
                <h2 className="text-2xl sm:text-3xl font-bold tracking-tight">
                  Run these against your
                  <span className="bg-gradient-to-r from-teal-400/80 to-cyan-400/70 bg-clip-text text-transparent"> full inventory.</span>
                </h2>
                <p className="mt-3 text-base text-white/55 max-w-lg mx-auto">
                  A free account scans your whole asset list, monitors changes, and
                  alerts you when a cert is about to expire or a header gets dropped.
                </p>
                <div className="mt-7 flex flex-col sm:flex-row items-center justify-center gap-3">
                  <Link href="/register" className="group inline-flex items-center gap-2 rounded-xl bg-teal-600 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-teal-900/30 hover:bg-teal-500 transition-all">
                    Create free account
                    <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                  </Link>
                  <Link href="/quick-scan" className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-6 py-3 text-sm font-medium text-white/70 hover:text-white hover:bg-white/[0.06] transition-all">
                    Try Quick Scan instead
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>

      <LandingFooter />
    </div>
  );
}
```

(`metadata.ts` from the earlier step is no longer needed — `page.tsx` is now a server component and exports its own `metadata`. Delete `metadata.ts` if it was created.)

- [ ] **Step 5: Manual UI check**

`npm run dev`, visit `http://localhost:3000/tools`.

Expected:
- Hero renders with the teal/cyan gradient
- 8 accordion rows visible, first one (WHOIS) open by default
- Clicking another row collapses the previous and opens the new one
- Running WHOIS on `example.com` returns a result rendered by `ToolResultView`
- Page source contains the WebPage, ItemList, and BreadcrumbList JSON-LD blocks

---

### Task 3.5: Add the `/tools` link to landing page + nav

**Files:**
- Modify: `frontend/app/(unauthenticated)/QuickToolsCard.tsx`
- Modify: `frontend/app/(unauthenticated)/LandingNav.tsx`

- [ ] **Step 1: Add "See all 8 tools →" link to `QuickToolsCard`**

In `QuickToolsCard.tsx`, find the closing `</div>` of the result panel (around the end of the file, after the `<div className="px-6 pb-6 flex-1">...</div>` block). Just before the outermost component-return closing `</div>`, insert:

```tsx
{result && (
  <div className="px-6 pb-4 -mt-1">
    <Link
      href="/tools"
      className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-teal-400 hover:text-teal-300 transition-colors"
    >
      See all 8 tools <ArrowRight className="w-3 h-3" />
    </Link>
  </div>
)}
```

(`Link` is already imported at the top of the file; no new imports needed.)

- [ ] **Step 2: Add Free Tools to the nav Product dropdown**

In `LandingNav.tsx`, the Product `items` array (already updated in Task 2.3 to include Quick Discovery), add one more entry right after Quick Discovery:

```tsx
{ href: "/tools", label: "Free Tools", description: "Lookup utilities — WHOIS, DNS, certs, headers." },
```

So the final Product items list reads:

```tsx
items: [
  { href: "/#features", label: "Capabilities", description: "What the platform does, end to end." },
  { href: "/#how-it-works", label: "How it works", description: "Discover → scan → score → monitor." },
  { href: "/coverage", label: "Coverage", description: "Every finding category we detect.", badge: "New" },
  { href: "/quick-scan", label: "Quick Scan", description: "Try a free scan, no signup." },
  { href: "/quick-discovery", label: "Quick Discovery", description: "Find subdomains free, no signup." },
  { href: "/tools", label: "Free Tools", description: "Lookup utilities — WHOIS, DNS, certs, headers." },
  { href: "/#pricing", label: "Pricing", description: "Plan tiers and limits.", billingOnly: true },
],
```

---

### Task 3.6: Final verification + commit PR 3

- [ ] **Step 1: Walk the full user flow**

1. `http://localhost:3000/` → Product nav → Free Tools → page loads
2. Open each accordion row in turn — each closes the previous
3. Run a tool that takes a domain (DNS Lookup on `example.com`) → result renders
4. Run Reverse DNS on `8.8.8.8` → hostnames render
5. Trigger an error (e.g. invalid input) → error renders inline, doesn't break the page
6. `View page source` → confirm the WebPage, ItemList, and BreadcrumbList JSON-LD are all present in the HTML
7. On the landing page, run any tool in QuickToolsCard. After the result, the "See all 8 tools →" link appears. Click — routes to `/tools`.

- [ ] **Step 2: Confirm rate limit + Turnstile gate also fire on this surface**

With `TURNSTILE_SECRET_KEY` unset locally so verify is no-op, run any tool 11 times. The 11th should show the rate-limit error message inline (this comes from the backend's 429 response wrapped in `ToolAccordionRow`'s error state).

- [ ] **Step 3: Type-check + lint**

```bash
cd frontend
npx tsc --noEmit
npx next lint
```

Expected: no new errors.

- [ ] **Step 4: Stage and commit PR 3**

```bash
git add "frontend/app/(unauthenticated)/tools/" \
        "frontend/app/(unauthenticated)/QuickToolsCard.tsx" \
        "frontend/app/(unauthenticated)/LandingNav.tsx"
git commit -m "$(cat <<'EOF'
feat: add /tools dedicated public page (8-tool accordion)

Vertical accordion of WHOIS, DNS, email security, header check, cert
lookup, reverse DNS, sensitive paths, and GitHub leaks — all hitting the
existing rate-limit + Turnstile-gated public endpoints. ToolResultView
extracted from QuickToolsCard so both surfaces render results identically.
JSON-LD WebPage + ItemList + BreadcrumbList for SEO.

Landing-page card gets a 'See all 8 tools' link once it has results.
Nav entry added under Product.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Wait for the user's explicit push instruction.**

---

## Self-review

**Spec coverage:**
- `/quick-discovery` page with hero + embedded card → Phase 2 ✅
- `/tools` page as accordion → Phase 3 ✅
- 8 visible tools + 9th hidden cert-hash → tools-config.ts via VISIBLE_TOOLS filter ✅
- Landing-page deep-links from Discovery + Tools cards → Tasks 2.2 + 3.5 ✅
- Nav entries → Tasks 2.3 + 3.5 ✅
- Backend Turnstile + rate limit on 9 endpoints → Task 1.2 ✅
- Refactor `public_abuse_check` to shared module → Task 1.1 ✅
- Per-tool source buckets → Task 1.2 (table) ✅
- Rate-limit number 10/hr → Task 1.2 ✅
- SEO metadata + JSON-LD → Tasks 2.1, 3.4 ✅
- Backwards-compat for QuickToolsCard once Turnstile is required → Task 1.3 (this was an addition not in the original spec; needed to prevent prod breakage) ✅

**Placeholder scan:** None. All steps include the exact code or command.

**Type/name consistency:** `VISIBLE_TOOLS` defined in tools-config.ts and used consistently in `ToolsAccordion.tsx` + `page.tsx` + `tools-config.ts` re-exports. `ToolConfig` type used everywhere it's needed. `ToolResultView` default-exported and imported under the same name in both call sites.

**Files touched (across all 3 PRs):**

PR 1 (backend hardening + landing card token wiring):
- Create: `backend/app/utils/abuse_check.py`
- Modify: `backend/app/quick_scan/routes.py`, `backend/app/tools/routes.py`, `frontend/app/(unauthenticated)/QuickToolsCard.tsx`

PR 2 (`/quick-discovery` page):
- Create: `frontend/app/(unauthenticated)/quick-discovery/page.tsx`
- Modify: `frontend/app/(unauthenticated)/QuickDiscoveryCard.tsx`, `frontend/app/(unauthenticated)/LandingNav.tsx`

PR 3 (`/tools` page):
- Create: `frontend/app/(unauthenticated)/tools/{page.tsx, ToolsAccordion.tsx, ToolAccordionRow.tsx, ToolResultView.tsx, tools-config.ts}`
- Modify: `frontend/app/(unauthenticated)/QuickToolsCard.tsx`, `frontend/app/(unauthenticated)/LandingNav.tsx`
