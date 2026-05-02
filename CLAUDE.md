# Nano EASM — Project Context for Claude Code

## What This Is
Nano EASM (nanoasm.com) is an External Attack Surface Management platform. Users add root domains, the system discovers assets (subdomains, IPs, services), scans them for vulnerabilities, scores exposure risk, and provides continuous monitoring with alerting.

## Domain & Branding
- **Product name:** Nano EASM (was previously "BoltEdge EASM" — fully rebranded April 2026)
- **Production URL:** https://nanoasm.com
- **No references to "BoltEdge" should exist anywhere in the codebase**
- **Brand colours:** Dark theme with teal (#14b8a6) accent

## Current Product Status (v2 — April 2026)
Nano EASM v2 is open-source and **free to use during community preview**. Plans still exist and control feature limits, but billing and payment are disabled. Key points:

- Plans (Free, Starter, Professional, Enterprise Silver, Enterprise Gold) are **free upgrade tiers** — no payment is required
- All pricing, payment, subscription, checkout, and trial wording is **hidden from the UI**
- Plan limits and feature gates still enforce (assets, scans, team members, schedules, API keys, monitoring, deep discovery, webhooks)
- Real billing can be re-enabled later via a feature flag — **do not remove billing code**

## Tech Stack

### Backend (Flask/Python)
- **Framework:** Flask with blueprints, SQLAlchemy ORM, Flask-JWT-Extended for auth
- **Database:** PostgreSQL 16 (production on EC2, local dev on localhost:5432)
- **Entry point:** `backend/manage.py` → `gunicorn manage:app` in production
- **Config:** Environment variables loaded from `.env` — key one is `SQLALCHEMY_DATABASE_URI`
- **Migrations:** Flask-Migrate (Alembic) in `backend/migrations/`
- **Background jobs:** APScheduler for monitoring, scan schedules, trial expiry checks

### Frontend (Next.js/TypeScript)
- **Framework:** Next.js 16 with App Router, TypeScript, Tailwind CSS
- **Config:** `frontend/next.config.ts` with standalone output for Docker
- **API client:** `frontend/app/lib/api.ts` (all backend calls go through here)
- **Route groups:** `(authenticated)/` requires login, `(unauthenticated)/` is public

## Directory Structure

```
backend/app/
├── auth/           # JWT authentication, RBAC, permissions
├── assets/         # Asset CRUD + intelligence enrichment
├── discovery/      # Asset discovery (11 modules: CT logs, DNS enum, Shodan, etc.)
├── scanner/        # Vulnerability scanning (9 engines + 13 analyzers)
├── findings/       # Vulnerability findings management
├── monitoring/     # Continuous monitoring + change detection
├── reports/        # PDF/Excel report generation
├── integrations/   # Slack, Jira, webhooks, email notifications
├── billing/        # Plan management, trial handling (Stripe-ready stubs, not wired)
├── groups/         # Asset group management
├── tools/          # Public lookup tools (no auth required)
├── dashboard/      # Dashboard stats aggregation
├── trending/       # Trending analytics
├── settings/       # User/org settings
├── scan_jobs/      # Scan job management + comparison
├── scan_profiles/  # Quick/Standard/Deep scan profiles
├── scan_schedules/ # Scheduled scanning
├── quick_scan/     # Public quick scan (no auth)
├── audit/          # Activity audit logging
├── services/       # External API clients (Shodan, VirusTotal, AbuseIPDB, etc.)
├── utils/          # Validators, formatters, exceptions
├── models.py       # All SQLAlchemy models (60KB)
└── __init__.py     # App factory (blueprint registration, CORS, error handlers)

frontend/app/
├── (authenticated)/    # Protected pages (dashboard, assets, discovery, scan, etc.)
├── (unauthenticated)/  # Public pages (landing, login, register, quick-scan)
├── lib/                # API client, auth helpers, utils, billing-config
├── ui/                 # Reusable UI components
├── Sidebar.tsx         # App navigation sidebar
├── TopBar.tsx          # Top navigation bar
└── layout.tsx          # Root layout
```

## Key Architecture Patterns

### Backend
- Each module has `routes.py` (Flask blueprints) and supporting files
- All routes return JSON with consistent error format
- Auth uses JWT tokens with role-based permissions (Viewer, Analyst, Admin, Owner)
- Plan-based limits enforced via decorators in `auth/permissions.py`
- Discovery uses an orchestrator pattern: `discovery/orchestrator.py` coordinates 11 modules
- Scanner uses an orchestrator pattern: `scanner/orchestrator.py` coordinates 9 engines → 13 analyzers
- Finding templates defined in `scanner/templates.py` (75+ finding types)
- `models.py` is the single source of truth for all database tables

### Frontend
- App Router with route groups for auth separation
- `api.ts` is the central API client — all backend calls go through here
- Component pattern: pages import from `ui/`, `lib/`, and local components
- Sidebar.tsx and TopBar.tsx contain the navigation and brand logo
- `lib/billing-config.ts` exports `BILLING_ENABLED` — all billing/pricing UI is gated on this

## Platform Admin Console

A hidden superadmin area exists at `/admin`. It is not linked from anywhere in the normal UI and returns a generic 404 to non-superadmins.

### Superadmin flag
- `User.is_superadmin` boolean column (default `False`) in the database
- Only granted via Flask CLI — no UI to grant/revoke (intentional, prevents privilege escalation)

### Grant / revoke via CLI
```bash
# On the server:
flask grant-superadmin your@email.com
flask revoke-superadmin your@email.com

# In Docker:
docker compose exec easm-backend flask grant-superadmin your@email.com
```

### Admin capabilities
| Page | URL | What it does |
|---|---|---|
| Dashboard | `/admin/dashboard` | Platform-wide stats: orgs, users, assets, scans, plan distribution |
| Organizations | `/admin/organizations` | All orgs — search, filter by plan, suspend/archive/delete. Links to org detail |
| Org Detail | `/admin/organizations/<id>` | Usage, members, plan, custom limits editor, suspend/archive/delete |
| Users | `/admin/users` | All users — search, filter by role/org/suspension. Impersonate, reset password, suspend, delete |
| Audit Log | `/admin/audit-log` | Platform-wide audit log — filter by org, category, date range, search |
| Active Scans | `/admin/scans` | Live view of scan + discovery jobs across all orgs. Auto-refreshes every 15s |
| Broadcast | `/admin/broadcast` | Send info/warning/critical announcements to all orgs or a specific org |
| Health | `/admin/health` | DB ping + pool stats, job queue depths, error rates, uptime, platform totals |
| Quick Scans | `/admin/quick-scans` | Unauthenticated quick-scan log, top IPs, rate-limit tracking, IP block list |

### Admin backend endpoints (`/admin/*`)
All return **404** for non-superadmins (do not reveal existence).
```
GET    /admin/stats                          — platform-wide counts + plan breakdown
GET    /admin/organizations                  — all orgs (paginated, searchable, filterable)
GET    /admin/organizations/<id>             — single org detail + usage + members + limits
POST   /admin/organizations/<id>/plan        — change any org's plan
POST   /admin/organizations/<id>/limits      — set per-org limit overrides (JSON column)
POST   /admin/organizations/<id>/archive     — toggle org archived/active
POST   /admin/organizations/<id>/suspend     — toggle org suspended (blocks all logins)
DELETE /admin/organizations/<id>             — hard-delete org + all data (DB cascade)
GET    /admin/users                          — all users (paginated, filterable by role/org/suspended)
POST   /admin/users/<id>/impersonate         — issue session token for user (admin acts as them)
POST   /admin/users/<id>/reset-password      — generate password reset link, optional Resend email
POST   /admin/users/<id>/suspend             — toggle user suspended
DELETE /admin/users/<id>                     — hard-delete user (DB cascade)
GET    /admin/audit-log                      — platform-wide audit log (all orgs)
GET    /admin/scans                          — active + recent scan/discovery jobs (all orgs)
GET    /admin/announcements                  — list all platform announcements
POST   /admin/announcements                  — create announcement
DELETE /admin/announcements/<id>             — delete announcement
GET    /admin/health                         — platform health stats
GET    /admin/quick-scans                    — unauthenticated quick-scan log
GET    /admin/blocked-ips                    — IP block list
POST   /admin/blocked-ips                    — block an IP (with optional reason + expiry)
DELETE /admin/blocked-ips/<id>               — unblock an IP
```

### User-facing admin endpoints (authenticated users)
```
GET  /auth/announcements   — active announcements for this user's org (shown as dismissible banners)
```

### Security model
- `require_superadmin` decorator re-fetches user from DB on every request (no JWT-only trust)
- Returns 404 (not 401/403) on failure — route appears to not exist
- All admin actions are audit-logged
- Admin grants never set `plan_expires_at` — plans don't expire
- Impersonation is audit-logged; frontend stores return session in `asm_impersonate_return` localStorage key

### Key models added for admin features
- `User.is_superadmin` — boolean, default False, grant via CLI only
- `User.is_suspended` — boolean, blocks login with `ACCOUNT_SUSPENDED` 403
- `Organization.is_suspended` — boolean, blocks login for all org members
- `Organization.limit_overrides` — JSON column, merged with plan defaults in `get_effective_limits()`
- `AuditLog.organization_id` — nullable (admin actions have no org context)
- `PlatformAnnouncement` — title, body, kind (info/warning/critical), target_org_id (null=all), expires_at
- `QuickScanLog` — IP, user agent, target, status, duration, risk score, finding counts per severity
- `BlockedIP` — IP, reason, blocked_by, expires_at (null=permanent)

### Impersonation flow
1. Admin clicks impersonate on any non-superadmin user
2. Backend issues a normal session token for that user, audit-logs the action
3. Frontend saves admin session to `asm_impersonate_return`, sets `asm_impersonating` flag
4. Amber banner appears on every page: "Impersonating [name] — Exit impersonation"
5. Exit restores the admin session from localStorage and redirects to `/admin/users`

### Quick scan abuse protection
- Every unauthenticated `/quick-scan` request is logged to `quick_scan_log`
- Rate limit: 5 scans/hour per IP (checked against the log table — no Redis needed)
- Block list checked on entry; blocked IPs get 403, rate-limited get 429
- Both are logged with status `blocked` / `rate_limited`
- Admin view at `/admin/quick-scans` shows log, top IPs (24h), and block list management

### Announcement banners
- Admin creates via `/admin/broadcast` — kind, optional body, optional target org, optional expiry
- Users see dismissible banners in the authenticated layout (above page content)
- Dismissed IDs stored in `asm_dismissed_announcements` localStorage — survives page reload

### DB migrations (apply in order)
```bash
flask db upgrade
```
Pending migrations (chain from `e4f9a2b3c1d6`):
- `f5a1b2c3d4e6` — add `platform_announcement` table
- `a1b2c3d4e5f6` — make `audit_log.organization_id` nullable
- `b1c2d3e4f5a6` — add `quick_scan_log` and `blocked_ip` tables

## Billing Feature Flag

Billing UI is controlled by a single feature flag. **Currently set to `false`.**

### Frontend flag
`NEXT_PUBLIC_ENABLE_BILLING=false` in `frontend/.env.local`

Read via `frontend/app/lib/billing-config.ts`:
```ts
export const BILLING_ENABLED = process.env.NEXT_PUBLIC_ENABLE_BILLING === "true";
```

### Backend flag
`ENABLE_BILLING=false` (env var, defaults to false if not set)

Read in `backend/app/billing/routes.py`:
```python
ENABLE_BILLING = os.environ.get("ENABLE_BILLING", "false").lower() == "true"
```

### What changes when `BILLING_ENABLED=false` (current state)
**Frontend:**
- Landing page: pricing section hidden, "Pricing" nav link hidden, hero CTA says "Get started free"
- Sidebar: "Payment & Plans" → "Plans"
- Plans page (`/settings/billing`): no prices shown, no trial buttons, upgrade buttons say "Switch to this plan", Enterprise Gold shows "Contact Us" (mailto:contact@nanoasm.com)
- Monitoring upgrade prompt: no prices shown, "Switch to {plan}" instead of "Start Trial"
- TopBar and Sidebar: trial countdown badge hidden
- Register page: "No credit card required" → "Free to use"

**Backend:**
- `/billing/upgrade`: sets plan to active with no expiry date (`plan_expires_at = None`)
- Free upgrades work immediately — users click "Switch to this plan" and it takes effect

### What changes when `BILLING_ENABLED=true` (future)
- Full pricing UI restored on landing page, Plans page, and monitoring upgrade prompt
- Trial buttons restored (14/21/30/45-day trials)
- Upgrade sets `plan_expires_at` (30 days monthly, 365 days annual)
- Enterprise Gold requires contacting sales (403 response from backend)
- Trial expiry scheduler downgrades orgs automatically

### Billing backend endpoints (always present, regardless of flag)
```
GET  /billing/plan        — current org plan + usage + limits
GET  /billing/plans       — all 5 plan tiers with metadata
POST /billing/start-trial — start a free trial (billing mode only)
POST /billing/upgrade     — switch to a paid/free tier
POST /billing/downgrade   — revert to Free plan
POST /billing/cancel      — cancel trial or subscription
DELETE /billing/organization — delete org (owner only)
```

### Plan tiers and limits *(redesigned May 2026, cost-aware — see "Cost rationale" below before changing)*

| Plan | Price | Assets (inventory) | Monitored assets | Monitor freq | Scans/mo | Discoveries/mo | Members | Schedules | API Keys | Deep Discovery | Webhooks |
|------|-------|--------------------|------------------|--------------|----------|----------------|---------|-----------|----------|----------------|----------|
| Free | $0 | 2 | 0 | — | 5 | 2 | 1 | 1 | 1 | ✗ | ✗ |
| Starter | $19 | 15 | 5 | every 7d | 100 | 10 | 5 | 5 | 3 | ✗ | ✗ |
| Professional | $99 | 100 | 25 | every 3d | 1,000 | 50 | 20 | 25 | 10 | ✓ | ✓ |
| Enterprise Silver | $499 | 1,000 | 100 | daily | 6,000 | 200 | 100 | 100 | ∞ | ✓ | ✓ |
| Enterprise Gold | from $1,999 | 10,000 | 500 | every 12h | 50,000 (fair use) | ∞ | ∞ | ∞ | ∞ | ✓ | ✓ |

**Trials are request-only** for every paid tier — clicking "Request free trial" creates a typed `contact_request` that admins review and approve manually. Admin sets the trial duration when granting (no hard-coded `trialDays`). See `POST /billing/start-trial`.

### Cost rationale (DO NOT remove caps without re-running this math)

The big lever is **monitored-assets × monitoring frequency**. A monitor is a recurring scan job — the cost compounds every cycle, forever, per customer. Earlier plan designs that said "Silver: 15,000 assets, daily monitoring, unlimited scans" would have burned **$3,000+/mo per Silver customer in marginal cost** on a $249 plan. The redesigned plans separate `assets` (cheap inventory) from `monitored_assets` (the expensive recurring dial) and cap `scans_per_month` to cover BOTH manual and monitoring traffic in one budget.

**Per-scan marginal costs** (Shodan Corporate ~$0.001/credit, EC2 t2.medium near full utilisation):

| Operation | Cost |
|---|---|
| Quick scan (3–5 Shodan credits + ~5s compute) | ~$0.01 |
| Standard scan (10–15 credits + ~30s compute) | ~$0.02 |
| Deep scan (15–25 credits + ~120s compute) | ~$0.04 |
| Discovery job (CT + brute + ~30s compute) | ~$0.05 |

**Margin check per tier** (Standard-scan averages, full-quota usage):

| Tier | Price | Max scan cost | Disc cost | Hosting/Stripe | Total cost | Margin | Margin % |
|---|---|---|---|---|---|---|---|
| Starter | $19 | $2.00 | $0.50 | $0.50 | $3.00 | $16 | 84% |
| Professional | $99 | $20.00 | $2.50 | $2.00 | $24.50 | $74 | 75% |
| Enterprise Silver | $499 | $120.00 | $10.00 | $5.00 | $135.00 | $364 | 73% |
| Enterprise Gold | $1,999 | $1,000 (capped) | — | $20.00 | ~$1,020 | $979 | 49% |

**Hard rules — verify against these before changing any limit:**

1. **Never give a tier `scans_per_month: -1` (unlimited)** — Enterprise Gold has a soft 50,000/mo "fair use" cap; sales prices anything above that as a separate contract. Only Pro+ get explicit unlimited on `api_keys` (cheap to give) and Gold on `members`/`schedules` (also cheap).
2. **Free tier never gets monitoring** — recurring scans on a $0 plan = unbounded loss.
3. **Asset count and monitored_assets are independent dials.** Inventory is cheap (DB rows). Monitored is what bleeds.
4. **scans_per_month must mathematically cover monitoring + manual usage.** Formula: `monitored_assets × scans_per_month_per_monitored_asset_at_freq + manual_headroom`. If a Silver customer monitors 100 assets daily that's 3,000 scans/mo gone — `scans_per_month: 6,000` leaves them 3,000 for manual scans.
5. **Multi-million-asset prospects are sales-priced contracts**, not auto-provisioned via the website. Per-asset pricing ($1–$10/asset/mo) negotiated annually with usage caps. Don't accept "10M assets monitored hourly" via the contact form without quoting properly.
6. **API costs scale with Shodan plan tier.** If you downgrade your Shodan subscription, every margin number above shifts.

### Tracking real costs

`scans_per_month` is enforced via `check_limit("scans_per_month")` on the scan-job creation route — both manual and monitoring scans count against this single budget. `monitored_assets` is enforced via `check_limit("monitored_assets")` on the monitor-creation route. `discoveries_per_month` is enforced on `POST /discovery/run`. Live counts come from `_get_current_usage()` in `app/auth/permissions.py`.

### Stripe status
Stripe is **not implemented**. The database has `stripe_customer_id` and `stripe_subscription_id` nullable columns on the `Organization` model as stubs for future integration. No Stripe SDK, no API calls, no webhooks.

## Environment Variables (Local Dev)
```
# Backend
SQLALCHEMY_DATABASE_URI=postgresql://easm_user:localdevpassword@localhost:5432/easm
SECRET_KEY=local-dev-secret-key
CORS_ORIGINS=http://localhost:3000
ADMIN_EMAIL=admin@nanoasm.com
ENABLE_BILLING=false
SHODAN_API_KEY=<your key>
RESEND_API_KEY=<your key>

# Frontend (.env.local)
NEXT_PUBLIC_API_BASE_URL=http://localhost:5000/api
NEXT_PUBLIC_ENABLE_BILLING=false
```

## Running Locally
```bash
# Backend (terminal 1)
cd backend
$env:SQLALCHEMY_DATABASE_URI = "postgresql://easm_user:localdevpassword@localhost:5432/easm"
$env:SECRET_KEY = "local-dev-secret-key"
$env:CORS_ORIGINS = "http://localhost:3000"
$env:ENABLE_BILLING = "false"
python run.py

# Frontend (terminal 2)
cd frontend
npm run dev
```

## Production Deployment (EC2)
- **Server:** AWS EC2 t2.medium, Ubuntu 24.04, IP 34.232.100.29
- **Directory:** ~/boltedge-easm/ on EC2
- **Containers:** easm-frontend, easm-backend, easm-db
- **Proxy:** Shared Nginx at ~/boltedge/ routes nanoasm.com traffic
- **Deploy:** `cd ~/boltedge-easm && git pull && docker compose up -d --build`
- **Note:** `NEXT_PUBLIC_*` variables are baked in at build time — env changes require `--no-cache` rebuild

## Important Rules
1. Never add BoltEdge references — the product is Nano EASM
2. Do not remove billing/payment/plan code — it is temporarily hidden by feature flag, not deleted
3. `NEXT_PUBLIC_*` variables are baked in at build time — changes require `--no-cache` rebuild
4. Database schema changes must use Flask-Migrate: `flask db migrate` then `flask db upgrade`
5. The `models.py` file is large (60KB) — be careful with changes, check foreign keys
6. All API endpoints return JSON — never return HTML from the backend
7. External API keys are optional — engines should gracefully handle missing keys
8. All billing/pricing UI changes must go through `BILLING_ENABLED` from `lib/billing-config.ts` — never hardcode pricing visibility
