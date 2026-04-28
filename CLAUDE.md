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
| Page | URL | What it shows |
|---|---|---|
| Dashboard | `/admin/dashboard` | Total orgs, users, new orgs (30d), total assets, scans this month, plan distribution bar chart |
| Organizations | `/admin/organizations` | All orgs — searchable, filterable by plan, paginated. Inline plan change dropdown per org |
| Users | `/admin/users` | All users — searchable, paginated. Shows org, role, superadmin badge |

### Admin backend endpoints (`/admin/*`)
All return **404** for non-superadmins (do not reveal existence).
```
GET  /admin/stats                    — platform-wide stats
GET  /admin/organizations            — all orgs (paginated, searchable)
GET  /admin/organizations/<id>       — single org detail + members
POST /admin/organizations/<id>/plan  — change any org's plan (no expiry set)
GET  /admin/users                    — all users (paginated, searchable)
```

### Security model
- `require_superadmin` decorator re-fetches user from DB on every request (no JWT-only trust)
- Returns 404 (not 401/403) on failure — route appears to not exist
- All plan changes via admin are audit-logged with `action: "admin.plan_changed"`
- Admin grants never set `plan_expires_at` — plans don't expire

### DB migration needed
After deploying, run once:
```bash
flask db migrate -m "add is_superadmin to user"
flask db upgrade
# or in Docker:
docker compose exec easm-backend flask db migrate -m "add is_superadmin to user"
docker compose exec easm-backend flask db upgrade
```

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

### Plan tiers and limits
| Plan | Assets | Scans/mo | Members | Schedules | API Keys | Monitoring | Deep Discovery | Webhooks |
|------|--------|----------|---------|-----------|----------|------------|----------------|----------|
| Free | 2 | 4 | 1 | 2 | 1 | ✗ | ✗ | ✗ |
| Starter | 15 | 500 | 5 | 10 | 3 | Every 5d | ✗ | ✗ |
| Professional | 100 | 5,000 | 20 | 50 | 10 | Every 2d | ✓ | ✓ |
| Enterprise Silver | 15,000 | Unlimited | 100 | 100 | Unlimited | Daily | ✓ | ✓ |
| Enterprise Gold | 50,000 | Unlimited | Unlimited | Unlimited | Unlimited | Every 12h | ✓ | ✓ |

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
