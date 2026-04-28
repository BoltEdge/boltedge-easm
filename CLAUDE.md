# Nano EASM — Project Context for Claude Code

## What This Is
Nano EASM (nanoasm.com) is an External Attack Surface Management platform. Users add root domains, the system discovers assets (subdomains, IPs, services), scans them for vulnerabilities, scores exposure risk, and provides continuous monitoring with alerting.

## Domain & Branding
- **Product name:** Nano EASM (was previously "BoltEdge EASM" — fully rebranded April 2026)
- **Production URL:** https://nanoasm.com
- **No references to "BoltEdge" should exist anywhere in the codebase**
- **Brand colours:** Dark theme with teal (#14b8a6) accent

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
- **API client:** `frontend/app/lib/api.ts` (48KB, all backend calls)
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
├── billing/        # Plan management, trial handling
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
├── lib/                # API client, auth helpers, utils
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

## Environment Variables (Local Dev)
```
SQLALCHEMY_DATABASE_URI=postgresql://easm_user:localdevpassword@localhost:5432/easm
SECRET_KEY=local-dev-secret-key
CORS_ORIGINS=http://localhost:3000
NEXT_PUBLIC_API_BASE_URL=http://localhost:5000/api
ADMIN_EMAIL=admin@nanoasm.com
SHODAN_API_KEY=<your key>
RESEND_API_KEY=<your key>
```

## Running Locally
```bash
# Backend (terminal 1)
cd backend
$env:SQLALCHEMY_DATABASE_URI = "postgresql://easm_user:localdevpassword@localhost:5432/easm"
$env:SECRET_KEY = "local-dev-secret-key"
$env:CORS_ORIGINS = "http://localhost:3000"
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

## Important Rules
1. Never add BoltEdge references — the product is Nano EASM
2. `NEXT_PUBLIC_*` variables are baked in at build time — changes require `--no-cache` rebuild
3. Database schema changes must use Flask-Migrate: `flask db migrate` then `flask db upgrade`
4. The `models.py` file is large (60KB) — be careful with changes, check foreign keys
5. All API endpoints return JSON — never return HTML from the backend
6. External API keys are optional — engines should gracefully handle missing keys