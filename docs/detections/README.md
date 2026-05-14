# Detection Coverage — Operator Setup Guide

Each file in this directory is an operator-side reference for one detection capability:

- **What it detects** — one-line summary of the threat surface
- **Plan gate** — which plan tiers can access the feature
- **Required setup** — env vars, accounts, third-party tokens, anything an operator needs to provision before the feature works
- **Optional setup** — keys or accounts that improve the feature but aren't strictly required
- **How to verify** — concrete commands to confirm it's working
- **Operational notes** — cost, rate limits, known gotchas
- **Findings produced** — template IDs and customer category for the resulting findings

Use this as the deploy checklist when bringing up a new environment, and as the troubleshooting reference when a detection isn't producing findings as expected.

## Detection inventory

| # | Detection | File | Required setup |
|---|---|---|---|
| 1 | Sensitive path scanning | [sensitive-paths.md](sensitive-paths.md) | None |
| 2 | Shodan (host intel + CVEs) | [shodan.md](shodan.md) | `SHODAN_API_KEY` |
| 3 | SSL / TLS analysis | [ssl.md](ssl.md) | None |
| 4 | HTTP header + behaviour | [http.md](http.md) | None |
| 5 | DNS records (SPF/DMARC/DKIM) | [dns.md](dns.md) | None |
| 6 | Nmap port scanning | [nmap.md](nmap.md) | None (binary baked into image) |
| 7 | Nuclei CVE templates | [nuclei.md](nuclei.md) | None (binary baked into image) |
| 8 | Database probe | [db-probe.md](db-probe.md) | None (consumes Nmap output) |
| 9 | Cloud asset detection | [cloud-asset.md](cloud-asset.md) | None |
| 10 | Leak engine | [leak.md](leak.md) | `GITHUB_TOKEN` (recommended), `GITLAB_TOKEN` (optional), `PASTEBIN_FETCHER_ENABLED` + IP whitelist (optional) |
| 11 | KEV + EPSS enrichment | [kev-epss.md](kev-epss.md) | None |
| 12 | Lookalike domain detection | [lookalike.md](lookalike.md) | None (uses crt.sh; no token) |
| 13 | Site Mimic Watch | [site-mimic.md](site-mimic.md) | `MIMIC_ENABLED=true`, `MIMIC_S3_BUCKET`, S3 bucket provisioned, Chromium baked into image |

## Quick-deploy checklist for a fresh environment

The minimum env vars to get full coverage running on a new deployment:

```bash
# Core (required for anything to work)
SQLALCHEMY_DATABASE_URI=postgresql://...
SECRET_KEY=...
CORS_ORIGINS=https://yourdomain.com

# Shodan host intel (powers CVE enrichment via Shodan's vuln data)
SHODAN_API_KEY=...

# Leak detection — GitHub code / issues / commits
GITHUB_TOKEN=...

# Leak detection — GitLab public blobs (optional but recommended)
GITLAB_TOKEN=...

# Leak detection — Pastebin (optional; requires a Pastebin PRO account first)
PASTEBIN_FETCHER_ENABLED=false   # set true after account + IP whitelist done

# Site Mimic Watch (optional; requires S3 bucket and Chromium in image)
MIMIC_ENABLED=false
MIMIC_S3_BUCKET=
MIMIC_S3_REGION=us-east-1

# Email + bot protection (operational, not detection)
RESEND_API_KEY=...
TURNSTILE_SECRET_KEY=...
MFA_SECRET_KEY=...
```

Detections without setup (sensitive paths, SSL, HTTP, DNS, Nmap, Nuclei, DB probe, cloud asset, KEV/EPSS, Lookalike) work the moment the backend is running.

## Conventions used in these docs

- **Plan gate** lines refer to the `PLAN_CONFIG` keys in `backend/app/billing/routes.py`. Limit value of `-1` means unlimited.
- **Severity** comes from the engine's per-finding logic — operator-side setup doesn't change severity behaviour.
- **Verification commands** assume you have `docker compose` access to the running stack on the deployment host.
- Where a feature is bundled with another (e.g. Site Mimic Watch is bundled with Lookalike), enabling the dependency enables both.
