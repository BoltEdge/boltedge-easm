# DNS Records (SPF / DMARC / DKIM)

**Module:** `backend/app/scanner/engines/dns_engine.py` + `backend/app/scanner/analyzers/dns_analyzer.py` + `backend/app/scanner/analyzers/subdomain_takeover_analyzer.py`
**Detects:** Missing or weak SPF policy, weak DMARC policy (`p=none` in production), missing DKIM selectors, dangling CNAMEs pointing at unclaimed services (subdomain-takeover candidates), wildcard delegations
**Plan gate:** Runs on all paid tiers via Standard / Deep profiles
**Severity:** DMARC `p=none` → medium; missing SPF → medium; dangling CNAME → high (takeover potential)

## Required setup

None. Uses `dnspython` (already a runtime dependency) to query the customer's DNS records.

## Optional setup

None.

## How to verify

```bash
docker compose logs easm-backend --tail=200 2>&1 | grep -i "DNSEngine\|dns_analyzer\|takeover"

# Recent DNS-category findings:
docker compose exec easm-db psql -U easm_user -d easm -c "
SELECT public_id, severity, title FROM finding
WHERE category='dns' AND ignored=false AND resolved=false
ORDER BY id DESC LIMIT 10;
"
```

## Operational notes

- DNS resolution uses the container's system resolver — make sure the host DNS is reachable from the container
- Subdomain-takeover detection works by cross-referencing CNAME targets against a curated list of services where unclaimed targets are exploitable (Heroku, GitHub Pages, Azure CloudApp, etc.)
- DMARC parsing handles the common policy formats — `p=none`, `p=quarantine`, `p=reject`, `pct=N`, `rua=mailto:...`
- DKIM detection only checks a list of common selectors (default, google, mail, k1, etc.). Custom selectors won't be inventoried but aren't an error condition

## Findings produced

| Template ID | Trigger | Severity |
|---|---|---|
| `dns-no-spf` | No SPF record on the domain | medium |
| `dns-spf-too-permissive` | SPF `+all` or `?all` | high |
| `dns-spf-soft-fail` | SPF `~all` (soft fail) | low (info-grade) |
| `dns-no-dmarc` | No `_dmarc` TXT record | medium |
| `dns-dmarc-p-none` | DMARC policy is `p=none` | medium |
| `dns-dmarc-no-rua` | DMARC has no `rua=` reporting URI | low |
| `dns-no-dkim` | No DKIM TXT records found at any common selector | low |
| `subdomain-takeover-vulnerable` | CNAME points at a service where target is unclaimed | high |
| `subdomain-takeover-suspect` | CNAME pattern suggests takeover risk but couldn't confirm | medium |

**Customer-facing category:** Security Hygiene (SPF/DMARC/DKIM), Misconfigurations (takeover)
