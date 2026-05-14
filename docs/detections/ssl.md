# SSL / TLS Analysis

**Module:** `backend/app/scanner/engines/ssl_engine.py` + `backend/app/scanner/analyzers/ssl_analyzer.py`
**Detects:** Expired or near-expiring certificates, weak protocol versions (TLS 1.0/1.1), weak ciphers, self-signed or untrusted chains, missing OCSP stapling, certificate-name mismatches
**Plan gate:** Runs on all paid tiers via Standard / Deep profiles. `use_sslyze` profile flag controls per-scan (Quick scans skip it for speed)
**Severity:** Expiry urgency from days remaining (`<7d` → critical, `<30d` → high, `<90d` → medium). Protocol/cipher findings have fixed severities in the analyzer

## Required setup

None. Connects to the asset on port 443 (and other TLS-bearing ports Nmap identifies).

## Optional setup

None.

## How to verify

```bash
# Trigger a scan with the Standard or Deep profile on a domain. Look for engine activity:
docker compose logs easm-backend --tail=200 2>&1 | grep -i "SSLEngine\|ssl_analyzer"
# Expected: cert capture + analysis lines

# Or query a known asset's findings:
docker compose exec easm-db psql -U easm_user -d easm -c "
SELECT public_id, severity, title FROM finding
WHERE category='ssl' AND ignored=false AND resolved=false
ORDER BY id DESC LIMIT 5;
"
```

## Operational notes

- 10-second connection timeout per endpoint
- The engine captures the full certificate chain, not just the leaf
- Continuous monitoring (when enabled per asset) re-checks certificates on each monitoring tick so near-expiry alerts catch problems with lead time
- TLS 1.0 / 1.1 findings are tagged as `security_hygiene` rather than critical — they're a hygiene issue, not an active exploit
- No external API dependency — works fully offline

## Findings produced

Templates live in `app/scanner/templates.py` under the `ssl` category. Common ones:

| Template ID | Trigger | Severity |
|---|---|---|
| `ssl-cert-expired` | Cert already past notAfter | critical |
| `ssl-cert-expiring-soon` | Cert expires within 7 days | critical |
| `ssl-cert-expiring` | Cert expires within 30 days | high |
| `ssl-cert-expiring-90d` | Cert expires within 90 days | medium |
| `ssl-protocol-tls10` | TLS 1.0 enabled | medium |
| `ssl-protocol-tls11` | TLS 1.1 enabled | medium |
| `ssl-weak-cipher` | Weak cipher suite supported | medium |
| `ssl-self-signed` | Cert is self-signed | high |
| `ssl-name-mismatch` | Cert CN/SAN doesn't match the hostname | high |
| `ssl-no-ocsp-stapling` | OCSP stapling not configured | low |

**Customer-facing category:** Security Hygiene
