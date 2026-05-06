# Domain Migration — `nanoasm.com` → `nanoeasm.com`

| Field | Value |
|---|---|
| Document | Domain migration runbook |
| Owner | Founder / sole engineer |
| Effective | 2026-05-06 |
| Status | In progress (code-level change complete; DNS / external services pending) |

This document records the migration of Nano EASM from `nanoasm.com` to `nanoeasm.com`. The trigger was brand-entity SEO confusion with the `sehugg/nanoasm` open-source Verilog assembler — Google's entity graph was conflating the two domains. The new domain `nanoeasm.com` reads more naturally as "nano" + "EASM" and aligns with our branded "Nano EASM" wordmark (always written with a space).

The product name **Nano EASM** is unchanged. App functionality is unchanged. This is a domain / config / SEO / email migration.

---

## 1. Authority model

- **Primary domain:** `https://nanoeasm.com`
- **Legacy domain:** `https://nanoasm.com` — permanent **301 redirect** to `https://nanoeasm.com` (preserve path + query string)
- The 301 must be set up at the DNS / proxy layer **before** announcing the new domain to customers, so any inbound link from the old SEO work, social shares, or pasted URLs lands correctly.

---

## 2. What changed in code

A single sed-substitution `nanoasm.com → nanoeasm.com` was applied across the whole repo. Because the new domain is just the old plus an extra `e`, every email and URL form (`@nanoasm.com`, `https://nanoasm.com`, `nanoasm.com/api`, `support@nanoasm.com`, etc.) gets the same fix uniformly.

### Files updated (~83 files)
- Frontend: layout, sitemap, robots, opengraph image, all metadata exports, AnimatedDashboard fake URL bar, all auth/legal page wordmarks
- Backend: `FRONTEND_URL` defaults, all `@nanoasm.com` email senders, Resend domain references, OAuth redirect base
- `docker-compose.yml`: `FRONTEND_URL`, `EMAIL_FROM`, `STRIPE_SUCCESS_URL`, `STRIPE_CANCEL_URL`, `STRIPE_PORTAL_RETURN_URL`
- `.env.example` + `STRIPE.md`
- All SDLC docs (`docs/sdlc/`), all ADRs, both copies of legal docs (`Legal docs/` + `frontend/content/legal/`)
- `CLAUDE.md` production deployment section

### Files deliberately untouched
- `backend/migrations/versions/f1a2b3c4d5e6_add_contact_request.py` — migration files are immutable history. The mention of `mailto:contact@nanoasm.com` describes the historical state replaced by the contact form.
- `backend/app/models.py:1145` — same historical narrative in the `ContactRequest` model docstring.

Both references are correctly preserved as historical record. Neither address resolves anymore either way.

### Customer-facing email senders (now)
| Variable | Value |
|---|---|
| `EMAIL_FROM` | `Nano EASM <no-reply@nanoeasm.com>` |
| `MONITOR_EMAIL_FROM` | `Nano EASM Alerts <alerts@nanoeasm.com>` |
| `ADMIN_EMAIL` | `admin@nanoeasm.com` |
| User-facing support address | `support@nanoeasm.com` |

### Stripe URLs (sandbox right now)
| Variable | Value |
|---|---|
| `STRIPE_SUCCESS_URL` | `https://nanoeasm.com/settings/billing?checkout=success` |
| `STRIPE_CANCEL_URL` | `https://nanoeasm.com/settings/billing?checkout=cancel` |
| `STRIPE_PORTAL_RETURN_URL` | `https://nanoeasm.com/settings/billing` |

### API base URL
- Public API documentation lists `https://nanoeasm.com/api` (path-based)
- We do **not** use `api.nanoeasm.com` as a separate subdomain at this stage. If we ever do, it's a separate decision with its own DNS + Nginx work.

---

## 3. DNS — Cloudflare records to set

Assuming Cloudflare is the registrar / DNS provider for both `nanoasm.com` and `nanoeasm.com`. If you registered `nanoeasm.com` somewhere else, point its nameservers to Cloudflare first.

### `nanoeasm.com` (new primary)

| Type | Name | Content | Proxy | TTL |
|---|---|---|---|---|
| A | `nanoeasm.com` | `34.232.100.29` (current Elastic IP) | DNS only (orange cloud OFF until Let's Encrypt validates) | Auto |
| A | `www.nanoeasm.com` | `34.232.100.29` | DNS only initially | Auto |
| MX | `nanoeasm.com` | (Resend / Google Workspace / your provider) | n/a | Auto |
| TXT | `nanoeasm.com` | SPF: `v=spf1 include:resend.com -all` (or your provider) | n/a | Auto |
| TXT | `_dmarc.nanoeasm.com` | `v=DMARC1; p=quarantine; rua=mailto:dmarc@nanoeasm.com` | n/a | Auto |
| TXT | `resend._domainkey.nanoeasm.com` | (DKIM key from Resend dashboard) | n/a | Auto |
| CAA | `nanoeasm.com` | `0 issue "letsencrypt.org"` | n/a | Auto |

**Cert-issuance order:**
1. Create A records with Cloudflare proxy **off** (DNS only).
2. SSH the host. Add `nanoeasm.com` and `www.nanoeasm.com` to certbot:
   ```bash
   sudo certbot --nginx -d nanoeasm.com -d www.nanoeasm.com
   ```
3. Once the cert is issued and Nginx is updated, flip Cloudflare proxy ON if you want CDN/WAF.

### `nanoasm.com` (legacy → 301)

Two clean ways to do this; pick one:

**Option A — Cloudflare Page Rule / Bulk Redirect (recommended, no host changes)**
1. In Cloudflare dashboard, select the `nanoasm.com` zone.
2. Rules → **Redirect Rules** → Create rule:
   - Match: `(http.host eq "nanoasm.com" or http.host eq "www.nanoasm.com")`
   - Action: **Dynamic** redirect to: `concat("https://nanoeasm.com", http.request.uri.path)` (preserves path)
   - Status code: **301**
   - Preserve query string: **on**
3. Wait ~30 s for propagation, then test: `curl -I https://nanoasm.com/faq` should return `HTTP/1.1 301 Moved Permanently` with `Location: https://nanoeasm.com/faq`.

**Option B — Nginx server block on the EC2 host**
Add this to `~/boltedge/nginx/conf.d/nanoasm-redirect.conf`:
```nginx
server {
    listen 80;
    listen 443 ssl http2;
    server_name nanoasm.com www.nanoasm.com;
    ssl_certificate     /etc/letsencrypt/live/nanoasm.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nanoasm.com/privkey.pem;
    return 301 https://nanoeasm.com$request_uri;
}
```
Then reload Nginx. Note this requires keeping the LE cert for `nanoasm.com` alive (certbot renews automatically).

---

## 4. Stripe — sandbox update

Stripe is in **test mode** today (key starts with `sk_test_`). Update test-mode dashboard:

1. **Webhook endpoint**: Stripe Dashboard → Developers → Webhooks
   - Old URL: `https://nanoasm.com/api/billing/stripe-webhook` → **delete or disable**
   - New URL: `https://nanoeasm.com/api/billing/stripe-webhook` → create
   - Events: same set as before (`checkout.session.completed`, `customer.subscription.*`, `invoice.payment_*`)
   - Copy new signing secret → update `STRIPE_WEBHOOK_SECRET` in production `.env`
2. **Customer Portal settings**: Stripe Dashboard → Settings → Customer Portal
   - Update "Default redirect URL" / business links to `nanoeasm.com`
3. **Branding**: Stripe Dashboard → Settings → Branding
   - Update website URL to `https://nanoeasm.com`
   - (Logo/colours unchanged — brand is the same)
4. **Sandbox checkout test**: hit `/billing/upgrade` → Checkout → use test card `4242 4242 4242 4242` → confirm webhook lands on the new URL and the subscription state syncs correctly.

Re-run this whole sequence (with the live Stripe dashboard) when flipping to live mode at launch.

---

## 5. Resend — domain verification redo

Resend's domain authentication is **per-domain**. The old `nanoasm.com` records won't authenticate `nanoeasm.com`.

1. Resend Dashboard → Domains → **Add Domain** → enter `nanoeasm.com`
2. Resend will display SPF, DKIM, and the optional Return-Path (Tracking) records.
3. Add those records to Cloudflare DNS (see §3 above).
4. Wait for Resend to verify (usually < 5 minutes).
5. Send a test email via Resend's dashboard "Send test" feature → confirm it arrives without spam-warning headers.
6. The old `nanoasm.com` Resend domain can stay verified for now — useful while the 301 is in place. Remove it 30+ days after migration when no inbound mail still references the old address.

---

## 6. Google Search Console — new property

1. Go to [Google Search Console](https://search.google.com/search-console).
2. **Add property** → **Domain** → `nanoeasm.com`. (Domain-level property covers `nanoeasm.com`, `www.nanoeasm.com`, and any subdomains you add later.)
3. Verify by adding the TXT record Google provides to Cloudflare DNS.
4. Once verified, submit the sitemap: `https://nanoeasm.com/sitemap.xml`.
5. **Don't delete the `nanoasm.com` property.** Keep it so you can monitor the 301 redirect health and use the **Change of Address** tool:
   - Settings → Change of Address → Select destination property `nanoeasm.com` → confirm.
   - Google will treat this as an authoritative move and transfer ranking signals from the old domain to the new one. This is the SEO-recovery lever; don't skip it.
6. Resubmit the new sitemap on the new property after the 301 is verified.

---

## 7. Bing Webmaster Tools

Same pattern as Google:
1. Add `nanoeasm.com` as a new property.
2. Use the **Site Move** tool (Settings → Site Move) and point from `nanoasm.com` → `nanoeasm.com`.
3. Submit the new sitemap.

---

## 8. OAuth redirect URIs (Google + Microsoft)

Both OAuth providers pin redirect URIs. The new domain has to be registered or signins will fail.

### Google Cloud Console
1. APIs & Services → Credentials → OAuth 2.0 Client IDs → your client.
2. Authorised JavaScript origins: add `https://nanoeasm.com`.
3. Authorised redirect URIs: add `https://nanoeasm.com/api/auth/oauth/google/callback`.
4. Optionally remove the old `nanoasm.com` entries after 30 days of running on the new domain.

### Microsoft Entra (Azure AD)
1. App registrations → your app → Authentication.
2. Redirect URIs: add `https://nanoeasm.com/api/auth/oauth/microsoft/callback`.
3. (Same — keep old, then remove later.)

---

## 9. Other external services to update

Walk through each before announcing the new domain:

- [ ] **Production `.env`** on EC2 host — update every `nanoasm.com` → `nanoeasm.com`. **Restart `easm-backend` and rebuild `easm-frontend` (`--no-cache`)** because `NEXT_PUBLIC_*` build args bake in.
- [ ] **CORS_ORIGINS** env var includes `https://nanoeasm.com` (and optionally still `https://nanoasm.com` for the redirect grace period).
- [ ] **Resend Domain** — verify (above).
- [ ] **Stripe webhook** — re-create on new URL (above).
- [ ] **Stripe branding** — update website (above).
- [ ] **OAuth** — Google + Microsoft redirect URIs (above).
- [ ] **Search Console + Bing** — add new property and use Change of Address tool (above).
- [ ] **Analytics** (if any) — update property URL.
- [ ] **Monitoring / uptime** (UptimeRobot, etc.) — point health checks at `https://nanoeasm.com/api/health`.
- [ ] **GitHub repo description / settings** — update website URL field.
- [ ] **Social profiles** (X / LinkedIn / etc.) — update links.
- [ ] **Email signatures** — internal team templates.

---

## 10. Deploy sequence

Order matters — you don't want users typing `nanoasm.com` and getting a broken page.

1. **Code deploy first** (frontend + backend on the EC2 host) using the new domain in env:
   ```bash
   git pull
   # Update .env to use nanoeasm.com everywhere, then:
   docker compose build --no-cache easm-frontend
   docker compose up -d --build
   ```
2. **DNS for nanoeasm.com** — A records, MX, SPF, DKIM, DMARC, CAA. Confirm with `dig`.
3. **TLS cert** — `certbot --nginx -d nanoeasm.com -d www.nanoeasm.com`.
4. **Smoke-test the new domain** — `curl -I https://nanoeasm.com/`, log in, hit `/api/health`, run a scan.
5. **Set up the 301 from nanoasm.com → nanoeasm.com** (Cloudflare Redirect Rule or Nginx).
6. **Re-verify old domain still serves the redirect** — `curl -I https://nanoasm.com/faq` returns 301 to `https://nanoeasm.com/faq`.
7. **Stripe + OAuth + Resend + Search Console** updates per §4–§7.
8. **Customer comms** — if there are any (no public users yet pre-launch, but team / early access list should be told).

---

## 11. Verification checklist

After all of the above is done:

- [ ] `curl -I https://nanoeasm.com/` returns 200.
- [ ] `curl -I https://nanoasm.com/` returns 301 → `https://nanoeasm.com/`.
- [ ] `curl https://nanoeasm.com/sitemap.xml` lists 13 URLs, all on `nanoeasm.com`.
- [ ] `curl https://nanoeasm.com/robots.txt` references `https://nanoeasm.com/sitemap.xml`.
- [ ] `https://nanoeasm.com/api/health` returns `{"status":"up and running"}`.
- [ ] Login + signup flows work end-to-end on the new domain.
- [ ] Verification email arrives from `no-reply@nanoeasm.com` and the link points at the new domain.
- [ ] Stripe sandbox checkout completes; webhook lands on the new URL; subscription state updates.
- [ ] OG preview at https://www.opengraph.xyz/ shows the new card with `nanoeasm.com` URL pill.
- [ ] Google Rich Results Test on `https://nanoeasm.com/` and `/faq` passes (`Organization`, `SoftwareApplication`, `FAQPage` detected).
- [ ] Search Console accepts the new sitemap.
- [ ] Search Console Change of Address from `nanoasm.com` → `nanoeasm.com` succeeds.

---

## 12. Rollback plan

If anything material breaks during migration:

1. **DNS rollback** — point Cloudflare A records for `nanoeasm.com` to a maintenance page (or remove them) and remove the 301 rule on `nanoasm.com`. This keeps the old domain functional while you investigate.
2. **Code rollback** — `git checkout <prev-sha>` and rebuild containers. The previous commit had `nanoasm.com` as the canonical, so the app continues working on the old domain.
3. **Search Console** — undo the Change of Address (if submitted) before reverting code; otherwise Google starts treating the old domain as the legacy.

Time-bounded: if not resolved within 1 hour, rollback rather than push through.

---

## 13. Why this migration is safe

- **The new domain is the old domain plus a single character.** Every `nanoasm.com` → `nanoeasm.com` substitution is mechanically symmetric across emails, URLs, paths, and attribute names.
- **No backend logic changed.** Auth, scanning, billing, scheduler, and database schema are untouched.
- **No UI layout changed.** The only visible diff is the URL pill in the OG image and the AnimatedDashboard fake URL bar.
- **No customer data migrated.** All Postgres rows reference user emails, not the domain. Nothing in the database needs updating.
- **Email senders changed from-address only.** Existing inboxes still receive — the From header reads `no-reply@nanoeasm.com` instead of `no-reply@nanoasm.com`. Replies route per the new MX records.
- **SEO ranking transferred via 301 + Change of Address.** Google explicitly supports this pattern for domain moves.

---

## 14. Why we kept legacy historical references

Two files mention `contact@nanoasm.com` and were deliberately left as-is:

- `backend/migrations/versions/f1a2b3c4d5e6_add_contact_request.py`
- `backend/app/models.py:1145`

Both describe the *historical state* that was replaced by the in-app contact form. Updating them would falsify the historical record without any benefit — neither address resolves, and the comments are about a thing that no longer exists. Migration files in particular are immutable by convention.

---

## 15. Related documents

- `docs/seo.md` — SEO inventory; URLs in there are already updated to `nanoeasm.com`.
- `docs/sdlc/03-sad/04-deployment-view.md` — production topology, now references `nanoeasm.com`.
- `docs/adr/0007-single-ec2-deployment.md` — DNS choice.
- `docs/adr/0009-resend-for-transactional-email.md` — domain authentication.
- `docs/adr/0010-stripe-as-payment-processor.md` — Stripe URL setup.
- `CLAUDE.md` — operator runbook.

---

*Migration owner: Founder. Last updated: 2026-05-06.*
