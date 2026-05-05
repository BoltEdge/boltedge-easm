# ADR 0005 — JWT in Authorization Header, Not HttpOnly Cookies

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-05-05 |
| Deciders | Founder / sole engineer |
| Supersedes | – |
| Superseded by | – |

## Context

Web app authentication needs to:
1. Identify the user on every API request.
2. Survive page reloads.
3. Be revocable.
4. Resist common attacks (XSS, CSRF, token theft).

The session-credential storage choice is the load-bearing decision. There are two mainstream models:

- **Cookie-based:** server sets a session cookie (typically `HttpOnly`, `Secure`, `SameSite=Lax/Strict`). Browser auto-attaches it on every same-origin request. CSRF tokens compensate for the auto-attach behaviour on state-changing requests.
- **Token-in-header:** server returns a JWT (or opaque token), client stores it (memory, sessionStorage, localStorage, IndexedDB). Client manually attaches it via `Authorization: Bearer <jwt>`. No CSRF concern (no auto-attach), but the token is reachable by JavaScript.

The trade-off is well-known: cookies are stronger against XSS (script can't read `HttpOnly`), tokens are stronger against CSRF (no auto-attach). Most production posture: cookies + CSRF tokens for first-party browser apps; bearer tokens for APIs and SPAs.

Nano EASM has both surfaces:
- A first-party browser app (Next.js).
- A documented public API for programmatic clients, authenticated via API keys (`ag_sk_*`) over `Authorization: Bearer`.

## Decision

We authenticate **all clients** — browser and programmatic — via `Authorization: Bearer <token>`.

- Browser: token is a JWT issued at login, stored in `localStorage` and shadowed in memory. Frontend's `app/lib/api.ts` attaches it on every API call.
- Programmatic: token is an API key `ag_sk_<rest>`, attached the same way.
- We do **not** use cookies for authentication.
- Lifetime is short (30 minutes) with a sliding inactivity-window refresh.

## Considered alternatives

| Alternative | Why rejected |
|---|---|
| **HttpOnly cookie + CSRF token** | Stronger XSS posture, but introduces CSRF as a class of bug we have to defend against on every state-changing endpoint. Asymmetric with our public API surface (which already uses Bearer for API keys). Two auth shapes for one backend = bugs. |
| **Cookie for browser, Bearer for API keys** | Forces dual auth paths in every middleware, decorator, and test. We tried this in spirit early on; symmetric is simpler. |
| **Refresh token + short-lived access token** | Useful when access tokens are very short (minutes) and refresh tokens are long-lived. We accept short sessions with no refresh: 30-min absolute, sliding within. Users who are active stay logged in; idle users re-auth. No refresh-token rotation infrastructure to build. |
| **Server-side sessions (opaque token)** | Requires session storage. Postgres-backed sessions work fine, but we'd lose the stateless property of JWT. Trade-off only makes sense if we need server-side revocation (which is a known gap; see below). |
| **OAuth provider (Auth0, Clerk, Supabase Auth)** | Adds a vendor. We do this ourselves because the auth surface is small and well-understood. Reconsider if MFA enrolment, SSO, or social login become a focus. |

## Consequences

**Positive:**
- **Symmetric auth:** browser and programmatic clients use the same `Authorization` header. Same parsing, same logging, same rate limiting.
- **No CSRF surface.** A malicious site cannot induce the browser to attach our credential, because the browser does not auto-attach `Authorization` headers. CSRF tokens, double-submit cookies, `SameSite` correctness — none of these become bugs we must defend against.
- **Easy cross-origin** for any future subdomain split or API consumer. CORS is the only knob.
- **Stateless backend** for auth verification. JWT signature check is local; no session table read on every request.

**Negative:**
- **XSS posture matters more.** A successful XSS reads the JWT directly. We mitigate with: framework-level output escaping (React's default), strong CSP, no `dangerouslySetInnerHTML` on user data, and short token lifetime (window of stolen-token validity is bounded).
- **No native server-side revocation.** A stolen token is valid until expiry. Today's "revoke everyone" mechanism is rotating `SECRET_KEY` (invalidates all tokens). Per-user revocation requires a `jti` denylist (Redis-backed) which is **a known gap** flagged in `00-positioning-pivot-tasks.md` §10.2.
- **Token in `localStorage` survives tab close.** This is a deliberate UX choice — users expect "remember me" by default. The trade is: a short-lived stolen token vs. logging the user out every tab close.
- **Cannot use cookie-only browser features** (cookie partitioning, FedCM-style flows). Not in our roadmap.

## Notes

The implicit assumption is that **our XSS posture is and will remain strong**. If we ever load third-party scripts that have access to the page, or relax CSP, the calculus flips. The auth model would not change — we'd add a `jti` denylist and shorten lifetime — but the operational discipline around content security would tighten.

If we eventually need same-origin cookie auth (e.g. for a download endpoint that can't carry headers cleanly), we add it as a *secondary* path scoped to that one feature, not as a replacement for the primary Bearer flow.

## References

- ADR 0001 — record decisions
- §06 Security Architecture §3, §4 — JWT specifics, password storage
- §06 Security Architecture §11 — CORS / CSRF posture
- `00-positioning-pivot-tasks.md` §10.2 — JWT revocation gap

---
