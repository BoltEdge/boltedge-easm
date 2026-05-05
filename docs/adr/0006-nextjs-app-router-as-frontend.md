# ADR 0006 — Next.js 16 App Router as the Frontend Framework

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-05-05 |
| Deciders | Founder / sole engineer |
| Supersedes | – |
| Superseded by | – |

## Context

Nano EASM has:
- A public marketing surface (landing page, pricing, public tools, quick-scan).
- An authenticated SPA-style application (dashboard, assets, scans, findings, monitoring, reports, settings).
- A platform admin console at `/admin/*` (superadmin only).

Requirements:
- SEO-friendly public pages (server rendering for landing, blog, public tools).
- Snappy SPA navigation for the authenticated app.
- TypeScript first.
- Component composition / styling that scales to ~50+ pages.
- Reasonable default for forms, error boundaries, loading states.

## Decision

We use **Next.js 16 with the App Router**, TypeScript, and Tailwind CSS.

- **Route groups** separate auth contexts: `(unauthenticated)/` for public, `(authenticated)/` for logged-in, with `admin/` nested inside authenticated.
- Pages are React Server Components by default; client components opt in with `"use client"`.
- All API calls go through a single client at `app/lib/api.ts`.
- Tailwind is the only styling system. No CSS modules, no styled-components.
- Production builds use Next.js standalone output for Docker.

## Considered alternatives

| Alternative | Why rejected |
|---|---|
| **Pages Router (Next.js)** | Older surface area; App Router is now the recommended path for new apps. Server Components + nested layouts are a meaningful win for our route-group structure. |
| **Vite + React + React Router** | Pure SPA; we'd reinvent SSR for the marketing pages. The "two apps" friction (marketing site + app) is the classic reason teams adopt Next.js in the first place. |
| **Remix** | Comparable framework, smaller ecosystem, slightly different mental model around loaders. Next.js's broader docs / community is the deciding factor at one-engineer scale. |
| **SvelteKit** | Excellent framework, but the team lives in React. Cost of context-switching for an unrelated technology is too high. |
| **Two separate apps (marketing on Astro, app on Vite/React)** | Genuine simplification for the marketing side, but the duplicated component / styling / branding is a tax we're not paying yet. Reconsider if the marketing site grows to a content-heavy CMS. |

## Consequences

**Positive:**
- **One codebase covers public + app + admin.** Shared components, shared styling, shared API client.
- **Server Components reduce client-side JS** for read-heavy pages (asset list, finding list). Default-server with explicit client opt-in is the right ergonomic for our shape.
- **Route groups give us auth-context separation** without nested layouts gymnastics. The `(authenticated)/` layout enforces redirects to `/login`; `admin/` adds the superadmin guard on top.
- **TypeScript end-to-end.** API response shapes are typed; the API client at `app/lib/api.ts` is the single point of contact.
- **Tailwind is fast to write and easy to review** — a class soup is easier to scan than scattered CSS modules.

**Negative:**
- **`NEXT_PUBLIC_*` env vars are baked in at build time.** Changing one requires `docker compose build --no-cache`. This has bitten us — the deploy procedure documents it (§04 Deployment §2).
- **App Router is newer; some patterns are still settling.** We've hit "which lifecycle does this run in" friction a few times. Acceptable cost.
- **Next.js opinions creep.** Image optimisation, font loading, middleware — using these well is a small learning curve per feature. Worth it for the win on the public pages.
- **Build times are longer** than a Vite SPA. We accept it; CI runs in a few minutes regardless.
- **Server Components require careful auth handling.** Calling backend APIs from a Server Component requires the JWT to be reachable server-side; we currently render auth-gated pages as Client Components and hit the API from the browser. Consistent and simple. We may revisit if SSR-with-auth becomes important for performance.

## Notes

The "everything is React" axiom applies here. We do not use mini-frameworks (HTMX, Stimulus, vanilla JS islands) for any sub-section; mixing paradigms in a small team multiplies cognitive load.

## References

- §01 Logical View §3 — frontend module map
- §03 Development View §3 — frontend code organisation
- §04 Deployment View §2 — frontend container build / `NEXT_PUBLIC_*` build-time gotcha

---
