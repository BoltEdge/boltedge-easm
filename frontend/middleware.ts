// frontend/middleware.ts
//
// Adds X-Robots-Tag: noindex, nofollow to every response from
// authenticated, admin, auth-flow, and anonymous-compute routes.
//
// This is belt-and-braces alongside robots.ts (which uses Disallow):
// - robots.txt is advisory and only respected by polite crawlers.
// - X-Robots-Tag is an HTTP-header-level directive that Google,
//   Bing, and most others honour even when they bypass robots.txt
//   (e.g., when discovering URLs through links from external sites).
//
// We intentionally do NOT noindex the public marketing/legal/api-docs
// pages — those should rank.

import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const NOINDEX_PREFIXES = [
  "/dashboard",
  "/assets",
  "/groups",
  "/scan",
  "/discovery",
  "/findings",
  "/monitoring",
  "/reports",
  "/trending",
  "/tools",
  "/settings",
  "/admin",
  "/api/",
  "/login",
  "/register",
  "/forgot-password",
  "/reset-password",
  "/verify-email",
  "/complete-profile",
  "/invite",
  "/oauth",
  "/quick-scan",
];

function shouldNoIndex(pathname: string): boolean {
  return NOINDEX_PREFIXES.some(
    (p) => pathname === p || pathname.startsWith(`${p}/`),
  );
}

export function middleware(req: NextRequest) {
  const res = NextResponse.next();
  if (shouldNoIndex(req.nextUrl.pathname)) {
    res.headers.set("X-Robots-Tag", "noindex, nofollow");
  }
  return res;
}

export const config = {
  // Match everything except static / image / favicon / OG / robots /
  // sitemap so we don't waste edge cycles on static assets.
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|favicon.png|favicon-64.png|opengraph-image|robots.txt|sitemap.xml).*)",
  ],
};
