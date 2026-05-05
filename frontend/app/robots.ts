// app/robots.ts
// Next.js App Router convention — auto-served at /robots.txt.
// Allows crawling of public marketing/legal/api-docs pages, blocks
// every authenticated app surface and admin console.

import type { MetadataRoute } from "next";

const SITE_URL = "https://nanoasm.com";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        disallow: [
          // Authenticated app
          "/dashboard",
          "/assets",
          "/groups",
          "/scan",
          "/scan/",
          "/discovery",
          "/findings",
          "/monitoring",
          "/reports",
          "/trending",
          "/tools",
          "/settings",
          "/oauth/",
          // Admin console
          "/admin",
          "/admin/",
          // Auth flow / API surface
          "/api/",
          "/login",
          "/login/",
          "/register",
          "/forgot-password",
          "/reset-password",
          "/reset-password/",
          "/verify-email",
          "/complete-profile",
          "/invite",
          // Anonymous compute surfaces — keep out of search
          "/quick-scan",
        ],
      },
    ],
    sitemap: `${SITE_URL}/sitemap.xml`,
  };
}
