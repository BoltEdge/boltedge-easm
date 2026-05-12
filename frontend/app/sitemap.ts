// app/sitemap.ts
// Next.js App Router convention — auto-served at /sitemap.xml.
// Lists ONLY public, indexable pages. Authenticated app routes
// (dashboard / assets / scans / settings / etc.) are excluded by
// robots.ts disallow rules and are not listed here.

import type { MetadataRoute } from "next";
import fs from "node:fs";
import path from "node:path";

import { getAllArticles } from "./(unauthenticated)/resources/blog/_lib";

const SITE_URL = "https://nanoeasm.com";

// Slugs that exist as markdown files in /content/legal/. Listed
// explicitly so we can attach lastmod from the file's mtime.
const LEGAL_SLUGS = [
  "terms-of-use",
  "privacy-policy",
  "acceptable-use-policy",
  "security-scanning-authorisation",
  "subscription-payment-terms",
  "refund-cancellation-policy",
  "liability-limitation",
  "data-handling-retention",
];

function legalLastMod(slug: string): Date {
  // Prefer the file mtime so re-publishing a policy bumps lastmod.
  // Falls back to "now" if the file isn't found at build time.
  try {
    const file = path.join(
      process.cwd(),
      "content",
      "legal",
      `${slug}.md`,
    );
    return fs.statSync(file).mtime;
  } catch {
    return new Date();
  }
}

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date();

  return [
    {
      url: `${SITE_URL}/`,
      lastModified: now,
      changeFrequency: "weekly",
      priority: 1.0,
    },
    {
      url: `${SITE_URL}/faq`,
      lastModified: now,
      changeFrequency: "monthly",
      priority: 0.8,
    },
    {
      url: `${SITE_URL}/coverage`,
      lastModified: now,
      changeFrequency: "weekly",
      priority: 0.9,
    },
    // Five per-category sub-pages — each carries its own
    // category-specific keyword surface and 400+ words of unique
    // content. See app/(unauthenticated)/coverage/category-content.ts.
    ...[
      "vulnerabilities",
      "service-exposure",
      "data-leaks",
      "misconfigurations",
      "security-hygiene",
    ].map((slug) => ({
      url: `${SITE_URL}/coverage/${slug}`,
      lastModified: now,
      changeFrequency: "weekly" as const,
      priority: 0.85,
    })),
    {
      url: `${SITE_URL}/api-docs`,
      lastModified: now,
      changeFrequency: "monthly",
      priority: 0.8,
    },
    {
      url: `${SITE_URL}/resources/what-is-nano-easm`,
      lastModified: now,
      changeFrequency: "monthly",
      priority: 0.8,
    },
    {
      url: `${SITE_URL}/terms-and-policies`,
      lastModified: now,
      changeFrequency: "monthly",
      priority: 0.5,
    },
    ...LEGAL_SLUGS.map((slug) => ({
      url: `${SITE_URL}/terms-and-policies/${slug}`,
      lastModified: legalLastMod(slug),
      changeFrequency: "yearly" as const,
      priority: 0.3,
    })),
    // Blog index + every published article. Articles use their
    // publishDate as lastmod — sufficient for the static-publish model.
    {
      url: `${SITE_URL}/resources/blog`,
      lastModified: now,
      changeFrequency: "weekly" as const,
      priority: 0.85,
    },
    ...getAllArticles().map((a) => ({
      url: `${SITE_URL}/resources/blog/${a.slug}`,
      lastModified: new Date(a.publishDate),
      changeFrequency: "monthly" as const,
      priority: 0.7,
    })),
  ];
}
