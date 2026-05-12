// FILE: app/(unauthenticated)/resources/blog/rss.xml/route.ts
//
// RSS 2.0 feed for the blog. Lets readers / syndicators (Feedly,
// readers, security newsletters) subscribe without writing a scraper.
// Server-rendered as a static route — no client/runtime cost.

import { getAllArticles } from "../_lib";

const SITE_URL = "https://nanoeasm.com";

export const dynamic = "force-static";

function xmlEscape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

export async function GET() {
  const articles = getAllArticles();
  const updated = articles[0]?.publishDate
    ? new Date(articles[0].publishDate).toUTCString()
    : new Date().toUTCString();

  const items = articles
    .map((a) => {
      const url = `${SITE_URL}/resources/blog/${a.slug}`;
      const pubDate = new Date(a.publishDate).toUTCString();
      return `    <item>
      <title>${xmlEscape(a.title)}</title>
      <link>${url}</link>
      <guid isPermaLink="true">${url}</guid>
      <pubDate>${pubDate}</pubDate>
      <description>${xmlEscape(a.description)}</description>
      <category>${xmlEscape(a.category)}</category>
      <author>noreply@nanoeasm.com (${xmlEscape(a.author)})</author>
    </item>`;
    })
    .join("\n");

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>Nano EASM Blog</title>
    <link>${SITE_URL}/resources/blog</link>
    <description>Articles on Attack Surface Management, vulnerability discovery, exposure monitoring, and modern cybersecurity practice for IT teams and MSSPs.</description>
    <language>en-AU</language>
    <lastBuildDate>${updated}</lastBuildDate>
    <atom:link href="${SITE_URL}/resources/blog/rss.xml" rel="self" type="application/rss+xml" />
${items}
  </channel>
</rss>`;

  return new Response(xml, {
    headers: {
      "Content-Type": "application/rss+xml; charset=utf-8",
      "Cache-Control": "public, max-age=3600",
    },
  });
}
