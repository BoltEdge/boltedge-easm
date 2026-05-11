// FILE: app/(unauthenticated)/terms-and-policies/[slug]/page.tsx
//
// Renders any of the eight legal documents from frontend/content/legal/
// as a styled, server-rendered page. Markdown is parsed at build time
// (the docs are static) so there's no runtime markdown cost.
//
// Source-of-truth lives in /Legal docs/ at the project root and is
// duplicated into frontend/content/legal/ so it's inside the Docker
// build context.

import type { Metadata } from "next";
import fs from "fs";
import path from "path";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { marked } from "marked";

import LandingNav from "../../LandingNav";
import LandingFooter from "../../LandingFooter";
import JsonLd from "../../JsonLd";

const SITE_URL = "https://nanoeasm.com";

export const dynamic = "force-static";

const DOCS: Record<string, { title: string; file: string }> = {
  "terms-of-use": { title: "Terms of Use", file: "terms-of-use.md" },
  "privacy-policy": { title: "Privacy Policy", file: "privacy-policy.md" },
  "acceptable-use-policy": { title: "Acceptable Use Policy", file: "acceptable-use-policy.md" },
  "refund-cancellation-policy": { title: "Refund & Cancellation Policy", file: "refund-cancellation-policy.md" },
  "security-scanning-authorisation": { title: "Security & Scanning Authorisation", file: "security-scanning-authorisation.md" },
  "liability-limitation": { title: "Liability Limitation", file: "liability-limitation.md" },
  "subscription-payment-terms": { title: "Subscription & Payment Terms", file: "subscription-payment-terms.md" },
  "data-handling-retention": { title: "Data Handling & Retention", file: "data-handling-retention.md" },
};

export function generateStaticParams() {
  return Object.keys(DOCS).map((slug) => ({ slug }));
}

export async function generateMetadata(
  { params }: { params: Promise<{ slug: string }> },
): Promise<Metadata> {
  const { slug } = await params;
  const meta = DOCS[slug];
  if (!meta) return {};
  const url = `${SITE_URL}/terms-and-policies/${slug}`;
  return {
    title: meta.title,
    description: `${meta.title} — part of the Nano EASM Terms and Policies. Review your rights, obligations, and how Nano EASM handles your data and your scans.`,
    alternates: { canonical: `/terms-and-policies/${slug}` },
    openGraph: {
      title: `${meta.title} | Nano EASM`,
      description: `${meta.title} — part of the Nano EASM Terms and Policies.`,
      url,
      type: "article",
      siteName: "Nano EASM",
      locale: "en_AU",
    },
    twitter: {
      card: "summary_large_image",
      title: `${meta.title} | Nano EASM`,
      description: `${meta.title} — part of the Nano EASM Terms and Policies.`,
    },
  };
}

export default async function LegalDocPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug: rawSlug } = await params;
  // Accept "/terms-and-policies/foo.md" as a courtesy — strip the
  // extension and resolve to the same page. Avoids 404s when someone
  // deep-links with the file extension still attached.
  const slug = rawSlug.replace(/\.md$/i, "");
  const meta = DOCS[slug];
  if (!meta) notFound();

  const filePath = path.join(process.cwd(), "content", "legal", meta.file);
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf-8");
  } catch {
    notFound();
  }

  // Strip the duplicate H1 from the markdown — we render our own
  // styled title in the page header below.
  const stripped = raw!.replace(/^#\s+.+\n/, "").trim();

  // Extract the "Last updated: <date>" line from the top of every doc
  // so we can render it as a styled chip near the title rather than
  // letting it sit as inline body text. Falls back to null if absent.
  const lastUpdatedMatch = stripped.match(/^\*\*Last updated:\*\*\s+(.+)$/m);
  const lastUpdated = lastUpdatedMatch ? lastUpdatedMatch[1].trim() : null;
  const dateStripped = stripped
    .replace(/^\*\*Last updated:\*\*\s+.+\n+/m, "")
    .replace(/^---\s*\n/m, "") // drop the leading separator if it's now the first line
    .trim();

  // Rewrite cross-doc relative links: `./privacy-policy.md` and
  // `./privacy-policy.md#anchor` become absolute URLs so they
  // navigate to the correct page (no `.md` 404s).
  const linksFixed = dateStripped.replace(
    /\]\(\.\/([a-z0-9-]+)\.md(#[^)]+)?\)/gi,
    "](/terms-and-policies/$1$2)",
  );

  marked.setOptions({ gfm: true, breaks: false });
  const html = await marked.parse(linksFixed);

  const url = `${SITE_URL}/terms-and-policies/${slug}`;

  const articleJsonLd = {
    "@context": "https://schema.org",
    "@type": "Article",
    headline: meta.title,
    description: `${meta.title} — part of the Nano EASM Terms and Policies.`,
    url,
    mainEntityOfPage: url,
    inLanguage: "en-AU",
    author: { "@type": "Organization", name: "Nano EASM", url: SITE_URL },
    publisher: {
      "@type": "Organization",
      name: "Nano EASM",
      url: SITE_URL,
      logo: {
        "@type": "ImageObject",
        url: `${SITE_URL}/logo-on-dark.svg`,
      },
    },
  };

  const breadcrumbJsonLd = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: [
      {
        "@type": "ListItem",
        position: 1,
        name: "Home",
        item: `${SITE_URL}/`,
      },
      {
        "@type": "ListItem",
        position: 2,
        name: "Terms and Policies",
        item: `${SITE_URL}/terms-and-policies`,
      },
      {
        "@type": "ListItem",
        position: 3,
        name: meta.title,
        item: url,
      },
    ],
  };

  return (
    <>
      <JsonLd data={[articleJsonLd, breadcrumbJsonLd]} />
      <LandingNav />

      <main className="pt-24 pb-20">
        <div className="mx-auto max-w-6xl px-4 sm:px-6">
          <Link
            href="/terms-and-policies"
            className="inline-flex items-center gap-1.5 text-sm text-white/65 hover:text-white transition-colors mb-8"
          >
            <ArrowLeft className="w-4 h-4" />Back to Terms &amp; Policies
          </Link>

          <div className="grid grid-cols-1 lg:grid-cols-[1fr_240px] gap-10">
            {/* ── Article (constrained for readability) ── */}
            <div className="min-w-0 max-w-3xl">
              <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">{meta.title}</h1>

              {lastUpdated && (
                <div className="mt-3 inline-flex items-center gap-1.5 rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1 text-[11px] text-white/65">
                  Last updated <span className="text-white/85 font-medium">{lastUpdated}</span>
                </div>
              )}

              <article
                className="legal-doc mt-8 text-[15px] leading-relaxed text-white/70"
                dangerouslySetInnerHTML={{ __html: html }}
              />
            </div>

            {/* ── Sticky sidebar: related policies + support ── */}
            <aside className="hidden lg:block">
              <div className="sticky top-24 space-y-5">
                <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
                  <div className="text-[11px] uppercase tracking-wider text-white/45 font-semibold mb-3">
                    Other policies
                  </div>
                  <nav className="space-y-0.5 text-sm">
                    {Object.entries(DOCS).map(([s, d]) => {
                      const active = s === slug;
                      return (
                        <Link
                          key={s}
                          href={`/terms-and-policies/${s}`}
                          aria-current={active ? "page" : undefined}
                          className={`block py-1.5 px-2 rounded transition-colors ${
                            active
                              ? "text-teal-300 bg-teal-500/[0.08] border-l-2 border-teal-500/40 -ml-[2px] pl-[10px]"
                              : "text-white/65 hover:text-white hover:bg-white/[0.04]"
                          }`}
                        >
                          {d.title}
                        </Link>
                      );
                    })}
                  </nav>
                </div>

                <div className="rounded-xl border border-teal-500/20 bg-teal-500/[0.04] p-4">
                  <div className="text-sm font-medium text-white mb-1.5">Something unclear?</div>
                  <p className="text-xs text-white/60 leading-relaxed mb-3">
                    Reach out and a human will get back to you — we keep these short on purpose.
                  </p>
                  <Link
                    href="/#contact"
                    className="inline-flex items-center gap-1.5 text-xs font-medium text-teal-400 hover:text-teal-300"
                  >
                    Contact support →
                  </Link>
                </div>
              </div>
            </aside>
          </div>
        </div>
      </main>

      <LandingFooter />
    </>
  );
}
