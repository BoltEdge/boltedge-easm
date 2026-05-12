// FILE: app/(unauthenticated)/resources/blog/page.tsx
//
// Blog index — card grid of all articles, with a featured top slot,
// category filter chips, and a simple search input. Server-rendered;
// the filter / search use a tiny client-side companion since we want
// fast keystroke feedback and the article list is small.

import type { Metadata } from "next";
import Link from "next/link";
import { ArrowLeft, ArrowRight, BookOpen, Rss } from "lucide-react";

import LandingNav from "../../LandingNav";
import LandingFooter from "../../LandingFooter";
import JsonLd from "../../JsonLd";

import {
  getAllArticles,
  CATEGORIES,
  CATEGORY_BADGE,
  categoryLabel,
  formatPublishDate,
} from "./_lib";
import BlogIndexClient from "./BlogIndexClient";

const SITE_URL = "https://nanoeasm.com";
const PAGE_URL = `${SITE_URL}/resources/blog`;

export const dynamic = "force-static";

export const metadata: Metadata = {
  title: "Blog — Attack Surface Management & Security Insights",
  description:
    "Articles on External Attack Surface Management, vulnerability discovery, exposure monitoring, and modern cybersecurity practice for IT teams and MSSPs.",
  alternates: { canonical: "/resources/blog" },
  openGraph: {
    title: "Nano EASM Blog — ASM, EASM & Security Insights",
    description:
      "Articles on External Attack Surface Management, vulnerability discovery, exposure monitoring, and modern cybersecurity practice.",
    url: PAGE_URL,
    type: "website",
    siteName: "Nano EASM",
    locale: "en_AU",
  },
  twitter: {
    card: "summary_large_image",
    title: "Nano EASM Blog",
    description: "Articles on ASM, EASM, and modern security practice.",
  },
};

export default function BlogIndexPage() {
  const articles = getAllArticles();
  const featured = articles.find((a) => a.featured) ?? articles[0];
  const rest = articles.filter((a) => a.slug !== featured?.slug);

  const blogJsonLd = {
    "@context": "https://schema.org",
    "@type": "Blog",
    name: "Nano EASM Blog",
    url: PAGE_URL,
    description: metadata.description,
    publisher: {
      "@type": "Organization",
      name: "Nano EASM",
      url: SITE_URL,
      logo: {
        "@type": "ImageObject",
        url: `${SITE_URL}/logo-on-dark.svg`,
      },
    },
    blogPost: articles.map((a) => ({
      "@type": "BlogPosting",
      headline: a.title,
      url: `${SITE_URL}/resources/blog/${a.slug}`,
      datePublished: a.publishDate,
      author: { "@type": "Organization", name: a.author },
    })),
  };

  return (
    <div className="min-h-screen bg-[#060b18] text-white overflow-x-hidden">
      <JsonLd data={blogJsonLd} />
      <LandingNav />
      <div className="h-16" /> {/* spacer for fixed navbar */}

      <main className="mx-auto max-w-6xl px-4 sm:px-6 pt-12 pb-20">
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-sm text-white/50 hover:text-white transition-colors mb-8"
        >
          <ArrowLeft className="w-4 h-4" />Back to home
        </Link>

        {/* Header */}
        <div className="mb-10 flex items-start justify-between gap-6 flex-wrap">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-teal-500/20 bg-teal-500/[0.06] px-3 py-1 mb-4">
              <BookOpen className="w-3 h-3 text-teal-400" />
              <span className="text-[11px] font-medium text-teal-400/75 uppercase tracking-wider">Blog</span>
            </div>
            <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">Security insights & ASM fundamentals</h1>
            <p className="mt-3 text-base text-white/55 leading-relaxed max-w-2xl">
              Articles on Attack Surface Management, vulnerability discovery, exposure monitoring,
              and how modern security teams stay ahead of an ever-expanding attack surface.
            </p>
          </div>
          <a
            href="/resources/blog/rss.xml"
            className="inline-flex items-center gap-1.5 text-xs text-white/50 hover:text-white px-3 py-2 rounded-lg border border-white/[0.08] bg-white/[0.02] hover:bg-white/[0.05] transition-colors"
            title="Subscribe to the RSS feed"
          >
            <Rss className="w-3 h-3" />RSS
          </a>
        </div>

        {/* Featured article — only shown when articles exist. */}
        {featured && (
          <Link
            href={`/resources/blog/${featured.slug}`}
            className="group block rounded-2xl border border-teal-500/20 bg-gradient-to-br from-teal-500/[0.06] via-[#060b18] to-[#060b18] p-6 sm:p-8 mb-10 hover:border-teal-500/40 transition-colors"
          >
            <div className="flex items-start gap-3 flex-wrap mb-4">
              <span className="text-[10px] font-semibold text-teal-400/80 uppercase tracking-widest">Featured</span>
              <span className="text-white/15">·</span>
              <span className={`inline-flex items-center px-2 py-0.5 rounded-md border text-[10px] font-semibold ${CATEGORY_BADGE[featured.category]}`}>
                {categoryLabel(featured.category)}
              </span>
              <span className="text-white/15">·</span>
              <span className="text-[11px] text-white/50">{formatPublishDate(featured.publishDate)}</span>
              <span className="text-white/15">·</span>
              <span className="text-[11px] text-white/50">{featured.computedReadTime} min read</span>
            </div>
            <h2 className="text-2xl sm:text-3xl font-bold text-foreground leading-tight group-hover:text-teal-300 transition-colors">
              {featured.title}
            </h2>
            <p className="mt-3 text-base text-white/65 leading-relaxed max-w-3xl">
              {featured.description}
            </p>
            <div className="mt-5 inline-flex items-center gap-1.5 text-sm text-teal-400 group-hover:text-teal-300">
              Read the article <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
            </div>
          </Link>
        )}

        {/* Empty state — first launch, no articles yet. */}
        {articles.length === 0 && (
          <div className="text-center py-20 border border-dashed border-white/10 rounded-xl">
            <BookOpen className="w-12 h-12 text-white/15 mx-auto mb-4" />
            <p className="text-white/50">No articles yet. Check back soon.</p>
          </div>
        )}

        {/* Client-side filter / search over the remaining articles */}
        {rest.length > 0 && (
          <BlogIndexClient articles={rest} categories={CATEGORIES} />
        )}
      </main>

      <LandingFooter />
    </div>
  );
}
