// FILE: app/(unauthenticated)/resources/blog/[slug]/page.tsx
//
// Article template — renders one markdown file from /content/articles/.
// Mirrors the styling pattern used by /terms-and-policies/[slug]:
// fixed-width prose column on the left, sticky info sidecar on the right
// with article metadata + related-article links + a back-to-Nano-EASM
// CTA.

import type { Metadata } from "next";
import Link from "next/link";
import { ArrowLeft, ArrowRight, Clock, Calendar, User, Tag, Rss, Compass } from "lucide-react";
import { marked } from "marked";
import { notFound } from "next/navigation";

import LandingNav from "../../../LandingNav";
import LandingFooter from "../../../LandingFooter";
import JsonLd from "../../../JsonLd";

import {
  getAllArticles,
  getArticleBySlug,
  getRelatedArticles,
  CATEGORIES,
  CATEGORY_BADGE,
  categoryLabel,
  formatPublishDate,
} from "../_lib";

const SITE_URL = "https://nanoeasm.com";

export const dynamic = "force-static";

export function generateStaticParams() {
  return getAllArticles().map((a) => ({ slug: a.slug }));
}

export async function generateMetadata(
  { params }: { params: Promise<{ slug: string }> },
): Promise<Metadata> {
  const { slug } = await params;
  const article = getArticleBySlug(slug);
  if (!article) return {};
  const url = `${SITE_URL}/resources/blog/${article.slug}`;
  const ogImage = article.ogImage
    ? (article.ogImage.startsWith("http") ? article.ogImage : `${SITE_URL}${article.ogImage}`)
    : `${SITE_URL}/opengraph-image.png`;
  return {
    title: article.title,
    description: article.description,
    alternates: { canonical: `/resources/blog/${article.slug}` },
    openGraph: {
      title: article.title,
      description: article.description,
      url,
      type: "article",
      siteName: "Nano EASM",
      locale: "en_AU",
      publishedTime: article.publishDate,
      authors: [article.author],
      tags: article.tags,
      images: [{ url: ogImage }],
    },
    twitter: {
      card: "summary_large_image",
      title: article.title,
      description: article.description,
      images: [ogImage],
    },
  };
}

export default async function ArticlePage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const article = getArticleBySlug(slug);
  if (!article) notFound();

  marked.setOptions({ gfm: true, breaks: false });
  const html = await marked.parse(article.body);
  const related = getRelatedArticles(article, 3);
  const url = `${SITE_URL}/resources/blog/${article.slug}`;

  const articleJsonLd = {
    "@context": "https://schema.org",
    "@type": "BlogPosting",
    headline: article.title,
    description: article.description,
    url,
    mainEntityOfPage: url,
    datePublished: article.publishDate,
    dateModified: article.publishDate,
    inLanguage: "en-AU",
    author: { "@type": "Organization", name: article.author, url: SITE_URL },
    publisher: {
      "@type": "Organization",
      name: "Nano EASM",
      url: SITE_URL,
      logo: { "@type": "ImageObject", url: `${SITE_URL}/logo-on-dark.svg` },
    },
    keywords: (article.tags ?? []).join(", "),
    articleSection: categoryLabel(article.category),
  };

  const breadcrumbJsonLd = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: [
      { "@type": "ListItem", position: 1, name: "Home", item: `${SITE_URL}/` },
      { "@type": "ListItem", position: 2, name: "Blog", item: `${SITE_URL}/resources/blog` },
      { "@type": "ListItem", position: 3, name: article.title, item: url },
    ],
  };

  return (
    <div className="min-h-screen bg-[#060b18] text-white overflow-x-hidden">
      <JsonLd data={[articleJsonLd, breadcrumbJsonLd]} />
      <LandingNav />
      <div className="h-16" /> {/* spacer for fixed navbar */}

      <main className="mx-auto max-w-6xl px-4 sm:px-6 pt-10 pb-20">
        <Link
          href="/resources/blog"
          className="inline-flex items-center gap-1.5 text-sm text-white/55 hover:text-white transition-colors mb-8"
        >
          <ArrowLeft className="w-4 h-4" />Back to blog
        </Link>

        <div className="grid grid-cols-1 lg:grid-cols-[1fr_240px] gap-10">
          {/* Article body */}
          <div className="min-w-0 max-w-3xl">
            {/* Title + metadata header */}
            <div className="mb-8">
              <div className="flex items-center gap-2 flex-wrap mb-4">
                <span className={`inline-flex items-center px-2 py-0.5 rounded-md border text-[10px] font-semibold ${CATEGORY_BADGE[article.category]}`}>
                  {categoryLabel(article.category)}
                </span>
                <span className="text-white/15">·</span>
                <span className="text-[11px] text-white/50 inline-flex items-center gap-1">
                  <Calendar className="w-3 h-3" />{formatPublishDate(article.publishDate)}
                </span>
                <span className="text-white/15">·</span>
                <span className="text-[11px] text-white/50 inline-flex items-center gap-1">
                  <Clock className="w-3 h-3" />{article.computedReadTime} min read
                </span>
              </div>

              <h1 className="text-3xl sm:text-4xl font-bold tracking-tight leading-[1.15]">
                {article.title}
              </h1>

              <p className="mt-4 text-lg text-white/65 leading-relaxed">
                {article.description}
              </p>

              <div className="mt-6 flex items-center gap-2 text-xs text-white/45">
                <User className="w-3 h-3" />
                <span>
                  By <span className="text-white/70">{article.author}</span>
                  {article.authorTitle && <span className="text-white/40"> · {article.authorTitle}</span>}
                </span>
              </div>
            </div>

            {/* Hero image — only when one is set; otherwise the title block carries the visual weight. */}
            {article.heroImage && (
              <div className="mb-8 rounded-2xl overflow-hidden border border-white/[0.08] bg-white/[0.02]">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={article.heroImage}
                  alt=""
                  className="w-full h-auto block"
                />
              </div>
            )}

            <article
              className="article-doc text-[16px] leading-relaxed text-white/75"
              dangerouslySetInnerHTML={{ __html: html }}
            />

            {/* Tags */}
            {article.tags && article.tags.length > 0 && (
              <div className="mt-10 pt-6 border-t border-white/[0.06]">
                <div className="flex items-center gap-2 flex-wrap">
                  <Tag className="w-3 h-3 text-white/30" />
                  {article.tags.map((t) => (
                    <span
                      key={t}
                      className="inline-flex items-center px-2 py-0.5 rounded-md border border-white/[0.08] bg-white/[0.02] text-[11px] text-white/55"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Bottom CTA — the editorial-to-product handoff */}
            <div className="mt-10 rounded-2xl border border-teal-500/20 bg-gradient-to-br from-teal-500/[0.06] via-[#060b18] to-[#060b18] p-6 sm:p-8">
              <h3 className="text-xl font-bold text-foreground">See your attack surface in 60 seconds</h3>
              <p className="mt-2 text-sm text-white/60 leading-relaxed max-w-xl">
                Run a free scan against your own domain — no signup, no card, no demo call. Find out what an attacker on the internet sees about your organisation.
              </p>
              <div className="mt-5 flex flex-col sm:flex-row gap-3">
                <Link
                  href="/quick-scan"
                  className="inline-flex items-center justify-center gap-2 rounded-lg bg-teal-600 px-5 py-2.5 text-sm font-semibold text-white shadow-md shadow-teal-900/30 hover:bg-teal-500 transition-all"
                >
                  Run a free scan <ArrowRight className="w-4 h-4" />
                </Link>
                <Link
                  href="/register"
                  className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-5 py-2.5 text-sm font-medium text-white/70 hover:text-white hover:bg-white/[0.06] transition-all"
                >
                  Create free account
                </Link>
              </div>
            </div>
          </div>

          {/* Sidecar — has two modes:
              · with related articles → show them up top
              · alone (first article in the blog) → fill with "What we cover"
                so the column doesn't read as empty space. */}
          <aside className="hidden lg:block">
            <div className="sticky top-24 space-y-5">
              {/* Related articles — by category first, falling back to recent. */}
              {related.length > 0 ? (
                <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
                  <div className="text-[11px] uppercase tracking-wider text-white/45 font-semibold mb-3">
                    Related articles
                  </div>
                  <div className="space-y-3">
                    {related.map((r) => (
                      <Link
                        key={r.slug}
                        href={`/resources/blog/${r.slug}`}
                        className="block group"
                      >
                        <div className="text-xs text-white/40 mb-0.5">
                          {categoryLabel(r.category)} · {r.computedReadTime} min
                        </div>
                        <div className="text-sm text-foreground group-hover:text-teal-300 transition-colors leading-snug">
                          {r.title}
                        </div>
                      </Link>
                    ))}
                  </div>
                </div>
              ) : (
                // First-article fallback — show the topic taxonomy so the
                // reader knows what's coming. Disappears the moment a
                // related article exists.
                <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Compass className="w-3.5 h-3.5 text-teal-400" />
                    <div className="text-[11px] uppercase tracking-wider text-white/45 font-semibold">
                      What we cover
                    </div>
                  </div>
                  <div className="space-y-2.5">
                    {CATEGORIES.map((cat) => (
                      <div key={cat.id}>
                        <div className="text-sm text-white/85 font-medium">{cat.label}</div>
                        <div className="text-[11px] text-white/45 leading-relaxed">{cat.description}</div>
                      </div>
                    ))}
                  </div>
                  <Link
                    href="/resources/blog"
                    className="inline-flex items-center gap-1 mt-4 text-xs font-medium text-teal-400 hover:text-teal-300"
                  >
                    Browse the blog <ArrowRight className="w-3 h-3" />
                  </Link>
                </div>
              )}

              {/* Subscribe card — RSS now, room to add email later. */}
              <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Rss className="w-3.5 h-3.5 text-amber-400" />
                  <div className="text-sm font-medium text-white">Subscribe</div>
                </div>
                <p className="text-xs text-white/55 leading-relaxed mb-3">
                  Get new articles in your feed reader the moment they publish.
                </p>
                <a
                  href="/resources/blog/rss.xml"
                  className="inline-flex items-center gap-1 text-xs font-medium text-teal-400 hover:text-teal-300"
                >
                  RSS feed <ArrowRight className="w-3 h-3" />
                </a>
              </div>

              {/* Product cross-link — closes the editorial loop. */}
              <div className="rounded-xl border border-teal-500/20 bg-teal-500/[0.04] p-4">
                <div className="text-sm font-medium text-white mb-1.5">About Nano EASM</div>
                <p className="text-xs text-white/60 leading-relaxed mb-3">
                  External Attack Surface Management for IT teams and MSSPs. Continuous discovery, scanning, and exposure monitoring.
                </p>
                <Link
                  href="/resources/what-is-nano-easm"
                  className="inline-flex items-center gap-1 text-xs font-medium text-teal-400 hover:text-teal-300"
                >
                  What is Nano EASM? <ArrowRight className="w-3 h-3" />
                </Link>
              </div>
            </div>
          </aside>
        </div>
      </main>

      <LandingFooter />
    </div>
  );
}
