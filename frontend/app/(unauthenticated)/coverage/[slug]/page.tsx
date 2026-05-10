// FILE: app/(unauthenticated)/coverage/[slug]/page.tsx
//
// Per-category landing pages — one for each of the five customer
// categories. Each is fully SSG'd via generateStaticParams from the
// content module. Each carries:
//   - WebPage + Article JSON-LD with category-specific keywords
//   - BreadcrumbList JSON-LD (Home → Coverage → {Category})
//   - ~400+ words of unique content (what we detect, why it matters,
//     how it works, common scenarios)
//
// Why dynamic route with one [slug] file rather than five separate
// page.tsx? Single template means a copy/style/SEO change happens
// once, not five times. Content lives in category-content.ts so
// adding a new category later is a one-file change.

import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import {
  ArrowLeft, ArrowRight, Bug, Globe2, KeyRound, AlertTriangle, ShieldCheck,
  Check, Lightbulb, Layers,
} from "lucide-react";

import LandingNav from "../../LandingNav";
import JsonLd from "../../JsonLd";
import { ALL_SLUGS, CATEGORY_CONTENT, type CategorySlug } from "../category-content";

const SITE_URL = "https://nanoeasm.com";

const ICON_FOR_CATEGORY: Record<CategorySlug, any> = {
  "vulnerabilities":  Bug,
  "service-exposure": Globe2,
  "data-leaks":       KeyRound,
  "misconfigurations": AlertTriangle,
  "security-hygiene": ShieldCheck,
};

const ACCENT_FOR_CATEGORY: Record<CategorySlug, { text: string; tint: string; ring: string }> = {
  "vulnerabilities":  { text: "text-red-300",     tint: "bg-red-500/[0.06]",     ring: "border-red-500/20"     },
  "service-exposure": { text: "text-amber-300",   tint: "bg-amber-500/[0.06]",   ring: "border-amber-500/20"   },
  "data-leaks":       { text: "text-fuchsia-300", tint: "bg-fuchsia-500/[0.06]", ring: "border-fuchsia-500/20" },
  "misconfigurations": { text: "text-orange-300", tint: "bg-orange-500/[0.06]",  ring: "border-orange-500/20"  },
  "security-hygiene": { text: "text-teal-300",    tint: "bg-teal-500/[0.06]",    ring: "border-teal-500/20"    },
};


export const dynamic = "force-static";

export function generateStaticParams() {
  return ALL_SLUGS.map((slug) => ({ slug }));
}


type Params = { slug: string };

export async function generateMetadata({ params }: { params: Promise<Params> }): Promise<Metadata> {
  const { slug } = await params;
  const content = CATEGORY_CONTENT[slug as CategorySlug];
  if (!content) return {};
  const url = `${SITE_URL}/coverage/${slug}`;
  return {
    title: content.pageTitle,
    description: content.metaDescription,
    alternates: { canonical: `/coverage/${slug}` },
    openGraph: {
      title: content.pageTitle,
      description: content.metaDescription,
      url,
      type: "article",
      siteName: "Nano EASM",
      locale: "en_AU",
    },
    twitter: {
      card: "summary_large_image",
      title: content.pageTitle,
      description: content.metaDescription,
    },
    keywords: content.keywords.join(", "),
  };
}


export default async function CategoryPage({ params }: { params: Promise<Params> }) {
  const { slug } = await params;
  const content = CATEGORY_CONTENT[slug as CategorySlug];
  if (!content) notFound();

  const Icon = ICON_FOR_CATEGORY[content.slug];
  const accent = ACCENT_FOR_CATEGORY[content.slug];
  const url = `${SITE_URL}/coverage/${content.slug}`;

  const PAGE_JSONLD = {
    "@context": "https://schema.org",
    "@type": "WebPage",
    name: content.pageTitle,
    description: content.metaDescription,
    url,
    inLanguage: "en-AU",
    isPartOf: { "@type": "WebSite", name: "Nano EASM", url: SITE_URL },
    about: {
      "@type": "SoftwareApplication",
      name: "Nano EASM",
      applicationCategory: "SecurityApplication",
      applicationSubCategory: "External Attack Surface Management",
      url: SITE_URL,
    },
    keywords: content.keywords.join(", "),
  };

  const BREADCRUMB_JSONLD = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: [
      { "@type": "ListItem", position: 1, name: "Home", item: `${SITE_URL}/` },
      { "@type": "ListItem", position: 2, name: "Coverage", item: `${SITE_URL}/coverage` },
      { "@type": "ListItem", position: 3, name: content.label, item: url },
    ],
  };

  return (
    <>
      <JsonLd data={[PAGE_JSONLD, BREADCRUMB_JSONLD]} />
      <LandingNav />

      <main className="pt-24 pb-20">
        <div className="mx-auto max-w-3xl px-4 sm:px-6">
          {/* Breadcrumb */}
          <nav className="flex items-center gap-1.5 text-xs text-white/55 mb-6">
            <Link href="/" className="hover:text-white transition-colors">Home</Link>
            <span className="text-white/20">/</span>
            <Link href="/coverage" className="hover:text-white transition-colors">Coverage</Link>
            <span className="text-white/20">/</span>
            <span className="text-white/70">{content.label}</span>
          </nav>

          <Link
            href="/coverage"
            className="inline-flex items-center gap-1.5 text-sm text-white/50 hover:text-white transition-colors mb-8"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to coverage
          </Link>

          {/* Hero */}
          <div className="flex items-center gap-3 mb-4">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${accent.tint} border ${accent.ring}`}>
              <Icon className={`w-5 h-5 ${accent.text}`} />
            </div>
            <span className={`text-xs font-semibold uppercase tracking-wider ${accent.text}`}>
              {content.label}
            </span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight leading-tight">
            {content.headline}
          </h1>
          <p className="mt-4 text-lg text-white/60 leading-relaxed">{content.intro}</p>

          {/* What we detect */}
          <h2 className="mt-12 text-2xl font-semibold tracking-tight flex items-center gap-2">
            <Layers className={`w-5 h-5 ${accent.text}`} />
            What we detect
          </h2>
          <ul className="mt-4 space-y-2.5">
            {content.whatWeDetect.map((item) => (
              <li key={item} className="flex items-start gap-2.5 text-white/65 leading-relaxed">
                <Check className={`w-4 h-4 ${accent.text} shrink-0 mt-1`} />
                <span>{item}</span>
              </li>
            ))}
          </ul>

          {/* Why it matters */}
          <h2 className="mt-12 text-2xl font-semibold tracking-tight">Why it matters</h2>
          <p className="mt-3 text-white/65 leading-relaxed">{content.whyItMatters}</p>

          {/* How it works */}
          <h2 className="mt-12 text-2xl font-semibold tracking-tight">How Nano EASM detects it</h2>
          <p className="mt-3 text-white/65 leading-relaxed">{content.howItWorks}</p>

          {/* Scenarios */}
          <h2 className="mt-12 text-2xl font-semibold tracking-tight flex items-center gap-2">
            <Lightbulb className={`w-5 h-5 ${accent.text}`} />
            Common scenarios
          </h2>
          <div className="mt-5 space-y-4">
            {content.scenarios.map((s) => (
              <div
                key={s.title}
                className={`rounded-xl border ${accent.ring} ${accent.tint} p-5`}
              >
                <h3 className={`text-sm font-semibold ${accent.text} mb-2`}>{s.title}</h3>
                <p className="text-sm text-white/60 leading-relaxed">{s.body}</p>
              </div>
            ))}
          </div>

          {/* CTA */}
          <div className="mt-16 rounded-xl border border-teal-500/20 bg-teal-500/[0.04] p-7 text-center">
            <h3 className="text-lg font-semibold text-white">Try it free against your domain</h3>
            <p className="text-white/55 text-sm mt-2 max-w-xl mx-auto leading-relaxed">
              Quick Scan runs the engines that surface {content.label.toLowerCase()}{" "}
              findings, plus the rest of the platform's coverage. No signup, no
              credit card, real results in under a minute.
            </p>
            <div className="flex items-center justify-center gap-3 mt-5 flex-wrap">
              <Link
                href="/quick-scan"
                className="inline-flex items-center gap-1.5 rounded-lg bg-teal-600 px-5 py-2.5 text-sm font-medium text-white hover:bg-teal-500 transition-colors"
              >
                Try Quick Scan
                <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                href="/register"
                className="inline-flex items-center rounded-lg border border-white/20 bg-white/[0.04] px-5 py-2.5 text-sm font-medium text-white/80 hover:text-white hover:bg-white/[0.08] transition-colors"
              >
                Get started free
              </Link>
            </div>
          </div>

          {/* Cross-links to other categories — internal linking */}
          <div className="mt-16">
            <h3 className="text-xs font-semibold uppercase tracking-widest text-white/55 mb-4">
              Other coverage categories
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {ALL_SLUGS.filter((s) => s !== content.slug).map((s) => {
                const other = CATEGORY_CONTENT[s];
                const OtherIcon = ICON_FOR_CATEGORY[s];
                const otherAccent = ACCENT_FOR_CATEGORY[s];
                return (
                  <Link
                    key={s}
                    href={`/coverage/${s}`}
                    className="group flex items-center gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] hover:border-white/15 hover:bg-white/[0.04] p-3 transition-colors"
                  >
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${otherAccent.tint} border ${otherAccent.ring} shrink-0`}>
                      <OtherIcon className={`w-4 h-4 ${otherAccent.text}`} />
                    </div>
                    <span className="text-sm text-white/80 group-hover:text-white">
                      {other.label}
                    </span>
                    <ArrowRight className="w-3.5 h-3.5 text-white/30 group-hover:text-white/60 ml-auto" />
                  </Link>
                );
              })}
            </div>
          </div>
        </div>
      </main>
    </>
  );
}
