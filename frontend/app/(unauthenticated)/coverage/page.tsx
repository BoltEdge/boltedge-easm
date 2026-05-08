// FILE: app/(unauthenticated)/coverage/page.tsx
// Public Coverage page — describes the five categories of alert that
// Nano EASM can raise. We deliberately do NOT publish individual
// template names or the total template count on this page: that's
// detection IP and lives behind the root-admin-only template browser.
// This page reads only the high-level category metadata baked into
// coverage.json.

import type { Metadata } from "next";
import Link from "next/link";
import {
  ArrowLeft, Bug, Globe2, KeyRound, AlertTriangle, ShieldCheck,
} from "lucide-react";
import LandingNav from "../LandingNav";
import JsonLd from "../JsonLd";
// Auto-generated — do not edit by hand. Regenerate with:
//   python backend/scripts/generate_catalogue.py
import coverageData from "../../../data/coverage.json";

const SITE_URL = "https://nanoeasm.com";

export const dynamic = "force-static";

const PAGE_TITLE = "What Nano EASM Detects — Coverage";
const PAGE_DESCRIPTION =
  "Five categories of external-exposure alert: vulnerabilities, service " +
  "exposure, data leaks, misconfigurations, and security hygiene.";

export const metadata: Metadata = {
  title: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  alternates: { canonical: "/coverage" },
  openGraph: {
    title: PAGE_TITLE,
    description: PAGE_DESCRIPTION,
    url: `${SITE_URL}/coverage`,
    type: "article",
    siteName: "Nano EASM",
    locale: "en_AU",
  },
  twitter: {
    card: "summary_large_image",
    title: PAGE_TITLE,
    description: PAGE_DESCRIPTION,
  },
  keywords: [
    "external attack surface management coverage",
    "EASM detection capabilities",
    "vulnerability detection",
    "service exposure detection",
    "data leak detection",
    "credential leak detection",
    "misconfiguration scanning",
    "security hygiene checks",
    "DMARC SPF DKIM scanner",
    "SSL certificate monitoring",
    "CVE scanning",
    "cloud bucket exposure",
    "GitHub leak detection",
    "Nano EASM templates",
  ].join(", "),
};

// Icon and accent colour per category. Keys must match the `id` field
// in coverage.json. If the backend adds a new customer category, add
// it here too — the page falls back to a neutral icon if missing.
const CATEGORY_VISUALS: Record<
  string,
  { icon: any; accent: string; tint: string; ring: string }
> = {
  vulnerabilities: {
    icon: Bug,
    accent: "text-red-300",
    tint: "bg-red-500/[0.04]",
    ring: "border-red-500/20",
  },
  service_exposure: {
    icon: Globe2,
    accent: "text-amber-300",
    tint: "bg-amber-500/[0.04]",
    ring: "border-amber-500/20",
  },
  data_leaks: {
    icon: KeyRound,
    accent: "text-fuchsia-300",
    tint: "bg-fuchsia-500/[0.04]",
    ring: "border-fuchsia-500/20",
  },
  misconfigurations: {
    icon: AlertTriangle,
    accent: "text-orange-300",
    tint: "bg-orange-500/[0.04]",
    ring: "border-orange-500/20",
  },
  security_hygiene: {
    icon: ShieldCheck,
    accent: "text-teal-300",
    tint: "bg-teal-500/[0.04]",
    ring: "border-teal-500/20",
  },
};

// JSON-LD — three pieces:
//   1. WebPage    binds the page to the site, names the SoftwareApplication
//      it's about, and carries the keyword surface for the categories.
//   2. ItemList   the five categories themselves, in order.
//   3. Breadcrumb home → coverage trail.
// Three separate objects (not one nested) so each surface validates
// independently with Google's Rich Results Test.
const COVERAGE_KEYWORDS = [
  "EASM coverage",
  "external attack surface coverage",
  "vulnerability detection",
  "service exposure detection",
  "data leak detection",
  "credential leak monitoring",
  "misconfiguration detection",
  "DMARC SPF scanner",
  "SSL certificate monitoring",
  "subdomain takeover detection",
];

const COVERAGE_PAGE_JSONLD = {
  "@context": "https://schema.org",
  "@type": "WebPage",
  name: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  url: `${SITE_URL}/coverage`,
  inLanguage: "en-AU",
  isPartOf: {
    "@type": "WebSite",
    name: "Nano EASM",
    url: SITE_URL,
  },
  about: {
    "@type": "SoftwareApplication",
    name: "Nano EASM",
    applicationCategory: "SecurityApplication",
    applicationSubCategory: "External Attack Surface Management",
    url: SITE_URL,
  },
  keywords: COVERAGE_KEYWORDS.join(", "),
};

const COVERAGE_LIST_JSONLD = {
  "@context": "https://schema.org",
  "@type": "ItemList",
  name: "Nano EASM coverage — finding categories",
  description: PAGE_DESCRIPTION,
  numberOfItems: coverageData.categories.length,
  itemListElement: coverageData.categories.map((cat, idx) => ({
    "@type": "ListItem",
    position: idx + 1,
    name: cat.label,
    description: cat.blurb,
    url: `${SITE_URL}/coverage/${cat.id.replace(/_/g, "-")}`,
  })),
};

const COVERAGE_BREADCRUMB_JSONLD = {
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  itemListElement: [
    { "@type": "ListItem", position: 1, name: "Home", item: `${SITE_URL}/` },
    { "@type": "ListItem", position: 2, name: "Coverage", item: `${SITE_URL}/coverage` },
  ],
};

export default function CoveragePage() {
  return (
    <>
      <JsonLd data={[COVERAGE_PAGE_JSONLD, COVERAGE_LIST_JSONLD, COVERAGE_BREADCRUMB_JSONLD]} />
      <LandingNav />

      <main className="pt-24 pb-20">
        <div className="mx-auto max-w-5xl px-4 sm:px-6">
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 text-sm text-white/50 hover:text-white transition-colors mb-8"
          >
            <ArrowLeft className="w-4 h-4" />Back to home
          </Link>

          {/* Hero */}
          <div className="mb-12">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-teal-500/10 border border-teal-500/20 text-teal-300 text-xs font-semibold uppercase tracking-wider mb-4">
              <span className="w-1.5 h-1.5 rounded-full bg-teal-400" />
              Coverage
            </div>
            <h1 className="text-3xl sm:text-5xl font-bold tracking-tight leading-tight">
              What Nano EASM <span className="text-teal-400">detects</span>
            </h1>
            <p className="mt-4 text-white/60 text-base sm:text-lg max-w-2xl leading-relaxed">
              Every alert the platform can raise falls into one of five
              categories you can toggle independently for your organisation
              — or per asset group.
            </p>
          </div>

          {/* Category overview cards. Each card is a link to the
              dedicated /coverage/{slug} sub-page — internal linking
              from the index page boosts the sub-page rankings. */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {coverageData.categories.map((cat) => {
              const visuals = CATEGORY_VISUALS[cat.id] ?? CATEGORY_VISUALS.security_hygiene;
              const Icon = visuals.icon;
              const slug = cat.id.replace(/_/g, "-");
              return (
                <Link
                  key={cat.id}
                  href={`/coverage/${slug}`}
                  className={`group rounded-xl border ${visuals.ring} ${visuals.tint} p-6 transition-all hover:bg-white/[0.04]`}
                >
                  <div className={`w-11 h-11 rounded-lg flex items-center justify-center ${visuals.tint} border ${visuals.ring} mb-4`}>
                    <Icon className={`w-5 h-5 ${visuals.accent}`} />
                  </div>
                  <h3 className={`text-base font-semibold ${visuals.accent} mb-2`}>{cat.label}</h3>
                  <p className="text-sm text-white/55 leading-relaxed">{cat.blurb}</p>
                  <div className={`mt-4 text-xs font-medium ${visuals.accent} opacity-60 group-hover:opacity-100 transition-opacity`}>
                    Learn more →
                  </div>
                </Link>
              );
            })}
          </div>

          {/* CTA */}
          <div className="mt-16 rounded-xl border border-teal-500/20 bg-teal-500/[0.04] p-8 text-center">
            <h3 className="text-lg font-semibold text-white">Run a free quick scan</h3>
            <p className="text-white/50 text-sm mt-2 max-w-xl mx-auto">
              Enter a domain, get a real result in under a minute — no signup,
              no credit card.
            </p>
            <div className="flex items-center justify-center gap-3 mt-5">
              <Link
                href="/quick-scan"
                className="inline-flex items-center gap-1.5 rounded-lg bg-teal-600 px-5 py-2.5 text-sm font-medium text-white hover:bg-teal-500 transition-colors"
              >
                Try Quick Scan →
              </Link>
              <Link
                href="/register"
                className="inline-flex items-center rounded-lg border border-white/20 bg-white/[0.04] px-5 py-2.5 text-sm font-medium text-white/80 hover:text-white hover:bg-white/[0.08] transition-colors"
              >
                Get started free
              </Link>
            </div>
          </div>
        </div>
      </main>
    </>
  );
}
