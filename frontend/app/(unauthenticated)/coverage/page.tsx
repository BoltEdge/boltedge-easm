// FILE: app/(unauthenticated)/coverage/page.tsx
// Public Coverage page — single source of truth for what Nano EASM
// detects. Reads coverage.json (auto-generated from the backend
// FindingTemplate registry by `python backend/scripts/generate_catalogue.py`)
// at build time, so the data is always in sync with the live registry
// and the page is fully SSR'd for SEO.

import type { Metadata } from "next";
import Link from "next/link";
import {
  ArrowLeft, Bug, Globe2, KeyRound, AlertTriangle, ShieldCheck,
} from "lucide-react";
import LandingNav from "../LandingNav";
import JsonLd from "../JsonLd";
import CoverageCategoryDetails from "./CoverageCategoryDetails";
// Auto-generated — do not edit by hand. Regenerate with:
//   python backend/scripts/generate_catalogue.py
import coverageData from "../../../data/coverage.json";

const SITE_URL = "https://nanoeasm.com";

export const dynamic = "force-static";

const PAGE_TITLE = "What Nano EASM Detects — Coverage & Templates";
const PAGE_DESCRIPTION =
  `${coverageData.totalTemplates}+ finding templates across vulnerabilities, ` +
  "service exposure, data leaks, misconfigurations, and security hygiene — " +
  "every alert Nano EASM can raise on your external attack surface.";

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

const SEVERITY_PILL: Record<string, string> = {
  critical: "bg-red-500/10 text-red-300 border-red-500/20",
  high:     "bg-orange-500/10 text-orange-300 border-orange-500/20",
  medium:   "bg-amber-500/10 text-amber-300 border-amber-500/20",
  low:      "bg-sky-500/10 text-sky-300 border-sky-500/20",
  info:     "bg-white/[0.06] text-white/40 border-white/10",
};

// JSON-LD lets Google understand the page as a structured catalogue.
const COVERAGE_JSONLD = {
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
  })),
};

export default function CoveragePage() {
  return (
    <>
      <JsonLd data={COVERAGE_JSONLD} />
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
              Every alert the platform can raise, grouped into five categories
              you can toggle independently. {coverageData.totalTemplates}{" "}
              templates and counting — derived from real engagements,
              not aspirational marketing.
            </p>
            <p className="mt-2 text-xs text-white/30">
              Last updated {coverageData.generatedOn} · single source of truth in our finding registry.
            </p>
          </div>

          {/* Category overview cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-16">
            {coverageData.categories.map((cat) => {
              const visuals = CATEGORY_VISUALS[cat.id] ?? CATEGORY_VISUALS.security_hygiene;
              const Icon = visuals.icon;
              return (
                <a
                  key={cat.id}
                  href={`#${cat.id}`}
                  className={`group rounded-xl border ${visuals.ring} ${visuals.tint} p-5 transition-all hover:bg-white/[0.04] hover:border-white/20`}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${visuals.tint} border ${visuals.ring}`}>
                      <Icon className={`w-4 h-4 ${visuals.accent}`} />
                    </div>
                    <span className="text-2xl font-bold text-white/80 tabular-nums">
                      {cat.totalCount}
                    </span>
                  </div>
                  <h3 className={`text-sm font-semibold ${visuals.accent} mb-1`}>{cat.label}</h3>
                  <p className="text-xs text-white/50 leading-relaxed line-clamp-3">{cat.blurb}</p>
                  <div className="flex items-center gap-1.5 mt-3 flex-wrap">
                    {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
                      const n = (cat.severityCounts as Record<string, number>)[sev] ?? 0;
                      if (n === 0) return null;
                      return (
                        <span
                          key={sev}
                          className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold border ${SEVERITY_PILL[sev]}`}
                        >
                          {n} {sev}
                        </span>
                      );
                    })}
                  </div>
                </a>
              );
            })}
          </div>

          {/* Per-category details */}
          <div className="space-y-12">
            {coverageData.categories.map((cat) => {
              const visuals = CATEGORY_VISUALS[cat.id] ?? CATEGORY_VISUALS.security_hygiene;
              const Icon = visuals.icon;
              return (
                <section key={cat.id} id={cat.id} className="scroll-mt-24">
                  <div className="flex items-center gap-3 mb-3">
                    <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${visuals.tint} border ${visuals.ring}`}>
                      <Icon className={`w-5 h-5 ${visuals.accent}`} />
                    </div>
                    <div>
                      <h2 className={`text-2xl font-bold ${visuals.accent}`}>{cat.label}</h2>
                      <p className="text-xs text-white/40">{cat.totalCount} templates</p>
                    </div>
                  </div>
                  <p className="text-white/60 text-sm leading-relaxed mb-6 max-w-3xl">{cat.blurb}</p>

                  <CoverageCategoryDetails
                    templates={cat.templates}
                    severityPill={SEVERITY_PILL}
                  />
                </section>
              );
            })}
          </div>

          {/* CTA */}
          <div className="mt-20 rounded-xl border border-teal-500/20 bg-teal-500/[0.04] p-8 text-center">
            <h3 className="text-lg font-semibold text-white">Run a free quick scan</h3>
            <p className="text-white/50 text-sm mt-2 max-w-xl mx-auto">
              Enter a domain, get a real result in under a minute — no signup, no credit card.
              See exactly which templates fired against your asset.
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
