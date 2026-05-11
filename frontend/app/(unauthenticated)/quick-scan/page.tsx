// app/(unauthenticated)/quick-scan/page.tsx
// Public Quick Scan page — hosts the QuickScanCard form standalone with
// a hero, an explainer of what's included vs what a free account adds,
// and a final sign-up CTA. Linked from the landing nav, footer, and
// every coverage page CTA.
import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, Check, X } from "lucide-react";

import LandingNav from "../LandingNav";
import LandingFooter from "../LandingFooter";
import JsonLd from "../JsonLd";
import QuickScanCard from "../QuickScanCard";

const SITE_URL = "https://nanoeasm.com";
const PAGE_TITLE = "Quick Scan — Nano EASM";
const PAGE_DESCRIPTION =
  "Free public scan of any domain or IP. See what's reachable from the internet, what services are running, and what's worth investigating — no signup, no card.";

export const metadata: Metadata = {
  title: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  alternates: { canonical: "/quick-scan" },
  openGraph: {
    title: PAGE_TITLE,
    description: PAGE_DESCRIPTION,
    url: `${SITE_URL}/quick-scan`,
    type: "website",
    siteName: "Nano EASM",
    locale: "en_AU",
  },
  twitter: {
    card: "summary_large_image",
    title: PAGE_TITLE,
    description: PAGE_DESCRIPTION,
  },
};

const PAGE_JSONLD = {
  "@context": "https://schema.org",
  "@type": "WebPage",
  name: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  url: `${SITE_URL}/quick-scan`,
  inLanguage: "en-AU",
  isPartOf: { "@type": "WebSite", name: "Nano EASM", url: SITE_URL },
  about: {
    "@type": "SoftwareApplication",
    name: "Nano EASM",
    applicationCategory: "SecurityApplication",
    applicationSubCategory: "External Attack Surface Management",
    url: SITE_URL,
  },
};

const BREADCRUMB_JSONLD = {
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  itemListElement: [
    { "@type": "ListItem", position: 1, name: "Home", item: `${SITE_URL}/` },
    { "@type": "ListItem", position: 2, name: "Quick Scan", item: `${SITE_URL}/quick-scan` },
  ],
};

export default function QuickScanPage() {
  return (
    <div className="min-h-screen bg-[#060b18] text-white overflow-x-hidden">
      <JsonLd data={[PAGE_JSONLD, BREADCRUMB_JSONLD]} />
      <LandingNav />
      <div className="h-16" /> {/* spacer for fixed navbar */}

      <main>
        {/* ================= HERO ================= */}
        <section className="relative">
          <div className="absolute inset-0 overflow-hidden pointer-events-none">
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-gradient-to-b from-teal-500/[0.07] via-cyan-500/[0.04] to-transparent rounded-full blur-3xl" />
          </div>
          <div className="relative mx-auto max-w-3xl px-4 sm:px-6 pt-12 sm:pt-16 pb-8 text-center">
            <div className="inline-flex items-center gap-2 rounded-full border border-teal-500/20 bg-teal-500/[0.06] px-4 py-1.5 mb-6">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-teal-400 opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-teal-400" />
              </span>
              <span className="text-xs font-medium text-teal-400/70 tracking-wide">Free quick scan</span>
            </div>
            <h1 className="text-3xl sm:text-5xl font-bold leading-[1.1] tracking-tight">
              See what&apos;s exposed<br />
              <span className="bg-gradient-to-r from-teal-400/80 via-cyan-400/70 to-teal-500/80 bg-clip-text text-transparent">
                in under a minute.
              </span>
            </h1>
            <p className="mt-5 text-base sm:text-lg text-white/70 leading-7 max-w-2xl mx-auto">
              Enter a domain or IP. We&apos;ll show you what&apos;s reachable from the public
              internet, what services are running, and what&apos;s worth investigating —
              no signup, no card.
            </p>
          </div>
        </section>

        {/* ================= SCAN CARD ================= */}
        <section className="py-6 sm:py-8">
          <div className="mx-auto max-w-3xl px-4 sm:px-6">
            <QuickScanCard />
          </div>
        </section>

        {/* ================= WHAT'S COVERED + UPGRADE (merged) ================= */}
        <section className="py-12 sm:py-16">
          <div className="mx-auto max-w-5xl px-4 sm:px-6">
            <div className="text-center mb-10">
              <span className="text-xs font-semibold text-teal-400 uppercase tracking-widest">What&apos;s covered</span>
              <h2 className="mt-3 text-2xl sm:text-3xl font-bold tracking-tight">
                A snapshot, not a full audit.
              </h2>
              <p className="mt-3 text-sm text-white/60 max-w-xl mx-auto leading-relaxed">
                Quick Scan is intentionally lightweight — accurate enough to read the
                room, fast enough to fit in a coffee break. Free accounts unlock the
                rest.
              </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
              {/* Included */}
              <div className="lg:col-span-2 rounded-xl border border-teal-500/20 bg-teal-500/[0.04] p-5">
                <h3 className="text-sm font-semibold text-teal-300 mb-3 flex items-center gap-2">
                  <Check className="w-4 h-4" />
                  Included in Quick Scan
                </h3>
                <ul className="space-y-2 text-sm text-white/70 leading-relaxed">
                  <li>Open ports + services across up to 5 IPs</li>
                  <li>Notable CVEs flagged on detected services</li>
                  <li>Top finding explained in plain English</li>
                  <li>No signup, no card, no follow-up email</li>
                </ul>
              </div>

              {/* Upgrade CTA — replaces the standalone "Want more?" band */}
              <div className="lg:col-span-3 relative overflow-hidden rounded-xl border border-white/[0.08] bg-gradient-to-br from-[#0d1a2e] to-[#0a1121] p-5">
                <div className="absolute inset-0 pointer-events-none">
                  <div className="absolute top-0 right-0 w-[300px] h-[200px] bg-teal-500/[0.06] rounded-full blur-3xl" />
                </div>
                <div className="relative">
                  <h3 className="text-sm font-semibold text-white/80 mb-3 flex items-center gap-2">
                    <X className="w-4 h-4 text-white/50" />
                    Free account adds
                  </h3>
                  <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2 text-sm text-white/65 leading-relaxed mb-5">
                    <li className="flex items-start gap-1.5"><span className="text-teal-400/60 mt-0.5">+</span>Continuous monitoring &amp; alerts</li>
                    <li className="flex items-start gap-1.5"><span className="text-teal-400/60 mt-0.5">+</span>GitHub &amp; GitLab leak detection</li>
                    <li className="flex items-start gap-1.5"><span className="text-teal-400/60 mt-0.5">+</span>Subdomain &amp; shadow-asset discovery</li>
                    <li className="flex items-start gap-1.5"><span className="text-teal-400/60 mt-0.5">+</span>Saved results, scheduled scans, reports</li>
                  </ul>
                  <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
                    <Link
                      href="/register"
                      className="group inline-flex items-center justify-center gap-2 rounded-lg bg-teal-600 px-5 py-2.5 text-sm font-semibold text-white shadow-md shadow-teal-900/30 hover:bg-teal-500 transition-all"
                    >
                      Create free account
                      <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                    </Link>
                    <Link
                      href="/coverage"
                      className="inline-flex items-center justify-center gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-5 py-2.5 text-sm font-medium text-white/65 hover:text-white hover:bg-white/[0.06] transition-all"
                    >
                      See full coverage
                    </Link>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>

      <LandingFooter />
    </div>
  );
}
