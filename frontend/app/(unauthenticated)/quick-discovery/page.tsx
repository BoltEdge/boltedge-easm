// app/(unauthenticated)/quick-discovery/page.tsx
// Public Quick Discovery page — hosts the QuickDiscoveryCard standalone with
// a hero, an explainer of free vs registered enumeration, and a sign-up CTA.
import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, Check, X } from "lucide-react";

import LandingNav from "../LandingNav";
import LandingFooter from "../LandingFooter";
import JsonLd from "../JsonLd";
import QuickDiscoveryCard from "../QuickDiscoveryCard";

const SITE_URL = "https://nanoeasm.com";
const PAGE_TITLE = "Free Subdomain Finder & Asset Discovery — Nano EASM";
const PAGE_DESCRIPTION =
  "Find subdomains, IPs, and shadow assets exposed against any domain. CT log discovery and DNS resolution, no signup, no card.";

export const metadata: Metadata = {
  title: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  alternates: { canonical: "/quick-discovery" },
  openGraph: {
    title: PAGE_TITLE,
    description: PAGE_DESCRIPTION,
    url: `${SITE_URL}/quick-discovery`,
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
  url: `${SITE_URL}/quick-discovery`,
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
    { "@type": "ListItem", position: 2, name: "Quick Discovery", item: `${SITE_URL}/quick-discovery` },
  ],
};

export default function QuickDiscoveryPage() {
  return (
    <div className="min-h-screen bg-[#060b18] text-white overflow-x-hidden">
      <JsonLd data={[PAGE_JSONLD, BREADCRUMB_JSONLD]} />
      <LandingNav />
      <div className="h-16" /> {/* spacer for fixed navbar */}

      <main>
        {/* ================= HERO ================= */}
        <section className="relative">
          <div className="absolute inset-0 overflow-hidden pointer-events-none">
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-gradient-to-b from-cyan-500/[0.07] via-teal-500/[0.04] to-transparent rounded-full blur-3xl" />
          </div>
          <div className="relative mx-auto max-w-3xl px-4 sm:px-6 pt-12 sm:pt-16 pb-8 text-center">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/[0.06] px-4 py-1.5 mb-6">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-400 opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-cyan-400" />
              </span>
              <span className="text-xs font-medium text-cyan-400/70 tracking-wide">Free quick discovery</span>
            </div>
            <h1 className="text-3xl sm:text-5xl font-bold leading-[1.1] tracking-tight">
              Find every subdomain<br />
              <span className="bg-gradient-to-r from-cyan-400/80 via-teal-400/70 to-cyan-500/80 bg-clip-text text-transparent">
                you forgot you owned.
              </span>
            </h1>
            <p className="mt-5 text-base sm:text-lg text-white/70 leading-7 max-w-2xl mx-auto">
              Enter a domain. We&apos;ll pull subdomains from public certificate
              transparency logs, resolve their IPs, and surface what&apos;s exposed —
              no signup, no card.
            </p>
          </div>
        </section>

        {/* ================= DISCOVERY CARD ================= */}
        <section className="py-6 sm:py-8">
          <div className="mx-auto max-w-3xl px-4 sm:px-6">
            <QuickDiscoveryCard />
          </div>
        </section>

        {/* ================= WHAT'S COVERED ================= */}
        <section className="py-12 sm:py-16">
          <div className="mx-auto max-w-3xl px-4 sm:px-6">
            <div className="text-center mb-10">
              <span className="text-xs font-semibold text-cyan-400 uppercase tracking-widest">What&apos;s covered</span>
              <h2 className="mt-3 text-2xl sm:text-3xl font-bold tracking-tight">
                A free first pass — register for the rest.
              </h2>
              <p className="mt-3 text-sm text-white/60 max-w-xl mx-auto leading-relaxed">
                Quick Discovery uses the same CT-log feed our paid tier does, but
                stops short of brute-forcing or active probing. Free accounts unlock
                deeper enumeration.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/[0.04] p-5">
                <h3 className="text-sm font-semibold text-cyan-300 mb-3 flex items-center gap-2">
                  <Check className="w-4 h-4" />
                  Included
                </h3>
                <ul className="space-y-2 text-sm text-white/70 leading-relaxed">
                  <li>Subdomains from CT logs (crt.sh)</li>
                  <li>Apex IP resolution</li>
                  <li>Up to 30 subdomain IP resolutions</li>
                  <li>No signup, no card, no follow-up email</li>
                </ul>
              </div>
              <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-5">
                <h3 className="text-sm font-semibold text-white/80 mb-3 flex items-center gap-2">
                  <X className="w-4 h-4 text-white/50" />
                  Free account adds
                </h3>
                <ul className="space-y-2 text-sm text-white/55 leading-relaxed">
                  <li>Brute-force subdomain enumeration</li>
                  <li>12 discovery sources (CT, DNS, Shodan, RapidDNS, etc.)</li>
                  <li>ASN-based asset discovery</li>
                  <li>Saved discoveries with delta tracking</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        {/* ================= FINAL CTA ================= */}
        <section className="py-12 sm:py-16">
          <div className="mx-auto max-w-3xl px-4 sm:px-6">
            <div className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-gradient-to-br from-[#0d1a2e] to-[#0a1121] px-8 py-12 text-center sm:px-12">
              <div className="absolute inset-0 pointer-events-none">
                <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[400px] h-[200px] bg-cyan-500/[0.06] rounded-full blur-3xl" />
              </div>
              <div className="relative">
                <h2 className="text-2xl sm:text-3xl font-bold tracking-tight">
                  Ready for the
                  <span className="bg-gradient-to-r from-cyan-400/80 to-teal-400/70 bg-clip-text text-transparent"> deep enumeration?</span>
                </h2>
                <p className="mt-3 text-base text-white/55 max-w-lg mx-auto">
                  Brute-force discovery, 12 sources, ASN coverage, saved results,
                  and delta alerts when new subdomains appear. Free to start.
                </p>
                <div className="mt-7 flex flex-col sm:flex-row items-center justify-center gap-3">
                  <Link
                    href="/register"
                    className="group inline-flex items-center gap-2 rounded-xl bg-cyan-600 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-cyan-900/30 hover:bg-cyan-500 transition-all"
                  >
                    Create free account
                    <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                  </Link>
                  <Link
                    href="/quick-scan"
                    className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-6 py-3 text-sm font-medium text-white/70 hover:text-white hover:bg-white/[0.06] transition-all"
                  >
                    Try Quick Scan instead
                  </Link>
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
