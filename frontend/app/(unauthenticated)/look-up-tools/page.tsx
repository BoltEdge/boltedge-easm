// app/(unauthenticated)/look-up-tools/page.tsx
import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight } from "lucide-react";

import LandingNav from "../LandingNav";
import LandingFooter from "../LandingFooter";
import JsonLd from "../JsonLd";
import ToolsAccordion from "./ToolsAccordion";
import { VISIBLE_TOOLS } from "./tools-config";

const SITE_URL = "https://nanoeasm.com";
const PAGE_TITLE = "Free Security Lookup Tools — WHOIS, DNS, Cert, Headers — Nano EASM";
const PAGE_DESCRIPTION =
  "Free public lookup tools — WHOIS, DNS, certificate, HTTP headers, email security, and more. No signup, no card.";

export const metadata: Metadata = {
  title: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  alternates: { canonical: "/look-up-tools" },
  openGraph: {
    title: PAGE_TITLE,
    description: PAGE_DESCRIPTION,
    url: `${SITE_URL}/look-up-tools`,
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
  url: `${SITE_URL}/look-up-tools`,
  inLanguage: "en-AU",
  isPartOf: { "@type": "WebSite", name: "Nano EASM", url: SITE_URL },
};

const TOOLS_ITEMLIST_JSONLD = {
  "@context": "https://schema.org",
  "@type": "ItemList",
  name: "Free security lookup tools",
  itemListElement: VISIBLE_TOOLS.map((t, i) => ({
    "@type": "ListItem",
    position: i + 1,
    item: {
      "@type": "SoftwareApplication",
      name: t.name,
      description: t.description,
      applicationCategory: "SecurityApplication",
    },
  })),
};

const BREADCRUMB_JSONLD = {
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  itemListElement: [
    { "@type": "ListItem", position: 1, name: "Home", item: `${SITE_URL}/` },
    { "@type": "ListItem", position: 2, name: "Free Tools", item: `${SITE_URL}/look-up-tools` },
  ],
};

export default function ToolsPage() {
  return (
    <div className="min-h-screen bg-[#060b18] text-white overflow-x-hidden">
      <JsonLd data={[PAGE_JSONLD, TOOLS_ITEMLIST_JSONLD, BREADCRUMB_JSONLD]} />
      <LandingNav />
      <div className="h-16" /> {/* spacer for fixed navbar */}

      <main>
        {/* HERO */}
        <section className="relative">
          <div className="absolute inset-0 overflow-hidden pointer-events-none">
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-gradient-to-b from-teal-500/[0.07] via-cyan-500/[0.04] to-transparent rounded-full blur-3xl" />
          </div>
          <div className="relative mx-auto max-w-3xl px-4 sm:px-6 pt-12 sm:pt-16 pb-8 text-center">
            <div className="inline-flex items-center gap-2 rounded-full border border-teal-500/20 bg-teal-500/[0.06] px-4 py-1.5 mb-6">
              <span className="text-xs font-medium text-teal-400/70 tracking-wide">Free lookup tools</span>
            </div>
            <h1 className="text-3xl sm:text-5xl font-bold leading-[1.1] tracking-tight">
              Quick checks for<br />
              <span className="bg-gradient-to-r from-teal-400/80 via-cyan-400/70 to-teal-500/80 bg-clip-text text-transparent">
                security teams.
              </span>
            </h1>
            <p className="mt-5 text-base sm:text-lg text-white/70 leading-7 max-w-2xl mx-auto">
              {VISIBLE_TOOLS.length} hand-picked utilities — WHOIS, DNS, certs, HTTP
              headers, email auth, leak search. One domain at a time, no signup.
            </p>
          </div>
        </section>

        {/* TOOL GRID */}
        <section className="py-6 sm:py-8">
          <div className="mx-auto max-w-5xl px-4 sm:px-6">
            <ToolsAccordion />
          </div>
        </section>

        {/* FINAL CTA */}
        <section className="py-12 sm:py-16">
          <div className="mx-auto max-w-3xl px-4 sm:px-6">
            <div className="relative overflow-hidden rounded-2xl border border-white/[0.08] bg-gradient-to-br from-[#0d1a2e] to-[#0a1121] px-8 py-12 text-center sm:px-12">
              <div className="absolute inset-0 pointer-events-none">
                <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[400px] h-[200px] bg-teal-500/[0.06] rounded-full blur-3xl" />
              </div>
              <div className="relative">
                <h2 className="text-2xl sm:text-3xl font-bold tracking-tight">
                  Run these against your
                  <span className="bg-gradient-to-r from-teal-400/80 to-cyan-400/70 bg-clip-text text-transparent"> full inventory.</span>
                </h2>
                <p className="mt-3 text-base text-white/55 max-w-lg mx-auto">
                  A free account scans your whole asset list, monitors changes, and
                  alerts you when a cert is about to expire or a header gets dropped.
                </p>
                <div className="mt-7 flex flex-col sm:flex-row items-center justify-center gap-3">
                  <Link href="/register" className="group inline-flex items-center gap-2 rounded-xl bg-teal-600 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-teal-900/30 hover:bg-teal-500 transition-all">
                    Create free account
                    <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                  </Link>
                  <Link href="/quick-scan" className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-6 py-3 text-sm font-medium text-white/70 hover:text-white hover:bg-white/[0.06] transition-all">
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
