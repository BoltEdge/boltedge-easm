// FILE: app/(unauthenticated)/faq/page.tsx
// FAQ page — server-rendered for SEO, hands off to a client child
// for accordion interactivity.

import type { Metadata } from "next";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import LandingNav from "../LandingNav";
import FAQContent from "./FAQContent";
import JsonLd from "../JsonLd";
import { faqsToJsonLd } from "./faq-data";

const SITE_URL = "https://nanoasm.com";

export const dynamic = "force-static";

export const metadata: Metadata = {
  title: "FAQ — Scanning, Pricing, Data, and Security Questions",
  description:
    "Answers to common questions about Nano EASM, authorised scanning, pricing, data handling, integrations, and external exposure monitoring.",
  alternates: { canonical: "/faq" },
  openGraph: {
    title: "Nano EASM FAQ — Scanning, Pricing, Data, and Security Questions",
    description:
      "Answers to common questions about Nano EASM, authorised scanning, pricing, data handling, integrations, and external exposure monitoring.",
    url: `${SITE_URL}/faq`,
    type: "article",
    siteName: "Nano EASM",
    locale: "en_AU",
  },
  twitter: {
    card: "summary_large_image",
    title: "Nano EASM FAQ — Scanning, Pricing, Data, and Security Questions",
    description:
      "Answers to common questions about Nano EASM, scanning authorisation, plans, data handling, and integrations.",
  },
};

// FAQPage JSON-LD is generated from the SAME data the visible UI
// renders (faq-data.tsx). Every question on the page is included,
// with the JSX answer flattened to plain text. Guarantees Google's
// "structured data must substantively match visible content" rule.
const FAQ_JSONLD = faqsToJsonLd();

export default function FAQPage() {
  return (
    <>
      <JsonLd data={FAQ_JSONLD} />
      <LandingNav />

      <main className="pt-24 pb-20">
        <div className="mx-auto max-w-3xl px-4 sm:px-6">
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 text-sm text-white/50 hover:text-white transition-colors mb-8"
          >
            <ArrowLeft className="w-4 h-4" />Back to home
          </Link>

          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">Frequently Asked Questions</h1>
          <p className="mt-3 text-white/50 text-base max-w-2xl leading-relaxed">
            Answers to common questions about Nano EASM, scanning authorisation, plans, data handling, and integrations.
          </p>

          <FAQContent />

          {/* Still stuck — contact CTA */}
          <div className="mt-16 rounded-xl border border-teal-500/20 bg-teal-500/[0.04] p-6 text-center">
            <p className="text-white/80 text-sm font-medium">Can&apos;t find what you&apos;re looking for?</p>
            <p className="text-white/50 text-sm mt-1">
              We&rsquo;re a small team and you&rsquo;ll get a real reply.
            </p>
            <Link
              href="/#contact"
              className="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white hover:bg-teal-500 transition-colors"
            >
              Contact us →
            </Link>
          </div>
        </div>
      </main>
    </>
  );
}
