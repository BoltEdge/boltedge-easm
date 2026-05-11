// FILE: app/(unauthenticated)/faq/page.tsx
// FAQ page — server-rendered for SEO, hands off to a client child
// for accordion interactivity.

import type { Metadata } from "next";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import LandingNav from "../LandingNav";
import LandingFooter from "../LandingFooter";
import FAQContent from "./FAQContent";
import JsonLd from "../JsonLd";
import { FAQS, faqsToJsonLd } from "./faq-data";

// Slugify category titles into stable anchor ids — must match the ids
// emitted by FAQContent so the sidebar's "#getting-started" links scroll
// the matching section into view.
function slugifyCategory(title: string): string {
  return title
    .toLowerCase()
    .replace(/&/g, "and")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
}

const SITE_URL = "https://nanoeasm.com";

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
        <div className="mx-auto max-w-6xl px-4 sm:px-6">
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 text-sm text-white/50 hover:text-white transition-colors mb-8"
          >
            <ArrowLeft className="w-4 h-4" />Back to home
          </Link>

          <div className="grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-10">
            {/* ── Sticky category TOC ── */}
            <aside className="hidden lg:block">
              <nav className="sticky top-24 space-y-1 text-sm">
                <div className="text-[11px] uppercase tracking-wider text-white/45 font-semibold mb-3">
                  Categories
                </div>
                {FAQS.map((cat) => {
                  const Icon = cat.icon;
                  const slug = slugifyCategory(cat.title);
                  return (
                    <a
                      key={cat.title}
                      href={`#${slug}`}
                      className="flex items-center gap-2 py-1.5 px-2 rounded text-white/65 hover:text-white hover:bg-white/[0.04] transition-colors"
                    >
                      <Icon className="w-3.5 h-3.5 text-teal-400/70 shrink-0" />
                      <span className="truncate">{cat.title}</span>
                    </a>
                  );
                })}
                <div className="mt-6 pt-4 border-t border-white/[0.06]">
                  <Link
                    href="/#contact"
                    className="flex items-center gap-2 py-1.5 px-2 rounded text-teal-400 hover:text-teal-300 hover:bg-white/[0.04] transition-colors"
                  >
                    Still stuck? Contact us →
                  </Link>
                </div>
              </nav>
            </aside>

            {/* ── Content ── */}
            <div className="min-w-0">
              <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">Frequently Asked Questions</h1>
              <p className="mt-3 text-white/65 text-base max-w-2xl leading-relaxed">
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
          </div>
        </div>
      </main>

      <LandingFooter />
    </>
  );
}
