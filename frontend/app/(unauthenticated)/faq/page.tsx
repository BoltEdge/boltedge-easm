// FILE: app/(unauthenticated)/faq/page.tsx
// FAQ page — server-rendered for SEO, hands off to a client child
// for accordion interactivity.

import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import LandingNav from "../LandingNav";
import FAQContent from "./FAQContent";

export const dynamic = "force-static";

export const metadata = {
  title: "FAQ — Nano EASM",
  description:
    "Answers to common questions about Nano EASM, scanning authorisation, plans, data handling, and integrations.",
};

export default function FAQPage() {
  return (
    <>
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
