// app/(unauthenticated)/contact/page.tsx
// Dedicated /contact page. The same ContactForm component is also
// rendered in the landing page's #contact section so existing
// "Request free trial" CTAs that scroll-link to /?type=trial#contact
// keep working. This page exists for direct sharing, search-result
// landing, and a focused page-style URL.

import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";
import { ArrowLeft, Mail, ShieldAlert, Clock } from "lucide-react";

import LandingNav from "../LandingNav";
import LandingFooter from "../LandingFooter";
import JsonLd from "../JsonLd";
import ContactForm from "../ContactForm";

const SITE_URL = "https://nanoeasm.com";

const PAGE_TITLE = "Contact Nano EASM";
const PAGE_DESCRIPTION =
  "Get in touch with Nano EASM — request a free trial, ask a security or product question, or arrange a demo. Real reply within one business day.";

export const metadata: Metadata = {
  title: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  alternates: { canonical: "/contact" },
  openGraph: {
    title: PAGE_TITLE,
    description: PAGE_DESCRIPTION,
    url: `${SITE_URL}/contact`,
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
  "@type": "ContactPage",
  name: PAGE_TITLE,
  description: PAGE_DESCRIPTION,
  url: `${SITE_URL}/contact`,
  inLanguage: "en-AU",
  isPartOf: { "@type": "WebSite", name: "Nano EASM", url: SITE_URL },
  about: {
    "@type": "Organization",
    name: "Nano EASM",
    url: SITE_URL,
    email: "support@nanoeasm.com",
  },
};

const BREADCRUMB_JSONLD = {
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  itemListElement: [
    { "@type": "ListItem", position: 1, name: "Home", item: `${SITE_URL}/` },
    { "@type": "ListItem", position: 2, name: "Contact", item: `${SITE_URL}/contact` },
  ],
};

export default function ContactPage() {
  return (
    <>
      <JsonLd data={[PAGE_JSONLD, BREADCRUMB_JSONLD]} />
      <LandingNav />

      <main className="pt-24 pb-20">
        <div className="mx-auto max-w-3xl px-4 sm:px-6">
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 text-sm text-white/65 hover:text-white transition-colors mb-8"
          >
            <ArrowLeft className="w-4 h-4" />Back to home
          </Link>

          {/* Hero */}
          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">Get in touch</h1>
          <p className="mt-3 text-white/65 text-base max-w-2xl leading-relaxed">
            One real reply within one business day, from a real person — not
            a bot, not a ticket queue. Pick what you&rsquo;re after below.
          </p>

          {/* Response signals */}
          <div className="mt-6 grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
              <Clock className="w-4 h-4 text-teal-400 mb-2" />
              <div className="text-sm font-semibold text-white">Response time</div>
              <div className="text-xs text-white/55 mt-1 leading-relaxed">
                One business day, usually faster.
              </div>
            </div>
            <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
              <Mail className="w-4 h-4 text-cyan-400 mb-2" />
              <div className="text-sm font-semibold text-white">Email directly</div>
              <div className="text-xs text-white/55 mt-1 leading-relaxed">
                <a href="mailto:support@nanoeasm.com" className="text-teal-400 hover:text-teal-300">
                  support@nanoeasm.com
                </a>
              </div>
            </div>
            <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
              <ShieldAlert className="w-4 h-4 text-rose-400 mb-2" />
              <div className="text-sm font-semibold text-white">Security report</div>
              <div className="text-xs text-white/55 mt-1 leading-relaxed">
                <a href="mailto:security@nanoeasm.com" className="text-teal-400 hover:text-teal-300">
                  security@nanoeasm.com
                </a>
              </div>
            </div>
          </div>

          {/* Form */}
          <div className="mt-8">
            <Suspense fallback={
              <div className="rounded-2xl border border-white/[0.08] bg-white/[0.02] p-6 text-sm text-white/55">
                Loading form…
              </div>
            }>
              <ContactForm />
            </Suspense>
          </div>

          {/* Helpful first-stops */}
          <div className="mt-12 rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
            <div className="text-sm font-semibold text-white mb-2">Faster than waiting for a reply</div>
            <ul className="text-sm text-white/65 space-y-1.5 leading-relaxed">
              <li>
                <Link href="/faq" className="text-teal-400 hover:text-teal-300 underline underline-offset-2">
                  FAQ
                </Link>{" "}
                — common questions about scanning, plans, data, and integrations.
              </li>
              <li>
                <Link href="/quick-scan" className="text-teal-400 hover:text-teal-300 underline underline-offset-2">
                  Quick Scan
                </Link>{" "}
                — try a real scan against your domain in under a minute, no signup.
              </li>
              <li>
                <Link href="/api-docs" className="text-teal-400 hover:text-teal-300 underline underline-offset-2">
                  API docs
                </Link>{" "}
                — REST reference for everything the platform does.
              </li>
            </ul>
          </div>
        </div>
      </main>

      <LandingFooter />
    </>
  );
}
