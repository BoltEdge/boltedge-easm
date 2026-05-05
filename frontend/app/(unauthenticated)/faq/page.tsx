// FILE: app/(unauthenticated)/faq/page.tsx
// FAQ page — server-rendered for SEO, hands off to a client child
// for accordion interactivity.

import type { Metadata } from "next";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import LandingNav from "../LandingNav";
import FAQContent from "./FAQContent";
import JsonLd from "../JsonLd";

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

// Plain-text mirror of the most common FAQ questions for Google's
// FAQPage rich result. Keep in sync with FAQContent.tsx — answers
// here should be the substance of the visible answers, paraphrased
// without JSX. Google requires the JSON-LD content to substantively
// match what users see on the page.
const FAQ_JSONLD = {
  "@context": "https://schema.org",
  "@type": "FAQPage",
  mainEntity: [
    {
      "@type": "Question",
      name: "What does Nano EASM do?",
      acceptedAnswer: {
        "@type": "Answer",
        text:
          "Nano EASM helps you see your external attack surface the way an attacker would. You give it a domain, IP, or cloud asset and it discovers what is connected, scans for risk, and continuously monitors for changes.",
      },
    },
    {
      "@type": "Question",
      name: "Am I allowed to scan any domain?",
      acceptedAnswer: {
        "@type": "Answer",
        text:
          "No. Only run discovery and scanning against assets you own or are explicitly authorised to test. Scanning unauthorised systems may be illegal in your jurisdiction.",
      },
    },
    {
      "@type": "Question",
      name: "Is there a free plan?",
      acceptedAnswer: {
        "@type": "Answer",
        text:
          "Yes. The Free plan supports up to 2 assets and 5 scans per month so you can evaluate the platform without billing details. Paid plans start at A$29 per month.",
      },
    },
    {
      "@type": "Question",
      name: "Where is my data stored?",
      acceptedAnswer: {
        "@type": "Answer",
        text:
          "Customer data is stored in AWS us-east-1, encrypted at rest on EBS volumes and in transit via TLS. See the Privacy Policy and Data Handling and Retention policy for full details.",
      },
    },
    {
      "@type": "Question",
      name: "Does Nano EASM support an API?",
      acceptedAnswer: {
        "@type": "Answer",
        text:
          "Yes. The Nano EASM REST API lets you manage assets, run scans, retrieve findings, and integrate with your existing security workflows. See the API documentation for endpoints and authentication.",
      },
    },
    {
      "@type": "Question",
      name: "How is two-factor authentication handled?",
      acceptedAnswer: {
        "@type": "Answer",
        text:
          "Two-factor authentication is mandatory for all accounts. Use any TOTP authenticator app and save the recovery key shown once at enrolment.",
      },
    },
    {
      "@type": "Question",
      name: "What integrations are supported?",
      acceptedAnswer: {
        "@type": "Answer",
        text:
          "Nano EASM integrates with Slack and Jira for notifications and ticketing, plus a customer-configured audit log webhook for SIEM ingestion (available on Enterprise Gold and Custom tiers).",
      },
    },
    {
      "@type": "Question",
      name: "Can I cancel anytime?",
      acceptedAnswer: {
        "@type": "Answer",
        text:
          "Yes. You can cancel from the billing portal at any time. You retain access through the end of your current billing period.",
      },
    },
  ],
};

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
