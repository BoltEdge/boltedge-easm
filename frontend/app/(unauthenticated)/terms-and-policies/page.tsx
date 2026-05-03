// FILE: app/(unauthenticated)/terms-and-policies/page.tsx
// Index page listing all eight legal documents.

import Link from "next/link";
import { ArrowLeft, FileText, ShieldAlert, Lock, RefreshCcw, ScanLine, Scale, CreditCard, Database } from "lucide-react";
import LandingNav from "../LandingNav";

export const dynamic = "force-static";

export const metadata = {
  title: "Terms & Policies — Nano EASM",
  description: "Terms, policies, and agreements that govern your use of Nano EASM.",
};

const DOCS = [
  {
    slug: "terms-of-use",
    title: "Terms of Use",
    summary: "Master agreement governing your use of the Service.",
    icon: FileText,
  },
  {
    slug: "privacy-policy",
    title: "Privacy Policy",
    summary: "What data we collect, why, who we share it with, and your rights.",
    icon: Lock,
  },
  {
    slug: "acceptable-use-policy",
    title: "Acceptable Use Policy",
    summary: "Rules for what you can and can't do with the Service.",
    icon: ShieldAlert,
  },
  {
    slug: "security-scanning-authorisation",
    title: "Security & Scanning Authorisation",
    summary: "Controlling text confirming you're authorised to scan the assets you submit.",
    icon: ScanLine,
  },
  {
    slug: "subscription-payment-terms",
    title: "Subscription & Payment Terms",
    summary: "Plans, billing cycles, payment, taxes, auto-renewal, and price changes.",
    icon: CreditCard,
  },
  {
    slug: "refund-cancellation-policy",
    title: "Refund & Cancellation Policy",
    summary: "How to cancel, when refunds apply, and how to handle billing disputes.",
    icon: RefreshCcw,
  },
  {
    slug: "liability-limitation",
    title: "Liability Limitation",
    summary: "Caps and exclusions on each side's financial exposure.",
    icon: Scale,
  },
  {
    slug: "data-handling-retention",
    title: "Data Handling & Retention",
    summary: "Where your data lives, how long we keep it, and how it's protected.",
    icon: Database,
  },
];

export default function LegalIndexPage() {
  return (
    <>
      <LandingNav />

      <main className="pt-24 pb-20">
        <div className="mx-auto max-w-4xl px-4 sm:px-6">
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 text-sm text-white/50 hover:text-white transition-colors mb-8"
          >
            <ArrowLeft className="w-4 h-4" />Back to home
          </Link>

          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">Terms &amp; Policies</h1>
          <p className="mt-3 text-white/50 text-base max-w-2xl">
            The terms and policies that govern your use of Nano EASM. We try to keep these
            short and readable. If anything is unclear, write to{" "}
            <a href="mailto:contact@nanoasm.com" className="text-teal-400 hover:text-teal-300">
              contact@nanoasm.com
            </a>.
          </p>

          <div className="mt-10 grid grid-cols-1 md:grid-cols-2 gap-4">
            {DOCS.map(({ slug, title, summary, icon: Icon }) => (
              <Link
                key={slug}
                href={`/terms-and-policies/${slug}`}
                className="group rounded-xl border border-white/[0.06] bg-white/[0.02] p-5 hover:bg-white/[0.04] hover:border-teal-500/30 transition-colors"
              >
                <div className="flex items-start gap-3">
                  <div className="w-9 h-9 rounded-lg bg-teal-500/10 flex items-center justify-center shrink-0">
                    <Icon className="w-4 h-4 text-teal-400" />
                  </div>
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-white group-hover:text-teal-300 transition-colors">{title}</div>
                    <div className="text-xs text-white/50 mt-1 leading-relaxed">{summary}</div>
                  </div>
                </div>
              </Link>
            ))}
          </div>

          <p className="mt-10 text-xs text-white/30">
            Last updated 1 May 2026. Material changes will be communicated in-product
            and by email to account holders.
          </p>
        </div>
      </main>
    </>
  );
}
