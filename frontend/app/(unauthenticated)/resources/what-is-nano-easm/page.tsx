// FILE: app/(unauthenticated)/resources/what-is-nano-easm/page.tsx
//
// Dedicated brand-entity SEO page. Exists to give Google an
// unambiguous "this is a cybersecurity SaaS, not the open-source
// Verilog assembler" signal at a stable URL we can link from
// elsewhere. The content is honest and substantive — Google's
// helpful-content guidelines penalise empty doorway pages.

import type { Metadata } from "next";
import Link from "next/link";
import { ArrowLeft, ArrowRight, Globe2, Radar, Bell, ClipboardCheck, Bug, ShieldCheck, KeyRound, AlertTriangle } from "lucide-react";

import LandingNav from "../../LandingNav";
import JsonLd from "../../JsonLd";

const SITE_URL = "https://nanoeasm.com";
const PAGE_URL = `${SITE_URL}/resources/what-is-nano-easm`;

export const dynamic = "force-static";

export const metadata: Metadata = {
  title: "What is Nano EASM?",
  description:
    "Nano EASM is a cybersecurity / External Attack Surface Management platform for IT teams, security generalists, and small MSSPs. Discover external assets, monitor exposure changes, and prioritise remediation.",
  alternates: { canonical: "/resources/what-is-nano-easm" },
  openGraph: {
    title: "What is Nano EASM? | Cybersecurity Platform",
    description:
      "Nano EASM is a cybersecurity / External Attack Surface Management platform for IT teams and small MSSPs.",
    url: PAGE_URL,
    type: "article",
    siteName: "Nano EASM",
    locale: "en_AU",
  },
  twitter: {
    card: "summary_large_image",
    title: "What is Nano EASM? | Cybersecurity Platform",
    description:
      "External Attack Surface Management platform for IT teams and small MSSPs.",
  },
};

const ARTICLE_JSONLD = {
  "@context": "https://schema.org",
  "@type": "Article",
  headline: "What is Nano EASM?",
  description:
    "Nano EASM is a cybersecurity / External Attack Surface Management platform for IT teams, security generalists, and small MSSPs.",
  url: PAGE_URL,
  mainEntityOfPage: PAGE_URL,
  author: { "@type": "Organization", name: "Nano EASM", url: SITE_URL },
  publisher: {
    "@type": "Organization",
    name: "Nano EASM",
    url: SITE_URL,
    logo: {
      "@type": "ImageObject",
      url: `${SITE_URL}/logo-on-dark.svg`,
    },
  },
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
    {
      "@type": "ListItem",
      position: 2,
      name: "Resources",
      item: `${SITE_URL}/resources/what-is-nano-easm`,
    },
    {
      "@type": "ListItem",
      position: 3,
      name: "What is Nano EASM?",
      item: PAGE_URL,
    },
  ],
};

export default function WhatIsNanoEasmPage() {
  return (
    <>
      <JsonLd data={[ARTICLE_JSONLD, BREADCRUMB_JSONLD]} />
      <LandingNav />

      <main className="pt-24 pb-20">
        <div className="mx-auto max-w-3xl px-4 sm:px-6">
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 text-sm text-white/50 hover:text-white transition-colors mb-8"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to home
          </Link>

          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">
            What is Nano EASM?
          </h1>
          <p className="mt-4 text-lg text-white/60 leading-relaxed">
            Nano EASM is a <strong className="text-white/80">cybersecurity SaaS platform</strong>{" "}
            for <strong className="text-white/80">External Attack Surface Management</strong>.
            It helps IT teams, security generalists, and small MSSPs discover
            internet-facing assets, scan for risk, monitor exposure changes, and
            prioritise remediation — without juggling multiple tools.
          </p>

          <h2 className="mt-12 text-2xl font-semibold tracking-tight">
            What does External Attack Surface Management mean?
          </h2>
          <p className="mt-3 text-white/60 leading-relaxed">
            Your <em>external attack surface</em> is everything an attacker on the
            public internet can see and reach: domains, subdomains, IP ranges, exposed
            cloud services, certificates, third-party integrations. Most organisations
            don&rsquo;t have a complete picture of theirs — shadow IT, forgotten
            subdomains, and misconfigured cloud assets accumulate over time. EASM is
            the discipline of continuously discovering, monitoring, and reducing that
            attack surface.
          </p>

          <h2 className="mt-10 text-2xl font-semibold tracking-tight">
            What Nano EASM helps you do
          </h2>

          <div className="mt-6 grid grid-cols-1 sm:grid-cols-2 gap-4">
            {[
              {
                icon: Globe2,
                title: "Discover external assets",
                blurb:
                  "Map subdomains, IPs, exposed services, and certificates from a single seed domain. Surfaces shadow IT and forgotten infrastructure.",
              },
              {
                icon: Radar,
                title: "Scan for risk",
                blurb:
                  "Quick, Standard, and Deep scans look for known vulnerabilities, misconfigurations, and exposure issues — with severity scoring and CVE references.",
              },
              {
                icon: Bell,
                title: "Monitor exposure changes",
                blurb:
                  "Continuous monitoring with change detection. Get alerted when a new port opens, a certificate is about to expire, or a finding appears.",
              },
              {
                icon: ClipboardCheck,
                title: "Prioritise remediation",
                blurb:
                  "Each finding comes with a plain-English explanation and clear next steps. Export to CSV/PDF for ticketing, audit evidence, or client reporting.",
              },
            ].map(({ icon: Icon, title, blurb }) => (
              <div
                key={title}
                className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5"
              >
                <div className="w-9 h-9 rounded-lg bg-teal-500/15 flex items-center justify-center mb-3">
                  <Icon className="w-4 h-4 text-teal-400" />
                </div>
                <h3 className="text-sm font-semibold text-white">{title}</h3>
                <p className="mt-1.5 text-sm text-white/50 leading-relaxed">{blurb}</p>
              </div>
            ))}
          </div>

          <h2 className="mt-10 text-2xl font-semibold tracking-tight">
            What Nano EASM detects
          </h2>
          <p className="mt-3 text-white/60 leading-relaxed">
            Every alert the platform raises falls into one of five categories. You
            can toggle any of them on or off for your organisation, and override per
            asset group — see the{" "}
            <Link href="/coverage" className="text-teal-400 hover:underline">
              full coverage page
            </Link>{" "}
            for details.
          </p>
          <div className="mt-5 grid grid-cols-1 sm:grid-cols-2 gap-3">
            {[
              {
                icon: Bug,
                title: "Vulnerabilities",
                blurb:
                  "Known CVEs and software flaws in services running on your assets.",
              },
              {
                icon: Globe2,
                title: "Service Exposure",
                blurb:
                  "Admin panels, dev tools, databases, and cloud assets reachable from the internet.",
              },
              {
                icon: KeyRound,
                title: "Data Leaks",
                blurb:
                  "Secrets, credentials, configuration files, and source code exposed in public repos or directly on the asset.",
              },
              {
                icon: AlertTriangle,
                title: "Misconfigurations",
                blurb:
                  "CORS, open redirects, default credentials, and accessible admin endpoints.",
              },
              {
                icon: ShieldCheck,
                title: "Security Hygiene",
                blurb:
                  "Expiring certificates, missing security headers, weak DMARC/SPF, and end-of-life software stacks.",
              },
            ].map(({ icon: Icon, title, blurb }) => (
              <div
                key={title}
                className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4"
              >
                <div className="flex items-center gap-2 mb-1.5">
                  <Icon className="w-4 h-4 text-teal-400" />
                  <h3 className="text-sm font-semibold text-white">{title}</h3>
                </div>
                <p className="text-sm text-white/55 leading-relaxed">{blurb}</p>
              </div>
            ))}
          </div>

          <h2 className="mt-10 text-2xl font-semibold tracking-tight">
            Who is Nano EASM for?
          </h2>
          <ul className="mt-3 space-y-2 text-white/60 leading-relaxed list-disc pl-5">
            <li>
              <strong className="text-white/80">IT teams</strong> at small and mid-size
              organisations who don&rsquo;t have a dedicated security operations
              centre but still need to know what&rsquo;s exposed on the internet.
            </li>
            <li>
              <strong className="text-white/80">Security generalists</strong> who want
              one platform that handles discovery, scanning, monitoring, and reporting
              — instead of stitching three or four tools together.
            </li>
            <li>
              <strong className="text-white/80">Small MSSPs</strong> managing multiple
              client environments who need separate workspaces, separate billing, and
              exportable reports per client.
            </li>
          </ul>

          <h2 className="mt-10 text-2xl font-semibold tracking-tight">
            How is it different from a vulnerability scanner?
          </h2>
          <p className="mt-3 text-white/60 leading-relaxed">
            A traditional vulnerability scanner needs you to tell it{" "}
            <em>what</em> to scan. EASM starts with the question{" "}
            <em>what do we have?</em> — discovering the assets first, then scanning
            them. The output is a complete view of external exposure, not just a list
            of CVEs against assets you already knew about.
          </p>

          <h2 className="mt-10 text-2xl font-semibold tracking-tight">
            Get started
          </h2>
          <p className="mt-3 text-white/60 leading-relaxed">
            Nano EASM has a Free plan with no payment details required — add up to two
            assets, run up to five scans a month, and see what your external attack
            surface actually looks like. Upgrade tiers add more assets, monitoring,
            scheduled scans, integrations, and team seats.
          </p>

          <div className="mt-6 flex flex-col sm:flex-row gap-3">
            <Link
              href="/register"
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-teal-600 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-teal-900/30 hover:bg-teal-500 transition-all"
            >
              Get started free
              <ArrowRight className="w-4 h-4" />
            </Link>
            <Link
              href="/faq"
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-6 py-3 text-sm font-medium text-white/70 hover:text-white hover:bg-white/[0.06] transition-all"
            >
              Read the FAQ
            </Link>
            <Link
              href="/api-docs"
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-6 py-3 text-sm font-medium text-white/70 hover:text-white hover:bg-white/[0.06] transition-all"
            >
              See the API docs
            </Link>
          </div>
        </div>
      </main>
    </>
  );
}
