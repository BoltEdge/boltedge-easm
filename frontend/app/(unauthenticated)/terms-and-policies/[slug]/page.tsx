// FILE: app/(unauthenticated)/terms-and-policies/[slug]/page.tsx
//
// Renders any of the eight legal documents from frontend/content/legal/
// as a styled, server-rendered page. Markdown is parsed at build time
// (the docs are static) so there's no runtime markdown cost.
//
// Source-of-truth lives in /Legal docs/ at the project root and is
// duplicated into frontend/content/legal/ so it's inside the Docker
// build context.

import fs from "fs";
import path from "path";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { marked } from "marked";

import LandingNav from "../../LandingNav";

export const dynamic = "force-static";

const DOCS: Record<string, { title: string; file: string }> = {
  "terms-of-use": { title: "Terms of Use", file: "terms-of-use.md" },
  "privacy-policy": { title: "Privacy Policy", file: "privacy-policy.md" },
  "acceptable-use-policy": { title: "Acceptable Use Policy", file: "acceptable-use-policy.md" },
  "refund-cancellation-policy": { title: "Refund & Cancellation Policy", file: "refund-cancellation-policy.md" },
  "security-scanning-authorisation": { title: "Security & Scanning Authorisation", file: "security-scanning-authorisation.md" },
  "liability-limitation": { title: "Liability Limitation", file: "liability-limitation.md" },
  "subscription-payment-terms": { title: "Subscription & Payment Terms", file: "subscription-payment-terms.md" },
  "data-handling-retention": { title: "Data Handling & Retention", file: "data-handling-retention.md" },
};

export function generateStaticParams() {
  return Object.keys(DOCS).map((slug) => ({ slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const meta = DOCS[slug];
  if (!meta) return {};
  return {
    title: `${meta.title} — Nano EASM`,
    description: `${meta.title} for the Nano EASM platform.`,
  };
}

export default async function LegalDocPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug: rawSlug } = await params;
  // Accept "/terms-and-policies/foo.md" as a courtesy — strip the
  // extension and resolve to the same page. Avoids 404s when someone
  // deep-links with the file extension still attached.
  const slug = rawSlug.replace(/\.md$/i, "");
  const meta = DOCS[slug];
  if (!meta) notFound();

  const filePath = path.join(process.cwd(), "content", "legal", meta.file);
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf-8");
  } catch {
    notFound();
  }

  // Strip the duplicate H1 from the markdown — we render our own
  // styled title in the page header below.
  const stripped = raw!.replace(/^#\s+.+\n/, "").trim();

  // Rewrite cross-doc relative links: `./privacy-policy.md` and
  // `./privacy-policy.md#anchor` become absolute URLs so they
  // navigate to the correct page (no `.md` 404s).
  const linksFixed = stripped.replace(
    /\]\(\.\/([a-z0-9-]+)\.md(#[^)]+)?\)/gi,
    "](/terms-and-policies/$1$2)",
  );

  marked.setOptions({ gfm: true, breaks: false });
  const html = await marked.parse(linksFixed);

  return (
    <>
      <LandingNav />

      <main className="pt-24 pb-20">
        <div className="mx-auto max-w-3xl px-4 sm:px-6">
          <Link
            href="/terms-and-policies"
            className="inline-flex items-center gap-1.5 text-sm text-white/50 hover:text-white transition-colors mb-8"
          >
            <ArrowLeft className="w-4 h-4" />Back to Terms &amp; Policies
          </Link>

          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">{meta.title}</h1>

          <article
            className="legal-doc mt-8 text-[15px] leading-relaxed text-white/70"
            dangerouslySetInnerHTML={{ __html: html }}
          />
        </div>
      </main>
    </>
  );
}
