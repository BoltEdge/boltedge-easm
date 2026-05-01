"use client";

import Link from "next/link";
import { ShieldAlert, ArrowLeft } from "lucide-react";
import LandingNav from "../LandingNav";

export const dynamic = "force-static";

export default function TermsPage() {
  const lastUpdated = "1 May 2026";

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

          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">Terms of Use</h1>
          <p className="mt-2 text-sm text-white/40">Last updated: {lastUpdated}</p>

          {/* Authorised use callout */}
          <div className="mt-8 rounded-xl border border-amber-500/30 bg-amber-500/[0.06] p-5 flex gap-3">
            <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="text-sm text-amber-100/90">
              <strong className="font-semibold text-amber-300">Authorised use only.</strong>{" "}
              You may only scan domains and IP addresses that you own or have
              explicit written permission to test. Using Nano EASM to scan
              third-party systems without authorisation may violate computer
              misuse, anti-hacking, or wiretap laws in your jurisdiction and
              is your sole responsibility.
            </div>
          </div>

          <div className="mt-10 space-y-8 text-[15px] leading-relaxed text-white/70">
            <section>
              <h2 className="text-xl font-semibold text-white mb-3">1. Acceptance</h2>
              <p>
                By creating an account, signing in, or using any feature of
                Nano EASM (&quot;the Service&quot;) — including the
                unauthenticated quick-scan tools — you agree to be bound by
                these Terms of Use. If you do not agree, do not use the Service.
              </p>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mb-3">2. Authorised Targets</h2>
              <p>
                You represent and warrant that, for every domain, hostname,
                or IP address you submit to the Service, you either:
              </p>
              <ul className="list-disc pl-6 mt-3 space-y-1.5">
                <li>own the asset and have authority to authorise scanning, or</li>
                <li>hold prior written permission from the asset owner to perform security testing.</li>
              </ul>
              <p className="mt-3">
                You are solely responsible for any consequences arising from
                scans you initiate. Nano EASM does not pre-validate ownership
                and disclaims liability for unauthorised use.
              </p>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mb-3">3. Acceptable Use</h2>
              <p>You agree not to use the Service to:</p>
              <ul className="list-disc pl-6 mt-3 space-y-1.5">
                <li>scan or probe systems you are not authorised to test;</li>
                <li>perform denial-of-service, brute-force, or credential-stuffing attacks;</li>
                <li>circumvent rate limits, IP blocks, or other access controls;</li>
                <li>distribute malware or use the Service as part of an attack chain against third parties;</li>
                <li>resell or repackage the Service without prior written agreement.</li>
              </ul>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mb-3">4. Quick-Scan Logging</h2>
              <p>
                Unauthenticated quick-scan requests are logged (IP address,
                user agent, target, and timestamp) for abuse prevention.
                Repeated misuse may result in IP-level blocking without notice.
              </p>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mb-3">5. No Warranty</h2>
              <p>
                The Service is provided &quot;as is&quot; without warranty of
                any kind, express or implied. Findings, severity scores,
                remediation guidance, and other output are best-effort and
                may contain false positives or false negatives. Nano EASM is
                not a substitute for a manual penetration test or qualified
                security review.
              </p>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mb-3">6. Limitation of Liability</h2>
              <p>
                To the maximum extent permitted by law, Nano EASM and its
                operators are not liable for any indirect, incidental,
                consequential, or punitive damages arising out of your use of
                the Service, including business interruption, data loss, or
                claims by third parties relating to scans you initiated.
              </p>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mb-3">7. Account Termination</h2>
              <p>
                We may suspend or terminate any account that violates these
                Terms or that we reasonably suspect is being used for
                unauthorised activity, with or without notice.
              </p>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mb-3">8. Changes</h2>
              <p>
                These Terms may be updated from time to time. Material changes
                will be communicated via the Service or by email to account
                holders. Continued use after the effective date constitutes
                acceptance of the revised Terms.
              </p>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mb-3">9. Contact</h2>
              <p>
                Questions about these Terms can be sent to{" "}
                <a href="mailto:contact@nanoasm.com" className="text-teal-400 hover:text-teal-300">
                  contact@nanoasm.com
                </a>
                .
              </p>
            </section>
          </div>

          <div className="mt-12 pt-6 border-t border-white/[0.06] text-xs text-white/30">
            This document is provided as a starting template. Review with
            qualified counsel before publishing publicly. It is not legal
            advice.
          </div>
        </div>
      </main>
    </>
  );
}
