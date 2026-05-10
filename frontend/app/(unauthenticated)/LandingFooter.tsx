// app/(unauthenticated)/LandingFooter.tsx
// Shared footer for every public marketing page. Mirrors the top-nav
// grouping (Product / Resources / Trust). Footer is the second-strongest
// internal-linking surface (every public page renders it), so the five
// coverage sub-pages get a permanent home here too.
import Link from "next/link";
import { BILLING_ENABLED } from "../lib/billing-config";

export default function LandingFooter() {
  return (
    <footer className="border-t border-white/[0.06]">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 py-12">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-8">
          {/* Brand column */}
          <div className="col-span-2 md:col-span-2">
            <Link href="/" className="flex items-center gap-2.5">
              <svg
                width="22"
                height="22"
                viewBox="0 0 32 32"
                fill="none"
                className="shrink-0"
                aria-hidden="true"
                focusable="false"
              >
                <rect width="32" height="32" rx="7" fill="#0a0f1e" />
                <path d="M17.5 4L9.5 17H14.5L13 28L21.5 14.5H16L17.5 4Z" fill="#14b8a6" />
              </svg>
              <span className="text-sm font-semibold">
                Nano <span className="text-teal-400">EASM</span>
              </span>
            </Link>
            <p className="mt-3 text-sm text-white/40 leading-relaxed max-w-xs">
              External Attack Surface Management for modern security
              teams. Discover, scan, monitor, prioritise.
            </p>
          </div>

          {/* Product */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-widest text-white/40 mb-4">Product</h4>
            <ul className="space-y-2.5 text-sm">
              <li><Link href="/#features" className="text-white/50 hover:text-white transition-colors">Capabilities</Link></li>
              <li><Link href="/#how-it-works" className="text-white/50 hover:text-white transition-colors">How it works</Link></li>
              <li><Link href="/coverage" className="text-white/50 hover:text-white transition-colors">Coverage</Link></li>
              <li><Link href="/quick-scan" className="text-white/50 hover:text-white transition-colors">Quick Scan</Link></li>
              {BILLING_ENABLED && (
                <li><Link href="/#pricing" className="text-white/50 hover:text-white transition-colors">Pricing</Link></li>
              )}
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-widest text-white/40 mb-4">Resources</h4>
            <ul className="space-y-2.5 text-sm">
              <li><Link href="/faq" className="text-white/50 hover:text-white transition-colors">FAQ</Link></li>
              <li><Link href="/api-docs" className="text-white/50 hover:text-white transition-colors">API docs</Link></li>
              <li><Link href="/resources/what-is-nano-easm" className="text-white/50 hover:text-white transition-colors">What is Nano EASM?</Link></li>
              <li><Link href="/#contact" className="text-white/50 hover:text-white transition-colors">Contact</Link></li>
            </ul>
          </div>

          {/* Trust */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-widest text-white/40 mb-4">Trust</h4>
            <ul className="space-y-2.5 text-sm">
              <li><Link href="/terms-and-policies" className="text-white/50 hover:text-white transition-colors">All policies</Link></li>
              <li><Link href="/terms-and-policies/terms-of-use" className="text-white/50 hover:text-white transition-colors">Terms of Use</Link></li>
              <li><Link href="/terms-and-policies/privacy-policy" className="text-white/50 hover:text-white transition-colors">Privacy</Link></li>
              <li><Link href="/terms-and-policies/security-scanning-authorisation" className="text-white/50 hover:text-white transition-colors">Scanning Authorisation</Link></li>
              <li><Link href="/terms-and-policies/data-handling-retention" className="text-white/50 hover:text-white transition-colors">Data handling</Link></li>
            </ul>
          </div>
        </div>

        {/* Coverage sub-page strip — cheap permanent internal links to all
            five category pages, on every marketing page. */}
        <div className="mt-10 pt-6 border-t border-white/[0.04]">
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-white/55">
            <span className="font-semibold text-white/45">Detection coverage:</span>
            <Link href="/coverage/vulnerabilities" className="hover:text-white/70 transition-colors">Vulnerabilities</Link>
            <Link href="/coverage/service-exposure" className="hover:text-white/70 transition-colors">Service Exposure</Link>
            <Link href="/coverage/data-leaks" className="hover:text-white/70 transition-colors">Data Leaks</Link>
            <Link href="/coverage/misconfigurations" className="hover:text-white/70 transition-colors">Misconfigurations</Link>
            <Link href="/coverage/security-hygiene" className="hover:text-white/70 transition-colors">Security Hygiene</Link>
          </div>
        </div>

        <div className="mt-8 pt-6 border-t border-white/[0.04] flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-white/50">
          <span>&copy; {new Date().getFullYear()} Nano EASM. All rights reserved.</span>
          <span>Built for security teams</span>
        </div>
      </div>
    </footer>
  );
}
