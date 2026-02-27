// app/(unauthenticated)/LandingNav.tsx
"use client";

import { useState } from "react";
import Link from "next/link";
import { Menu, X } from "lucide-react";

const NAV_LINKS = [
  { href: "#features", label: "Features" },
  { href: "#how-it-works", label: "How it works" },
  { href: "#try-it", label: "Quick Test" },
  { href: "#pricing", label: "Pricing" },
];

export default function LandingNav() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <header className="fixed top-0 left-0 right-0 z-50 border-b border-white/[0.06] bg-[#060b18]/80 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2.5 group">
          <svg width="28" height="28" viewBox="0 0 32 32" fill="none" className="shrink-0">
            <rect width="32" height="32" rx="7" fill="#0a0f1e" />
            <path d="M17.5 4L9.5 17H14.5L13 28L21.5 14.5H16L17.5 4Z" fill="#14b8a6" />
          </svg>
          <span className="text-[15px] font-semibold tracking-tight">
            Bolt<span className="text-teal-400">Edge</span>
            <span className="text-[10px] text-white/40 font-medium ml-1.5 uppercase tracking-wider">
              EASM
            </span>
          </span>
        </Link>

        {/* Desktop nav */}
        <nav className="hidden md:flex items-center gap-8">
          {NAV_LINKS.map(({ href, label }) => (
            <a
              key={href}
              href={href}
              className="text-sm text-white/50 hover:text-white transition-colors"
            >
              {label}
            </a>
          ))}
        </nav>

        {/* Desktop auth buttons */}
        <div className="hidden md:flex items-center gap-3">
          <Link
            href="/login"
            className="text-sm text-white/60 hover:text-white transition-colors px-3 py-2"
          >
            Sign in
          </Link>
          <Link
            href="/register"
            className="inline-flex items-center rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white shadow-md shadow-teal-900/20 hover:bg-teal-500 transition-all"
          >
            Register
          </Link>
        </div>

        {/* Mobile hamburger */}
        <button
          type="button"
          onClick={() => setMobileOpen((v) => !v)}
          className="md:hidden p-2 rounded-lg text-white/60 hover:text-white hover:bg-white/[0.06] transition-colors"
          aria-label={mobileOpen ? "Close menu" : "Open menu"}
        >
          {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
      </div>

      {/* Mobile dropdown */}
      {mobileOpen && (
        <div className="md:hidden border-t border-white/[0.06] bg-[#060b18]/95 backdrop-blur-xl">
          <nav className="flex flex-col px-4 py-4 space-y-1">
            {NAV_LINKS.map(({ href, label }) => (
              <a
                key={href}
                href={href}
                onClick={() => setMobileOpen(false)}
                className="block px-3 py-2.5 rounded-lg text-sm text-white/60 hover:text-white hover:bg-white/[0.06] transition-colors"
              >
                {label}
              </a>
            ))}

            <div className="pt-3 mt-2 border-t border-white/[0.06] space-y-2">
              <Link
                href="/login"
                onClick={() => setMobileOpen(false)}
                className="block w-full px-3 py-2.5 rounded-lg text-sm text-white/60 hover:text-white hover:bg-white/[0.06] transition-colors text-center"
              >
                Sign in
              </Link>
              <Link
                href="/register"
                onClick={() => setMobileOpen(false)}
                className="block w-full px-3 py-2.5 rounded-lg text-sm font-medium text-white bg-teal-600 hover:bg-teal-500 transition-all text-center"
              >
                Register
              </Link>
            </div>
          </nav>
        </div>
      )}
    </header>
  );
}