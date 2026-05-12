// app/(unauthenticated)/LandingNav.tsx
"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { ChevronDown, LayoutDashboard, Menu, X } from "lucide-react";
import { BILLING_ENABLED } from "../lib/billing-config";
import { isLoggedIn } from "../lib/auth";

// Nav model — top-level items can be either flat links or dropdowns
// containing sub-items. Pricing stays billing-gated. Hash anchors are
// only valid on the home page; if the user is on a sub-page (FAQ,
// Coverage, etc.), we route them to "/" first via the href anyway.

type NavSubItemLink = {
  kind?: "link";
  href: string;
  label: string;
  description?: string;
  badge?: string;
  billingOnly?: boolean;
};

type NavSubItemSection = {
  kind: "section";
  label: string;
};

type NavSubItem = NavSubItemLink | NavSubItemSection;

type NavTopItem =
  | { kind: "link"; href: string; label: string; billingOnly?: boolean }
  | { kind: "dropdown"; label: string; items: NavSubItem[] };

const TOP_NAV: NavTopItem[] = [
  {
    kind: "dropdown",
    label: "Product",
    items: [
      { href: "/#features", label: "Capabilities", description: "What the platform does, end to end." },
      { href: "/#how-it-works", label: "How it works", description: "Discover → scan → score → monitor." },
      { href: "/coverage", label: "Coverage", description: "Every finding category we detect.", badge: "New" },
      { kind: "section", label: "Free tools" },
      { href: "/quick-scan", label: "Quick Scan", description: "Try a free scan, no signup." },
      { href: "/quick-discovery", label: "Quick Discovery", description: "Find subdomains free, no signup." },
      { href: "/look-up-tools", label: "Lookup Tools", description: "WHOIS, DNS, certs, headers — free." },
      { href: "/#pricing", label: "Pricing", description: "Plan tiers and limits.", billingOnly: true },
    ],
  },
  {
    kind: "dropdown",
    label: "Resources",
    items: [
      { href: "/resources/blog", label: "Blog", description: "Articles on ASM, EASM, and modern security practice." },
      { href: "/faq", label: "FAQ", description: "Common questions, plain answers." },
      { href: "/api-docs", label: "API Docs", description: "Integrate Nano EASM with your stack." },
      { href: "/resources/what-is-nano-easm", label: "What is Nano EASM?", description: "The platform, explained." },
    ],
  },
  { kind: "link", href: "/terms-and-policies", label: "Trust" },
  { kind: "link", href: "/contact", label: "Contact" },
];


// Filter billing-only sub-items when billing is disabled. We don't
// remove whole top-level dropdowns — Pricing is the only billing-gated
// item, and Product still has plenty of entries without it.
function visibleNav(): NavTopItem[] {
  return TOP_NAV.map((top) => {
    if (top.kind === "link") {
      if (top.billingOnly && !BILLING_ENABLED) return null;
      return top;
    }
    const items = top.items.filter((it) => {
      if (it.kind === "section") return true;
      return !it.billingOnly || BILLING_ENABLED;
    });
    // Bail if the only items left are section headers with no link entries.
    if (!items.some((it) => it.kind !== "section")) return null;
    return { ...top, items };
  }).filter(Boolean) as NavTopItem[];
}


// Single-dropdown-at-a-time behaviour. Only one panel ever renders,
// so panels can't visually collide regardless of trigger spacing or
// panel width. Opening one trigger automatically closes the other
// via the shared activeMenu state in the parent.
type DropdownDesktopProps = {
  label: string;
  items: NavSubItem[];
  isOpen: boolean;
  onActivate: () => void;
  onClose: () => void;
  onPointerEnter: () => void;
  onPointerLeave: () => void;
};

function DropdownDesktop({
  label, items, isOpen, onActivate, onClose, onPointerEnter, onPointerLeave,
}: DropdownDesktopProps) {
  return (
    <div
      className="relative"
      onMouseEnter={onPointerEnter}
      onMouseLeave={onPointerLeave}
    >
      <button
        type="button"
        onClick={() => (isOpen ? onClose() : onActivate())}
        onFocus={onActivate}
        className="inline-flex items-center gap-1 text-sm text-white/50 hover:text-white transition-colors py-2"
        aria-expanded={isOpen}
        aria-haspopup="menu"
      >
        {label}
        <ChevronDown className={`w-3.5 h-3.5 transition-transform ${isOpen ? "rotate-180" : ""}`} />
      </button>

      {isOpen && (
        <div
          role="menu"
          // Anchor to the trigger's left edge rather than centring —
          // centring caused panels to extend further to the left than
          // the trigger does, so the Product and Resources panels
          // bled into each other when both were open. Left-anchored
          // panels stay strictly under their trigger and never cross
          // a sibling trigger horizontally. max-w clamp prevents
          // overflow on narrow viewports.
          className="absolute left-0 top-full mt-1 w-72 max-w-[calc(100vw-2rem)] rounded-xl border border-white/[0.08] bg-[#060b18]/98 backdrop-blur-xl shadow-2xl shadow-black/50 p-1.5 z-50"
        >
          {items.map((it, i) => {
            if (it.kind === "section") {
              return (
                <div
                  key={`section-${i}`}
                  className="px-3 pt-3 pb-1 mt-1 text-[10px] font-semibold uppercase tracking-wider text-white/40 border-t border-white/[0.06] first:mt-0 first:border-t-0 first:pt-2"
                >
                  {it.label}
                </div>
              );
            }
            return (
              <Link
                key={it.href}
                href={it.href}
                role="menuitem"
                onClick={onClose}
                className="block px-3 py-2.5 rounded-lg hover:bg-white/[0.04] transition-colors group"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium text-white/85 group-hover:text-white">
                    {it.label}
                  </span>
                  {it.badge && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-teal-500/20 text-teal-300 font-bold uppercase tracking-wider">
                      {it.badge}
                    </span>
                  )}
                </div>
                {it.description && (
                  <div className="text-xs text-white/40 mt-0.5 leading-relaxed">{it.description}</div>
                )}
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}


export default function LandingNav() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [mobileExpanded, setMobileExpanded] = useState<string | null>(null);
  const [isAuthed, setIsAuthed] = useState(false);

  // Which dropdown is open. Single string state — a non-null value
  // means exactly one dropdown is rendered, so panels can never
  // visually collide. Switching from one trigger to another is a
  // single setActiveMenu call: the previous panel's render condition
  // becomes false on the same render cycle.
  const [activeMenu, setActiveMenu] = useState<string | null>(null);
  const desktopNavRef = useRef<HTMLDivElement | null>(null);
  const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // SSR renders the logged-out variant (no token on the server) and
  // the client re-renders to "Open dashboard" once mount detects a
  // valid session — avoids hydration mismatch + the "click Sign in
  // while logged in → see login form" footgun.
  useEffect(() => {
    setIsAuthed(isLoggedIn());
  }, []);

  // Click-outside + ESC close whichever dropdown is open. Single
  // listener for the whole nav.
  useEffect(() => {
    if (!activeMenu) return;
    const onClick = (e: MouseEvent) => {
      if (desktopNavRef.current && !desktopNavRef.current.contains(e.target as Node)) {
        setActiveMenu(null);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setActiveMenu(null);
    };
    document.addEventListener("mousedown", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [activeMenu]);

  const cancelClose = () => {
    if (closeTimer.current) {
      clearTimeout(closeTimer.current);
      closeTimer.current = null;
    }
  };
  const scheduleClose = () => {
    cancelClose();
    // 120ms grace so the user can move from trigger to panel (or
    // between sibling triggers) without flicker.
    closeTimer.current = setTimeout(() => setActiveMenu(null), 120);
  };

  const nav = visibleNav();

  return (
    <header className="fixed top-0 left-0 right-0 z-50 border-b border-white/[0.06] bg-[#060b18]/80 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2.5 group">
          <svg
            width="28"
            height="28"
            viewBox="0 0 32 32"
            fill="none"
            className="shrink-0"
            aria-hidden="true"
            focusable="false"
          >
            <rect width="32" height="32" rx="7" fill="#0a0f1e" />
            <path d="M17.5 4L9.5 17H14.5L13 28L21.5 14.5H16L17.5 4Z" fill="#14b8a6" />
          </svg>
          <span className="text-[15px] font-semibold tracking-tight">
            Nano <span className="text-teal-400">EASM</span>
          </span>
        </Link>

        {/* Desktop nav. Each dropdown trigger manages its own hover
            in/out via DropdownDesktop's handlers, so switching from
            Product → Resources flips activeMenu instantly without a
            close-then-reopen flicker. */}
        <nav ref={desktopNavRef} className="hidden md:flex items-center gap-6">
          {nav.map((item) =>
            item.kind === "dropdown" ? (
              <DropdownDesktop
                key={item.label}
                label={item.label}
                items={item.items}
                isOpen={activeMenu === item.label}
                onActivate={() => { cancelClose(); setActiveMenu(item.label); }}
                onClose={() => { cancelClose(); setActiveMenu(null); }}
                onPointerEnter={() => { cancelClose(); setActiveMenu(item.label); }}
                onPointerLeave={scheduleClose}
              />
            ) : (
              <Link
                key={item.label}
                href={item.href}
                onClick={() => setActiveMenu(null)}
                className="text-sm text-white/50 hover:text-white transition-colors py-2"
              >
                {item.label}
              </Link>
            )
          )}
        </nav>

        {/* Desktop auth buttons */}
        <div className="hidden md:flex items-center gap-3">
          {isAuthed ? (
            <Link
              href="/dashboard"
              className="inline-flex items-center gap-2 rounded-lg bg-teal-600 px-4 py-2 text-sm font-medium text-white shadow-md shadow-teal-900/20 hover:bg-teal-500 transition-all"
            >
              <LayoutDashboard className="w-4 h-4" />
              Open dashboard
            </Link>
          ) : (
            <>
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
                Get started
              </Link>
            </>
          )}
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
          <nav className="flex flex-col px-4 py-4 space-y-1 max-h-[80vh] overflow-y-auto">
            {nav.map((item) => {
              if (item.kind === "link") {
                return (
                  <Link
                    key={item.label}
                    href={item.href}
                    onClick={() => setMobileOpen(false)}
                    className="block px-3 py-2.5 rounded-lg text-sm text-white/60 hover:text-white hover:bg-white/[0.06] transition-colors"
                  >
                    {item.label}
                  </Link>
                );
              }
              const expanded = mobileExpanded === item.label;
              return (
                <div key={item.label} className="space-y-1">
                  <button
                    type="button"
                    onClick={() => setMobileExpanded(expanded ? null : item.label)}
                    className="flex w-full items-center justify-between px-3 py-2.5 rounded-lg text-sm text-white/60 hover:text-white hover:bg-white/[0.06] transition-colors"
                    aria-expanded={expanded}
                  >
                    <span>{item.label}</span>
                    <ChevronDown className={`w-4 h-4 transition-transform ${expanded ? "rotate-180" : ""}`} />
                  </button>
                  {expanded && (
                    <div className="pl-3 space-y-0.5">
                      {item.items.map((sub, i) => {
                        if (sub.kind === "section") {
                          return (
                            <div
                              key={`section-${i}`}
                              className="px-3 pt-2 pb-0.5 text-[10px] font-semibold uppercase tracking-wider text-white/40"
                            >
                              {sub.label}
                            </div>
                          );
                        }
                        return (
                          <Link
                            key={sub.href}
                            href={sub.href}
                            onClick={() => setMobileOpen(false)}
                            className="block px-3 py-2 rounded-lg text-sm text-white/55 hover:text-white hover:bg-white/[0.06] transition-colors"
                          >
                            <div className="flex items-center justify-between">
                              <span>{sub.label}</span>
                              {sub.badge && (
                                <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-teal-500/20 text-teal-300 font-bold uppercase tracking-wider">
                                  {sub.badge}
                                </span>
                              )}
                            </div>
                          </Link>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}

            <div className="pt-3 mt-2 border-t border-white/[0.06] space-y-2">
              {isAuthed ? (
                <Link
                  href="/dashboard"
                  onClick={() => setMobileOpen(false)}
                  className="flex w-full items-center justify-center gap-2 px-3 py-2.5 rounded-lg text-sm font-medium text-white bg-teal-600 hover:bg-teal-500 transition-all"
                >
                  <LayoutDashboard className="w-4 h-4" />
                  Open dashboard
                </Link>
              ) : (
                <>
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
                    Get started
                  </Link>
                </>
              )}
            </div>
          </nav>
        </div>
      )}
    </header>
  );
}
