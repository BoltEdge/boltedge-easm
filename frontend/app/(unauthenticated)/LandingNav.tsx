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

type NavSubItem = {
  href: string;
  label: string;
  description?: string;
  badge?: string;
  billingOnly?: boolean;
};

type NavTopItem =
  | { kind: "link"; href: string; label: string; billingOnly?: boolean }
  | { kind: "dropdown"; label: string; items: NavSubItem[] };

const TOP_NAV: NavTopItem[] = [
  {
    kind: "dropdown",
    label: "Product",
    items: [
      { href: "/#features", label: "Features", description: "What the platform does, end to end." },
      { href: "/#how-it-works", label: "How it works", description: "Discover → scan → score → monitor." },
      { href: "/coverage", label: "Coverage", description: "Every finding category we detect.", badge: "New" },
      { href: "/quick-scan", label: "Quick Scan", description: "Try a free scan, no signup." },
      { href: "/#pricing", label: "Pricing", description: "Plan tiers and limits.", billingOnly: true },
    ],
  },
  {
    kind: "dropdown",
    label: "Resources",
    items: [
      { href: "/faq", label: "FAQ", description: "Common questions, plain answers." },
      { href: "/api-docs", label: "API docs", description: "Integrate Nano EASM with your stack." },
      { href: "/resources/what-is-nano-easm", label: "What is Nano EASM?", description: "The platform, explained." },
    ],
  },
  { kind: "link", href: "/terms-and-policies", label: "Trust" },
  { kind: "link", href: "/#contact", label: "Contact" },
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
    const items = top.items.filter((it) => !it.billingOnly || BILLING_ENABLED);
    if (items.length === 0) return null;
    return { ...top, items };
  }).filter(Boolean) as NavTopItem[];
}


// Single shared "which menu is open" state owned by LandingNav and
// passed down. Opening one menu auto-closes any other. Click-outside
// is also handled at the parent level — one listener instead of one
// per dropdown.
type DropdownDesktopProps = {
  label: string;
  items: NavSubItem[];
  isOpen: boolean;
  onOpen: () => void;
  onClose: () => void;
  onHoverOpen: () => void;
  onHoverClose: () => void;
};

function DropdownDesktop({
  label, items, isOpen, onOpen, onClose, onHoverOpen, onHoverClose,
}: DropdownDesktopProps) {
  return (
    <div
      className="relative"
      onMouseEnter={onHoverOpen}
      onMouseLeave={onHoverClose}
    >
      <button
        type="button"
        onClick={() => (isOpen ? onClose() : onOpen())}
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
          className="absolute left-1/2 -translate-x-1/2 top-full mt-1 w-72 rounded-xl border border-white/[0.08] bg-[#060b18]/98 backdrop-blur-xl shadow-2xl shadow-black/50 p-1.5 z-50"
        >
          {items.map((it) => (
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
          ))}
        </div>
      )}
    </div>
  );
}


export default function LandingNav() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [mobileExpanded, setMobileExpanded] = useState<string | null>(null);
  const [isAuthed, setIsAuthed] = useState(false);

  // Single "which dropdown is open" state shared by every desktop
  // dropdown. Opening one auto-closes any other; click-outside &
  // ESC close whatever is open. Hover uses a 120ms grace timer so
  // the user can move pointer between trigger and panel without
  // flicker.
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const desktopNavRef = useRef<HTMLDivElement | null>(null);
  const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // SSR renders the logged-out variant (no token on the server) and
  // the client re-renders to "Open dashboard" once mount detects a
  // valid session — avoids hydration mismatch + the "click Sign in
  // while logged in → see login form" footgun.
  useEffect(() => {
    setIsAuthed(isLoggedIn());
  }, []);

  // Click-outside + ESC close the open dropdown. Single listener for
  // the whole nav (lifted from per-dropdown to here when we made
  // openMenu a single shared value).
  useEffect(() => {
    if (!openMenu) return;
    const onClick = (e: MouseEvent) => {
      if (desktopNavRef.current && !desktopNavRef.current.contains(e.target as Node)) {
        setOpenMenu(null);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpenMenu(null);
    };
    document.addEventListener("mousedown", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [openMenu]);

  const cancelClose = () => {
    if (closeTimer.current) {
      clearTimeout(closeTimer.current);
      closeTimer.current = null;
    }
  };
  const scheduleClose = () => {
    cancelClose();
    closeTimer.current = setTimeout(() => setOpenMenu(null), 120);
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

        {/* Desktop nav */}
        <nav ref={desktopNavRef} className="hidden md:flex items-center gap-6">
          {nav.map((item) =>
            item.kind === "dropdown" ? (
              <DropdownDesktop
                key={item.label}
                label={item.label}
                items={item.items}
                isOpen={openMenu === item.label}
                onOpen={() => { cancelClose(); setOpenMenu(item.label); }}
                onClose={() => { cancelClose(); setOpenMenu(null); }}
                onHoverOpen={() => { cancelClose(); setOpenMenu(item.label); }}
                onHoverClose={scheduleClose}
              />
            ) : (
              <Link
                key={item.label}
                href={item.href}
                onClick={() => setOpenMenu(null)}
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
                      {item.items.map((sub) => (
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
                      ))}
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
