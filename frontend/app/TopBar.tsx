// app/TopBar.tsx
"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ChevronDown, Sparkles, UserCircle, LogOut, Search, Zap } from "lucide-react";
import { isLoggedIn, logout } from "./lib/auth";
import { useOrg } from "./(authenticated)/contexts/OrgContext";
import { BILLING_ENABLED } from "./lib/billing-config";
import { replayOnboardingTour } from "./ui/OnboardingTour";

function BoltIcon({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" className="shrink-0">
      <rect width="32" height="32" rx="7" fill="#0a0f1e"/>
      <path d="M17.5 4L9.5 17H14.5L13 28L21.5 14.5H16L17.5 4Z" fill="#14b8a6"/>
    </svg>
  );
}

function BrandLogo() {
  return (
    <Link href="/dashboard" className="flex items-center gap-2">
      <BoltIcon size={26} />
      <span className="font-semibold text-foreground">
        Nano<span className="text-[#14b8a6]">EASM</span>
      </span>
    </Link>
  );
}

/** Initials from a name or email — used as the avatar fallback. */
function userInitials(user: { name?: string; email: string } | null | undefined): string {
  if (!user) return "?";
  const source = (user.name || user.email || "").trim();
  if (!source) return "?";
  const parts = source.split(/[\s@]+/).filter(Boolean);
  if (parts.length === 0) return "?";
  const first = parts[0]?.[0] || "";
  const second = parts.length > 1 ? parts[1][0] : "";
  return (first + second).toUpperCase() || "?";
}

/** User menu in the TopBar — hosts replay-tour + the small set of
 *  cross-cutting actions that don't belong in the sidebar (which is
 *  navigation-first). Closes on outside-click and Escape. */
function UserMenu() {
  const { user } = useOrg();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);

  // Close on outside-click + Escape.
  useEffect(() => {
    if (!open) return;
    function onPointer(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 rounded-full p-0.5 pr-1.5 hover:bg-accent/30 transition-colors"
        title={user?.name || user?.email || "Account"}
      >
        <span className="w-7 h-7 rounded-full bg-primary/15 border border-primary/25 flex items-center justify-center text-[11px] font-semibold text-primary">
          {userInitials(user)}
        </span>
        <ChevronDown className={`w-3 h-3 text-muted-foreground transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      {open && (
        <div
          role="menu"
          className="absolute right-0 top-full mt-1.5 w-56 rounded-xl border border-border bg-popover shadow-2xl py-1.5 z-50"
        >
          {/* Header — name/email so the user knows which account they're acting on */}
          <div className="px-3 pb-2 mb-1 border-b border-border/60">
            <div className="text-sm font-medium text-foreground truncate">
              {user?.name || user?.email || "Signed in"}
            </div>
            {user?.name && user.email && (
              <div className="text-[11px] text-muted-foreground truncate">{user.email}</div>
            )}
          </div>

          <button
            type="button"
            role="menuitem"
            onClick={() => { setOpen(false); replayOnboardingTour(); }}
            className="w-full flex items-center gap-2 px-3 py-2 text-sm text-foreground hover:bg-accent/30 transition-colors text-left"
          >
            <Sparkles className="w-3.5 h-3.5 text-primary shrink-0" />
            Replay tour
          </button>

          <Link
            href="/settings/account"
            role="menuitem"
            onClick={() => setOpen(false)}
            className="w-full flex items-center gap-2 px-3 py-2 text-sm text-foreground hover:bg-accent/30 transition-colors"
          >
            <UserCircle className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
            Account & Team
          </Link>

          <div className="my-1 border-t border-border/60" />

          <button
            type="button"
            role="menuitem"
            onClick={() => { setOpen(false); logout(); }}
            className="w-full flex items-center gap-2 px-3 py-2 text-sm text-foreground hover:bg-accent/30 transition-colors text-left"
          >
            <LogOut className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
            Logout
          </button>
        </div>
      )}
    </div>
  );
}

/** Search input shown in the authenticated TopBar. Enter routes to the
 *  Assets page with the query pre-filled — the most useful first-hop for
 *  "I want to find X". Cmd/Ctrl-K focuses the input from anywhere. */
function GlobalSearch() {
  const router = useRouter();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [value, setValue] = useState("");
  const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        inputRef.current?.focus();
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const q = value.trim();
    if (!q) return;
    router.push(`/assets?q=${encodeURIComponent(q)}`);
  }

  return (
    <form onSubmit={onSubmit} className="relative w-full max-w-md">
      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
      <input
        ref={inputRef}
        type="text"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="Search assets, findings…"
        aria-label="Search"
        className="w-full h-9 pl-9 pr-14 rounded-lg border border-border bg-background/40 text-sm text-foreground placeholder:text-muted-foreground/60 outline-none focus:border-primary/40 focus:bg-background/60 transition-colors"
      />
      <kbd className="hidden md:inline-flex absolute right-2 top-1/2 -translate-y-1/2 items-center px-1.5 py-0.5 rounded border border-border bg-muted/20 text-[10px] text-muted-foreground font-mono pointer-events-none">
        {isMac ? "⌘K" : "Ctrl K"}
      </kbd>
    </form>
  );
}

/** Rendered inside OrgProvider (authenticated pages) — safe to call useOrg() */
function AuthTopBarContent() {
  const { organization, planLabel, isTrialing, trialDaysRemaining } = useOrg();

  return (
    <>
      <div className="flex items-center flex-shrink-0">
        <BrandLogo />
      </div>

      {/* Middle: global search — sits in the previously-empty horizontal void */}
      <div className="flex-1 flex items-center justify-center px-6 max-w-2xl mx-auto">
        <GlobalSearch />
      </div>

      <div className="flex items-center gap-3 flex-shrink-0">
        {/* Scan now — the single most-likely action from anywhere in the app */}
        <Link
          href="/scan/initiate"
          className="hidden md:inline-flex items-center gap-1.5 h-9 px-3 rounded-lg bg-primary/10 hover:bg-primary/20 text-primary text-sm font-medium border border-primary/20 transition-colors"
          title="Start a new scan"
        >
          <Zap className="w-3.5 h-3.5" />
          <span className="hidden lg:inline">Scan now</span>
        </Link>

        {organization && (
          <div className="hidden sm:flex flex-col items-end">
            <span className="text-sm text-muted-foreground font-medium">{organization.name}</span>
            <div className="flex items-center gap-1.5">
              {planLabel && (
                <span className="text-[10px] text-muted-foreground/50">{planLabel}</span>
              )}
              {BILLING_ENABLED && isTrialing && trialDaysRemaining !== null && (
                <span className="text-[10px] font-semibold text-[#ff8800]">
                  · {trialDaysRemaining}d trial
                </span>
              )}
            </div>
          </div>
        )}
        <UserMenu />
      </div>
    </>
  );
}

/** Rendered outside OrgProvider (login, register, landing) — no useOrg() */
function UnauthTopBarContent() {
  const pathname = usePathname();

  return (
    <>
      <div className="flex items-center gap-3">
        <BrandLogo />
      </div>
      <div className="flex items-center gap-3">
        <Link
          href="/login"
          className={`text-sm ${pathname === "/login" ? "text-foreground" : "text-muted-foreground"} hover:text-foreground`}
        >
          Login
        </Link>
        <Link
          href="/register"
          className={`text-sm ${pathname === "/register" ? "text-foreground" : "text-muted-foreground"} hover:text-foreground`}
        >
          Register
        </Link>
        <Link
          href="/dashboard"
          className="rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
        >
          Manage Assets
        </Link>
      </div>
    </>
  );
}

export default function TopBar() {
  const authed = isLoggedIn();

  return (
    <header className="sticky top-0 z-40 border-b border-border bg-background/80 backdrop-blur">
      <div className="flex h-14 items-center justify-between px-6">
        {authed ? <AuthTopBarContent /> : <UnauthTopBarContent />}
      </div>
    </header>
  );
}