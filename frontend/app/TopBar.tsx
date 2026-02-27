// app/TopBar.tsx
"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { isLoggedIn } from "./lib/auth";
import { useOrg } from "./(authenticated)/contexts/OrgContext";

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
        Bolt<span className="text-[#14b8a6]">Edge</span>
      </span>
      <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">EASM</span>
    </Link>
  );
}

/** Rendered inside OrgProvider (authenticated pages) — safe to call useOrg() */
function AuthTopBarContent() {
  const { organization, planLabel, isTrialing, trialDaysRemaining } = useOrg();

  return (
    <>
      <div className="flex items-center">
        <BrandLogo />
      </div>
      {organization && (
        <div className="flex flex-col items-end">
          <span className="text-sm text-muted-foreground font-medium">{organization.name}</span>
          <div className="flex items-center gap-1.5">
            {planLabel && (
              <span className="text-[10px] text-muted-foreground/50">{planLabel}</span>
            )}
            {isTrialing && trialDaysRemaining !== null && (
              <span className="text-[10px] font-semibold text-[#ff8800]">
                · {trialDaysRemaining}d trial
              </span>
            )}
          </div>
        </div>
      )}
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