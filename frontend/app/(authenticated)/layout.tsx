// app/(authenticated)/layout.tsx
"use client";

import React, { useEffect, useState, Suspense } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { getAccessToken, getImpersonating, stopImpersonation, type ImpersonatingInfo } from "../lib/auth";
import { useSessionGuard } from "../lib/useSessionGuard";
import { OrgProvider } from "./contexts/OrgContext";
import Sidebar from "../Sidebar";
import TopBar from "../TopBar";
import { getAnnouncements, getSubscriptionStatus, createPortalSession, type SubscriptionStatus } from "../lib/api";
import { BILLING_ENABLED } from "../lib/billing-config";
import { Info, AlertTriangle, AlertOctagon, X, ExternalLink, CreditCard, Clock } from "lucide-react";

const KIND_ICON = { info: Info, warning: AlertTriangle, critical: AlertOctagon };
const KIND_STYLE = {
  info: "bg-teal-500/10 border-teal-500/20 text-teal-200",
  warning: "bg-amber-500/10 border-amber-500/20 text-amber-200",
  critical: "bg-red-500/10 border-red-500/20 text-red-200",
};
const DISMISSED_KEY = "asm_dismissed_announcements";

function AnnouncementBanners() {
  const [items, setItems] = useState<any[]>([]);

  useEffect(() => {
    getAnnouncements().then((res) => {
      const dismissed: number[] = (() => {
        try { return JSON.parse(localStorage.getItem(DISMISSED_KEY) || "[]"); } catch { return []; }
      })();
      setItems((res.announcements || []).filter((a: any) => !dismissed.includes(a.id)));
    }).catch(() => {});
  }, []);

  function dismiss(id: number) {
    setItems((prev) => prev.filter((a) => a.id !== id));
    try {
      const dismissed: number[] = JSON.parse(localStorage.getItem(DISMISSED_KEY) || "[]");
      dismissed.push(id);
      localStorage.setItem(DISMISSED_KEY, JSON.stringify(dismissed));
    } catch {}
  }

  if (!items.length) return null;

  return (
    <div className="shrink-0">
      {items.map((a) => {
        const Icon = KIND_ICON[a.kind as keyof typeof KIND_ICON] || Info;
        const style = KIND_STYLE[a.kind as keyof typeof KIND_STYLE] || KIND_STYLE.info;
        return (
          <div key={a.id} className={`border-b px-6 py-2.5 flex items-start gap-3 ${style}`}>
            <Icon className="w-4 h-4 mt-0.5 shrink-0 opacity-80" />
            <div className="flex-1 min-w-0">
              <span className="text-sm font-semibold">{a.title}</span>
              {a.body && <span className="ml-2 text-xs opacity-70">{a.body}</span>}
              {a.linkUrl && (
                <a
                  href={a.linkUrl}
                  target={a.linkUrl.startsWith("/") ? undefined : "_blank"}
                  rel={a.linkUrl.startsWith("/") ? undefined : "noopener noreferrer"}
                  className="ml-2 inline-flex items-center gap-1 text-xs underline underline-offset-2 hover:opacity-80"
                >
                  View<ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>
            <button onClick={() => dismiss(a.id)} className="shrink-0 opacity-50 hover:opacity-100 transition-opacity">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
}

/**
 * Billing status banner — shown when the org's Stripe subscription
 * needs the user's attention.
 *
 *   past_due           → red "Payment failed — update your card"
 *   cancel_at_period_end → amber "Subscription ends on {date} — Reactivate"
 *
 * Both link to the Stripe Customer Portal where the action is taken.
 * Phase 1 routes everything through the Portal; Phase 2 may bring
 * cancel/reactivate buttons in-app.
 */
function BillingStatusBanner() {
  const [sub, setSub] = useState<SubscriptionStatus | null>(null);
  const [opening, setOpening] = useState(false);

  useEffect(() => {
    if (!BILLING_ENABLED) return;
    getSubscriptionStatus().then(setSub).catch(() => {});
  }, []);

  async function openPortal() {
    try {
      setOpening(true);
      const res = await createPortalSession();
      window.location.href = res.url;
    } catch {
      setOpening(false);
    }
  }

  if (!BILLING_ENABLED || !sub) return null;

  const isPastDue = sub.subscriptionStatus === "past_due";
  const isCancelling = sub.cancelAtPeriodEnd && sub.subscriptionStatus !== "canceled";

  if (!isPastDue && !isCancelling) return null;

  const periodEnd = sub.currentPeriodEnd
    ? new Date(sub.currentPeriodEnd).toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      })
    : null;

  const style = isPastDue
    ? "bg-red-500/10 border-red-500/20 text-red-200"
    : "bg-amber-500/10 border-amber-500/20 text-amber-200";
  const Icon = isPastDue ? AlertOctagon : Clock;

  return (
    <div className={`border-b px-6 py-2.5 flex items-center justify-between gap-3 shrink-0 ${style}`}>
      <div className="flex items-center gap-3 min-w-0">
        <Icon className="w-4 h-4 shrink-0 opacity-80" />
        <div className="text-sm min-w-0">
          {isPastDue ? (
            <>
              <span className="font-semibold">Payment failed.</span>
              <span className="ml-2 opacity-80">
                Update your payment method to keep your subscription active — Stripe will retry automatically once a valid card is on file.
              </span>
            </>
          ) : (
            <>
              <span className="font-semibold">
                Subscription ends{periodEnd ? ` on ${periodEnd}` : " at the end of the billing period"}.
              </span>
              <span className="ml-2 opacity-80">
                You can reactivate any time before then to keep your current plan.
              </span>
            </>
          )}
        </div>
      </div>
      <button
        onClick={openPortal}
        disabled={opening}
        className="shrink-0 inline-flex items-center gap-1.5 text-xs font-medium border border-current/30 px-2.5 py-1 rounded-lg hover:bg-current/10 transition-colors disabled:opacity-50"
      >
        <CreditCard className="w-3.5 h-3.5" />
        {opening ? "Opening…" : isPastDue ? "Update payment" : "Reactivate"}
      </button>
    </div>
  );
}

function ImpersonationBanner({ info }: { info: ImpersonatingInfo }) {
  return (
    <div className="bg-amber-500/10 border-b border-amber-500/20 px-6 py-2 flex items-center justify-between shrink-0">
      <span className="text-xs text-amber-300">
        Impersonating{" "}
        <span className="font-semibold">{info.name || info.email}</span>
        {info.name && <span className="text-amber-300/60 ml-1.5">({info.email})</span>}
        <span className="ml-2 text-amber-400/50">— changes you make are real</span>
      </span>
      <button
        onClick={() => { stopImpersonation(); window.location.href = "/admin/users"; }}
        className="text-xs text-amber-300 hover:text-white border border-amber-500/30 px-2.5 py-1 rounded-lg hover:bg-amber-500/10 transition-colors"
      >
        Exit impersonation
      </button>
    </div>
  );
}

function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [checked, setChecked] = useState(false);
  const [impersonating, setImpersonating] = useState<ImpersonatingInfo | null>(null);

  useEffect(() => {
    const token = getAccessToken();
    if (!token) {
      const qs = searchParams?.toString();
      const fullPath = qs ? `${pathname}?${qs}` : pathname;
      router.replace(`/login?next=${encodeURIComponent(fullPath)}`);
      return;
    }
    setImpersonating(getImpersonating());
    setChecked(true);
  }, [router, pathname, searchParams]);

  useSessionGuard();

  if (!checked) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-sm text-muted-foreground">Loading…</div>
      </div>
    );
  }

  return (
    <OrgProvider>
      <div className="min-h-screen bg-background flex">
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0">
          <TopBar />
          {impersonating && <ImpersonationBanner info={impersonating} />}
          <BillingStatusBanner />
          <AnnouncementBanners />
          {children}
        </div>
      </div>
    </OrgProvider>
  );
}

export default function AuthenticatedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-background flex items-center justify-center">
          <div className="text-sm text-muted-foreground">Loading…</div>
        </div>
      }
    >
      <AuthGuard>{children}</AuthGuard>
    </Suspense>
  );
}