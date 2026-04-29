// app/(authenticated)/layout.tsx
"use client";

import React, { useEffect, useState, Suspense } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { getAccessToken, getImpersonating, stopImpersonation, type ImpersonatingInfo } from "../lib/auth";
import { useSessionGuard } from "../lib/useSessionGuard";
import { OrgProvider } from "./contexts/OrgContext";
import Sidebar from "../Sidebar";
import TopBar from "../TopBar";
import { getAnnouncements } from "../lib/api";
import { Info, AlertTriangle, AlertOctagon, X } from "lucide-react";

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