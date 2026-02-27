// app/(authenticated)/layout.tsx
"use client";

import React, { useEffect, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { getAccessToken } from "../lib/auth";
import { useSessionGuard } from "../lib/useSessionGuard";
import { OrgProvider } from "./contexts/OrgContext";
import Sidebar from "../Sidebar";
import TopBar from "../TopBar";

export default function AuthenticatedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [checked, setChecked] = useState(false);

  // Check auth token on mount
  useEffect(() => {
    const token = getAccessToken();
    if (!token) {
      const qs = searchParams?.toString();
      const fullPath = qs ? `${pathname}?${qs}` : pathname;
      router.replace(`/login?next=${encodeURIComponent(fullPath)}`);
      return;
    }
    setChecked(true);
  }, [router, pathname, searchParams]);

  // Redirect to login if session expires while on page
  useSessionGuard();

  // Wait for auth check before rendering anything
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
          {children}
        </div>
      </div>
    </OrgProvider>
  );
}