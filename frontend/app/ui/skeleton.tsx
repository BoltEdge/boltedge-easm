// app/ui/skeleton.tsx
// Reusable shimmer skeleton components for loading states
// Uses a gradient sweep animation for a clearly visible "loading" effect
"use client";

import React, { useEffect } from "react";

function cn(...c: Array<string | false | null | undefined>) {
  return c.filter(Boolean).join(" ");
}

/* ── Shimmer keyframes — injected once into <head> ── */

const SHIMMER_CSS = `
@keyframes skeleton-shimmer {
  0% { background-position: -600px 0; }
  100% { background-position: 600px 0; }
}
`;

let injected = false;
function useShimmerStyles() {
  useEffect(() => {
    if (injected) return;
    const el = document.createElement("style");
    el.setAttribute("data-skeleton-shimmer", "");
    el.textContent = SHIMMER_CSS;
    document.head.appendChild(el);
    injected = true;
  }, []);
}

/* ── Base shimmer block ── */

export function Skeleton({ className }: { className?: string }) {
  useShimmerStyles();
  return (
    <div
      className={cn("rounded-md", className)}
      style={{
        background:
          "linear-gradient(90deg, rgba(148,163,184,0.06) 0%, rgba(148,163,184,0.18) 40%, rgba(148,163,184,0.06) 80%)",
        backgroundSize: "1200px 100%",
        animation: "skeleton-shimmer 2s ease-in-out infinite",
      }}
    />
  );
}

/* ── Stat card skeleton ── */

export function StatCardSkeleton() {
  return (
    <div className="rounded-2xl border border-border bg-card/40 p-5">
      <div className="flex items-center gap-2 mb-3">
        <Skeleton className="h-9 w-9 rounded-xl" />
        <Skeleton className="h-3 w-20" />
      </div>
      <Skeleton className="h-8 w-16 mb-2" />
      <Skeleton className="h-3 w-32" />
    </div>
  );
}

/* ── Panel skeleton (chart area) ── */

export function PanelSkeleton({ height = "h-[320px]" }: { height?: string }) {
  return (
    <div className="rounded-2xl border border-border bg-card/40 overflow-hidden">
      <div className="px-5 py-4 border-b border-border flex items-center gap-2">
        <Skeleton className="h-4 w-4 rounded" />
        <Skeleton className="h-4 w-32" />
      </div>
      <div className="p-5">
        <Skeleton className={cn("w-full rounded-xl", height)} />
      </div>
    </div>
  );
}

/* ── Table row skeleton ── */

export function TableRowSkeleton({ columns = 4 }: { columns?: number }) {
  return (
    <tr>
      {Array.from({ length: columns }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <Skeleton className={cn("h-4", i === 0 ? "w-16" : i === 1 ? "w-48" : "w-24")} />
        </td>
      ))}
    </tr>
  );
}

/* ── Group card skeleton ── */

export function GroupCardSkeleton() {
  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden">
      <div className="h-1.5 bg-muted/20" />
      <div className="p-5">
        <div className="flex items-start gap-3 mb-4">
          <Skeleton className="w-10 h-10 rounded-lg" />
          <div className="flex-1">
            <Skeleton className="h-5 w-36 mb-2" />
            <Skeleton className="h-3 w-24" />
          </div>
        </div>
        <div className="flex items-center justify-between pt-3 border-t border-border">
          <div className="flex items-center gap-2">
            <Skeleton className="h-5 w-16 rounded-md" />
            <Skeleton className="h-3 w-20" />
          </div>
          <Skeleton className="h-3 w-16" />
        </div>
      </div>
    </div>
  );
}

/* ── Finding row skeleton ── */

export function FindingRowSkeleton() {
  return (
    <tr>
      <td className="px-4 py-3"><Skeleton className="h-6 w-16 rounded-md" /></td>
      <td className="px-4 py-3">
        <Skeleton className="h-4 w-64 mb-1.5" />
        <Skeleton className="h-3 w-40" />
      </td>
      <td className="px-4 py-3"><Skeleton className="h-5 w-16 rounded-md" /></td>
      <td className="px-4 py-3"><Skeleton className="h-4 w-32" /></td>
      <td className="px-4 py-3"><Skeleton className="h-4 w-24" /></td>
      <td className="px-4 py-3"><Skeleton className="h-3 w-20" /></td>
    </tr>
  );
}

/* ═══════════════════════════════════════════════════════════════
   COMPOSITE PAGE SKELETONS
   ═══════════════════════════════════════════════════════════════ */

/* ── Dashboard skeleton ── */

export function DashboardSkeleton() {
  return (
    <div className="flex-1 overflow-y-auto bg-background">
      <div className="p-6 lg:p-8 max-w-[1600px] mx-auto">
        {/* Header */}
        <div className="mb-8 flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3">
              <Skeleton className="h-6 w-6 rounded" />
              <Skeleton className="h-7 w-48" />
            </div>
            <Skeleton className="h-4 w-72 mt-2" />
          </div>
          <Skeleton className="h-9 w-28 rounded-lg" />
        </div>

        {/* Row 1: Exposure + Stats */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 mb-6">
          {/* Exposure gauge */}
          <div className="lg:col-span-1 rounded-2xl border border-border bg-card/40 p-5 flex flex-col items-center justify-center">
            <Skeleton className="h-3 w-24 mb-4" />
            <Skeleton className="h-20 w-32 rounded-xl" />
            <Skeleton className="h-3 w-28 mt-4" />
          </div>
          {/* 4 stat cards */}
          <div className="lg:col-span-4 grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCardSkeleton />
            <StatCardSkeleton />
            <StatCardSkeleton />
            <StatCardSkeleton />
          </div>
        </div>

        {/* Row 2: Two panels */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <PanelSkeleton height="h-[280px]" />
          <PanelSkeleton height="h-[300px]" />
        </div>

        {/* Row 3: Two panels */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <PanelSkeleton height="h-[260px]" />
          <PanelSkeleton height="h-[260px]" />
        </div>

        {/* Row 4: Three panels */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <PanelSkeleton height="h-[200px]" />
          <PanelSkeleton height="h-[200px]" />
          <PanelSkeleton height="h-[200px]" />
        </div>
      </div>
    </div>
  );
}

/* ── Assets page skeleton ── */

export function AssetsPageSkeleton() {
  return (
    <div className="flex-1 bg-background overflow-auto">
      <div className="p-8">
        {/* Header */}
        <div className="flex justify-between items-start mb-8 gap-6">
          <div>
            <Skeleton className="h-7 w-40 mb-2" />
            <Skeleton className="h-4 w-64" />
          </div>
          <div className="flex items-center gap-3">
            <Skeleton className="h-9 w-24 rounded-lg" />
            <Skeleton className="h-9 w-24 rounded-lg" />
            <Skeleton className="h-9 w-32 rounded-lg" />
          </div>
        </div>

        {/* Search */}
        <div className="mb-6">
          <Skeleton className="h-10 w-full max-w-lg rounded-lg" />
        </div>

        {/* Group cards grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <GroupCardSkeleton />
          <GroupCardSkeleton />
          <GroupCardSkeleton />
          <GroupCardSkeleton />
          <GroupCardSkeleton />
          <GroupCardSkeleton />
        </div>
      </div>
    </div>
  );
}

/* ── Findings page skeleton ── */

export function FindingsPageSkeleton() {
  return (
    <div className="flex-1 bg-background overflow-auto">
      <div className="p-8">
        {/* Header */}
        <div className="flex justify-between items-start mb-6">
          <div>
            <Skeleton className="h-7 w-48 mb-2" />
            <Skeleton className="h-4 w-36" />
          </div>
          <Skeleton className="h-9 w-28 rounded-lg" />
        </div>

        {/* Status pills */}
        <div className="flex gap-2 mb-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-8 w-24 rounded-lg" />
          ))}
        </div>

        {/* Severity pills */}
        <div className="flex gap-2 mb-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-8 w-20 rounded-lg" />
          ))}
        </div>

        {/* Category pills */}
        <div className="flex gap-2 mb-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-7 w-16 rounded-md" />
          ))}
        </div>

        {/* Search + filter */}
        <div className="flex items-center gap-3 mb-6">
          <Skeleton className="h-10 w-80 rounded-lg" />
          <Skeleton className="h-10 w-36 rounded-lg" />
        </div>

        {/* Table */}
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          {/* Header */}
          <div className="bg-muted/30 border-b border-border px-4 py-3 flex gap-4">
            <Skeleton className="h-4 w-4 rounded" />
            <Skeleton className="h-4 w-16" />
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-4 w-16" />
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-4 w-20" />
            <Skeleton className="h-4 w-24" />
          </div>
          {/* Rows */}
          <table className="w-full">
            <tbody className="divide-y divide-border">
              {Array.from({ length: 10 }).map((_, i) => (
                <FindingRowSkeleton key={i} />
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}