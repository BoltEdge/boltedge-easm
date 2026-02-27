// app/StatusBadge.tsx
"use client";

import React from "react";

type Props = {
  status: string;
  className?: string;
};

function cn(...classes: Array<string | undefined | null | false>) {
  return classes.filter(Boolean).join(" ");
}

export function StatusBadge({ status, className }: Props) {
  const raw = String(status || "").toLowerCase();

  // normalize common variants
  const s =
    raw === "scanning" || raw === "in_progress"
      ? "running"
      : raw === "not_scanned" || raw === "pending" || raw === "waiting"
      ? "queued"
      : raw;

  const base =
    "inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold border";

  const styles: Record<string, string> = {
    completed: "bg-emerald-500/15 border-emerald-500/40 text-emerald-300",
    running: "bg-blue-500/15 border-blue-500/40 text-blue-300",
    queued: "bg-slate-500/15 border-slate-500/40 text-slate-200",
    failed: "bg-red-500/15 border-red-500/40 text-red-300",
  };

  const label =
    s === "completed"
      ? "Completed"
      : s === "running"
      ? "Running"
      : s === "queued"
      ? "Queued"
      : s === "failed"
      ? "Failed"
      : (status || "Unknown");

  return (
    <span className={cn(base, styles[s] ?? "bg-muted/30 border-border text-muted-foreground", className)}>
      {label}
    </span>
  );
}
