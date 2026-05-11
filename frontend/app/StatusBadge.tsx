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
    "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold border";

  const styles: Record<string, string> = {
    completed: "bg-emerald-500/15 border-emerald-500/40 text-emerald-300",
    running: "bg-blue-500/15 border-blue-500/40 text-blue-300",
    queued: "bg-slate-500/15 border-slate-500/40 text-slate-200",
    failed: "bg-red-500/15 border-red-500/40 text-red-300",
  };

  // Status-coloured dot prefix. Running pulses so live work feels alive;
  // others are static. Cheaper visual cue than re-introducing icons,
  // works in any column width.
  const dotColors: Record<string, string> = {
    completed: "bg-emerald-400",
    running: "bg-blue-400 animate-pulse",
    queued: "bg-slate-400",
    failed: "bg-red-400",
  };

  const label =
    s === "completed"
      ? "Scanned"
      : s === "running"
      ? "Scanning"
      : s === "queued"
      ? "Queued"
      : s === "failed"
      ? "Failed"
      : (status || "Unknown");

  return (
    <span className={cn(base, styles[s] ?? "bg-muted/30 border-border text-muted-foreground", className)}>
      <span className={cn("w-1.5 h-1.5 rounded-full", dotColors[s] ?? "bg-muted-foreground")} />
      {label}
    </span>
  );
}
