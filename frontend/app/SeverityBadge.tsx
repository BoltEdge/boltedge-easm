// app/SeverityBadge.tsx
"use client";

import React from "react";

export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "informational";

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const s = String(severity || "info").toLowerCase();
  const normalized: "critical" | "high" | "medium" | "low" | "info" =
    s === "informational" ? "info" :
    s === "critical" ? "critical" :
    s === "high" ? "high" :
    s === "medium" ? "medium" :
    s === "low" ? "low" :
    "info";

  const styles: Record<string, string> = {
    critical:
      "bg-purple-500/20 border border-purple-500/35 text-purple-100",
    high:
      "bg-red-500/20 border border-red-500/35 text-red-100",
    medium:
      "bg-amber-500/20 border border-amber-500/35 text-amber-100",
    low:
      "bg-yellow-500/15 border border-yellow-500/25 text-yellow-100",
    info:
      "bg-slate-400/10 border border-slate-400/20 text-slate-200",
  };

  return (
    <span
      className={[
        "inline-flex items-center rounded-md px-2.5 py-1 text-xs font-bold uppercase min-w-[90px] justify-center",
        styles[normalized],
      ].join(" ")}
    >
      {normalized === "info" ? "Informational" : normalized}
    </span>
  );
}
