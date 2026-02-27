// FILE: app/(authenticated)/discovery/discovery-components.tsx
"use client";
import React from "react";
import {
  Globe, Network, Server, CheckCircle2, Clock, XCircle, Loader2,
  Cloud, Link2, Shield,
} from "lucide-react";

export function cn(...p: Array<string | false | null | undefined>) { return p.filter(Boolean).join(" "); }

export function timeAgo(iso?: string | null): string {
  if (!iso) return "";
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

const STATUS_CFG: Record<string, { label: string; cls: string; spinning?: boolean }> = {
  pending: { label: "Pending", cls: "text-slate-400" },
  running: { label: "Running", cls: "text-[#00b8d4]", spinning: true },
  completed: { label: "Completed", cls: "text-[#10b981]" },
  partial: { label: "Partial", cls: "text-amber-400" },
  failed: { label: "Failed", cls: "text-red-400" },
  cancelled: { label: "Cancelled", cls: "text-slate-500" },
};

export const TYPE_COLORS: Record<string, string> = {
  domain: "bg-blue-500/10 text-blue-400",
  subdomain: "bg-[#00b8d4]/10 text-[#00b8d4]",
  ip: "bg-[#ffcc00]/10 text-[#ffcc00]",
  ip_range: "bg-violet-500/10 text-violet-400",
  cloud: "bg-orange-500/10 text-orange-400",
  url: "bg-emerald-500/10 text-emerald-400",
};

export const TYPE_ICONS: Record<string, React.ElementType> = {
  domain: Globe, subdomain: Network, ip: Server,
  ip_range: Shield, cloud: Cloud, url: Link2,
};

export function StatusBadge({ status }: { status: string }) {
  const c = STATUS_CFG[status] || STATUS_CFG.pending;
  const Icon = c.spinning ? Loader2 : status === "completed" ? CheckCircle2 : status === "failed" ? XCircle : Clock;
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold", c.cls)}>
      <Icon className={cn("w-3 h-3", c.spinning && "animate-spin")} />{c.label}
    </span>
  );
}

export function TypeBadge({ type }: { type: string }) {
  const Icon = TYPE_ICONS[type] || Globe;
  return (
    <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold uppercase", TYPE_COLORS[type] || "bg-muted/30 text-muted-foreground")}>
      <Icon className="w-3 h-3" />{type.replace("_", " ")}
    </span>
  );
}