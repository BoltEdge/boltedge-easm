// app/(unauthenticated)/tools/ToolResultView.tsx
// Shared renderer for public-tool API responses. Used by both QuickToolsCard
// (landing-page) and the dedicated /tools page accordion.
"use client";

import React from "react";
import Link from "next/link";
import { AlertTriangle, ArrowRight, CheckCircle2, Info } from "lucide-react";

function cn(...c: Array<string | false | null | undefined>) {
  return c.filter(Boolean).join(" ");
}

const SEV_ICONS: Record<string, React.ReactNode> = {
  critical: <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />,
  high: <AlertTriangle className="w-3.5 h-3.5 text-orange-400 shrink-0" />,
  medium: <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 shrink-0" />,
  low: <Info className="w-3.5 h-3.5 text-blue-400 shrink-0" />,
  info: <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />,
};

function GradeBadge({ grade }: { grade?: string }) {
  if (!grade) return null;
  const g = grade.replace(/[+-]/g, "");
  const colors: Record<string, string> = {
    A: "from-emerald-500/30 to-emerald-500/10 text-emerald-400 border-emerald-500/30",
    B: "from-yellow-500/30 to-yellow-500/10 text-yellow-400 border-yellow-500/30",
    C: "from-orange-500/30 to-orange-500/10 text-orange-400 border-orange-500/30",
    D: "from-red-500/30 to-red-500/10 text-red-400 border-red-500/30",
    F: "from-red-500/40 to-red-500/15 text-red-300 border-red-500/40",
  };
  return <span className={cn("inline-flex items-center px-2.5 py-1 rounded-lg text-base font-bold border bg-gradient-to-b", colors[g] || colors.F)}>{grade}</span>;
}

export default function ToolResultView({ data }: { data: any }) {
  if (data?.error) return <p className="text-sm text-red-400">{data.error}</p>;
  const grade = data.grade;
  const issues: any[] = data.issues || [];
  const nonInfo = issues.filter((i: any) => i.severity !== "info");

  return (
    <div className="space-y-3">
      {grade && (<div className="flex items-center gap-3"><GradeBadge grade={grade} /><span className="text-sm text-muted-foreground">{nonInfo.length} issue{nonInfo.length !== 1 ? "s" : ""} found</span></div>)}
      {data.certificate && (
        <div className="space-y-1">
          <div className="text-xs text-muted-foreground">Issued by <span className="text-foreground/70">{data.certificate.issuer}</span></div>
          {data.certificate.daysUntilExpiry !== undefined && <div className={cn("text-xs", data.certificate.daysUntilExpiry <= 30 ? "text-red-400" : "text-muted-foreground/60")}>Expires in {data.certificate.daysUntilExpiry} days</div>}
          {data.certificate.sans?.length > 0 && <div className="text-xs text-muted-foreground/40 font-mono truncate">SANs: {data.certificate.sans.slice(0, 3).join(", ")}{data.certificate.sans.length > 3 && ` +${data.certificate.sans.length - 3}`}</div>}
        </div>
      )}
      {data.totalFound !== undefined && (<div className="text-sm text-muted-foreground">Found <span className="text-foreground font-semibold">{data.totalFound}</span> certificate(s){data.coveredDomains?.length > 0 && <div className="text-xs text-muted-foreground/40 font-mono mt-1 truncate">{data.coveredDomains.slice(0, 4).join(", ")}{data.coveredDomains.length > 4 && ` +${data.coveredDomains.length - 4}`}</div>}</div>)}
      {data.resolvedIps?.length > 0 && <div className="text-xs text-muted-foreground font-mono">→ {data.resolvedIps.slice(0, 3).join(", ")}{data.resolvedIps.length > 3 && ` +${data.resolvedIps.length - 3} more`}</div>}
      {data.hostnames?.length > 0 && <div className="text-sm text-muted-foreground">→ {data.hostnames.slice(0, 3).join(", ")}{data.hostnames.length > 3 && ` +${data.hostnames.length - 3} more`}</div>}
      {data.registration?.registrar && (
        <div className="space-y-0.5">
          <div className="text-xs text-muted-foreground">Registrar: <span className="text-foreground/70">{data.registration.registrar}</span></div>
          {data.registration.daysUntilExpiry !== undefined && <div className={cn("text-xs", data.registration.daysUntilExpiry <= 30 ? "text-red-400" : "text-muted-foreground/60")}>Expires in {data.registration.daysUntilExpiry} days</div>}
          {data.registration.nameservers?.length > 0 && <div className="text-xs text-muted-foreground/40 font-mono truncate">NS: {data.registration.nameservers.slice(0, 2).join(", ")}{data.registration.nameservers.length > 2 && ` +${data.registration.nameservers.length - 2}`}</div>}
        </div>
      )}
      {data.network?.orgName && <div className="text-xs text-muted-foreground">{data.network.orgName}{data.network.country && <span className="ml-1">· {data.network.country}</span>}{data.network.cidr && <span className="ml-1 font-mono">· {data.network.cidr}</span>}</div>}
      {data.asn?.name && <div className="text-xs text-muted-foreground">{data.asn.name}{data.asn.country && <span className="ml-1">· {data.asn.country}</span>}</div>}
      {data.headerSummary && Object.keys(data.headerSummary).length > 0 && (
        <div className="flex flex-wrap gap-1">
          {Object.entries(data.headerSummary).slice(0, 6).map(([alias, info]: [string, any]) => (
            <span key={alias} className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium border", (info as any).present ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-400" : "border-red-500/20 bg-red-500/5 text-red-400")}>
              {(info as any).present ? <CheckCircle2 className="w-2.5 h-2.5" /> : <AlertTriangle className="w-2.5 h-2.5" />}{alias}
            </span>
          ))}
        </div>
      )}
      {issues.length > 0 && (
        <div className="space-y-1.5">
          {issues.slice(0, 3).map((issue: any, i: number) => (<div key={i} className="flex items-start gap-2 text-xs">{SEV_ICONS[issue.severity] || SEV_ICONS.info}<span className="text-foreground/70">{issue.title}</span></div>))}
          {issues.length > 3 && <div className="text-xs text-muted-foreground/40 pl-5">+ {issues.length - 3} more</div>}
        </div>
      )}
      <div className="pt-2 border-t border-border">
        <Link href="/register" className="inline-flex items-center gap-2 text-xs font-medium text-teal-400 hover:text-teal-300 transition-colors">Sign up for full details <ArrowRight className="w-3 h-3" /></Link>
      </div>
    </div>
  );
}
