// app/(unauthenticated)/QuickToolsCard.tsx
"use client";

import React, { useState, useCallback } from "react";
import Link from "next/link";
import {
  Lock, Globe, Shield, FileText, RefreshCcw, Plug,
  ArrowRight, Loader2, AlertTriangle, CheckCircle2, Info, Server,
  LogIn,
} from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:5000";

function cn(...c: Array<string | false | null | undefined>) {
  return c.filter(Boolean).join(" ");
}

type ToolId = "cert-lookup" | "dns-lookup" | "header-check" | "whois" | "reverse-dns" | "connectivity-check";

interface ToolDef {
  id: ToolId;
  name: string;
  icon: React.ComponentType<{ className?: string }>;
  placeholder: string;
  inputField: string;
  color: string;
  authOnly?: boolean;
  authTeaser?: string;
}

const TOOLS: ToolDef[] = [
  { id: "cert-lookup", name: "Certificate", icon: Lock, placeholder: "example.com or SHA-256 hash", inputField: "__smart", color: "text-emerald-400" },
  { id: "dns-lookup", name: "DNS", icon: Globe, placeholder: "example.com", inputField: "domain", color: "text-cyan-400" },
  { id: "header-check", name: "Headers", icon: Shield, placeholder: "example.com", inputField: "domain", color: "text-amber-400" },
  { id: "whois", name: "WHOIS", icon: FileText, placeholder: "example.com / 8.8.8.8 / AS13335", inputField: "query", color: "text-rose-400" },
  { id: "reverse-dns", name: "Reverse DNS", icon: RefreshCcw, placeholder: "8.8.8.8", inputField: "ip", color: "text-purple-400" },
  { id: "connectivity-check", name: "Connectivity", icon: Plug, placeholder: "example.com:443", inputField: "host", color: "text-sky-400", authOnly: true, authTeaser: "Test TCP port reachability, latency, banner grabs, and TLS detection" },
];

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

function PublicResultView({ data }: { data: any }) {
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
            <span key={alias} className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium border", info.present ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-400" : "border-red-500/20 bg-red-500/5 text-red-400")}>
              {info.present ? <CheckCircle2 className="w-2.5 h-2.5" /> : <AlertTriangle className="w-2.5 h-2.5" />}{alias}
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

function AuthOnlyTeaser({ tool }: { tool: ToolDef }) {
  const Icon = tool.icon;
  return (
    <div className="flex flex-col items-center justify-center py-6 space-y-3">
      <div className="h-10 w-10 rounded-xl bg-sky-500/10 flex items-center justify-center">
        <Icon className="w-5 h-5 text-sky-400" />
      </div>
      <div className="text-center">
        <p className="text-sm text-foreground/70 mb-1">{tool.name} requires sign-in</p>
        {tool.authTeaser && <p className="text-xs text-muted-foreground/40">{tool.authTeaser}</p>}
      </div>
      <Link href="/register" className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium bg-gradient-to-r from-teal-500 to-cyan-500 text-white shadow-lg shadow-teal-500/20 hover:shadow-teal-500/30 hover:brightness-110 transition-all">
        <LogIn className="w-3.5 h-3.5" />Sign up free
      </Link>
    </div>
  );
}

export default function QuickToolsCard() {
  const [activeTool, setActiveTool] = useState<ToolId>("cert-lookup");
  const [inputValue, setInputValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const tool = TOOLS.find((t) => t.id === activeTool)!;

  const handleToolSwitch = useCallback((id: ToolId) => { setActiveTool(id); setInputValue(""); setResult(null); }, []);

  const handleSubmit = useCallback(async () => {
    const val = inputValue.trim();
    if (!val || tool.authOnly) return;
    setLoading(true); setResult(null);
    try {
      let endpoint: string; let body: Record<string, string>;
      if (activeTool === "cert-lookup") {
        const cleaned = val.replace(/[:\s]/g, "").toLowerCase();
        const isHash = /^[0-9a-f]{64}$/.test(cleaned);
        if (isHash) { endpoint = `${API_BASE}/tools/public/cert-hash`; body = { hash: cleaned }; }
        else { endpoint = `${API_BASE}/tools/public/cert-lookup`; body = { domain: val }; }
      } else { endpoint = `${API_BASE}/tools/public/${activeTool}`; body = { [tool.inputField]: val }; }
      const res = await fetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const data = await res.json();
      if (!res.ok && data.error) setResult({ error: data.error }); else setResult(data);
    } catch { setResult({ error: "Request failed. Please try again." }); }
    finally { setLoading(false); }
  }, [inputValue, activeTool, tool]);

  const emptyHint = (() => {
    if (tool.authOnly) return "";
    switch (tool.inputField) { case "__smart": return "Enter a domain or SHA-256 hash"; case "query": return "Enter a domain, IP, or ASN"; default: return `Enter a ${tool.inputField}`; }
  })();

  return (
    <div className="rounded-2xl border border-border bg-card/40 backdrop-blur overflow-hidden h-full flex flex-col shadow-[0_0_80px_rgba(20,184,166,0.08)]">
      {/* Header */}
      <div className="px-6 pt-6 pb-4">
        <div className="flex items-center gap-2 mb-1"><Server className="w-5 h-5 text-teal-400" /><h3 className="text-sm font-semibold text-foreground">LookUp Tools</h3></div>
        <p className="text-xs text-muted-foreground">Quick-check any domain or IP — no account needed</p>
      </div>

      {/* Tool selector pills */}
      <div className="px-6 pb-4 flex flex-wrap gap-1.5">
        {TOOLS.map((t) => {
          const Icon = t.icon;
          return (
            <button key={t.id} onClick={() => handleToolSwitch(t.id)}
              className={cn("inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium transition-all border",
                activeTool === t.id ? "border-teal-500/30 bg-teal-500/10 text-teal-300" : "border-border bg-card/30 text-muted-foreground hover:text-foreground hover:border-border")}>
              <Icon className="w-3.5 h-3.5" />{t.name}{t.authOnly && <Lock className="w-2.5 h-2.5 ml-0.5 opacity-50" />}
            </button>
          );
        })}
      </div>

      {/* Input — hidden for auth-only tools */}
      {!tool.authOnly && (
        <div className="px-6 pb-4">
          <div className="flex gap-2">
            <input type="text" value={inputValue} onChange={(e) => setInputValue(e.target.value)} onKeyDown={(e) => e.key === "Enter" && !loading && handleSubmit()}
              placeholder={tool.placeholder} disabled={loading}
              className="flex-1 rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/40 font-mono" />
            <button onClick={handleSubmit} disabled={loading || !inputValue.trim()}
              className={cn("rounded-lg px-4 py-2 text-sm font-medium transition-all shrink-0",
                loading || !inputValue.trim() ? "bg-muted text-muted-foreground cursor-not-allowed" : "bg-gradient-to-r from-teal-500 to-cyan-500 text-white shadow-lg shadow-teal-500/20 hover:shadow-teal-500/30 hover:brightness-110")}>
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
            </button>
          </div>
        </div>
      )}

      {/* Results */}
      <div className="px-6 pb-6 flex-1">
        {tool.authOnly ? <AuthOnlyTeaser tool={tool} /> : result ? <PublicResultView data={result} /> : (
          <div className="flex items-center justify-center h-20 text-xs text-muted-foreground/40">{emptyHint} and press Enter</div>
        )}
      </div>
    </div>
  );
}