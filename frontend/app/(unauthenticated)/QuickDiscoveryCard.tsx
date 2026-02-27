"use client";

import { useMemo, useState } from "react";
import { Globe2 } from "lucide-react";

import { discoverDomainQuick, type QuickDiscoveryResponse } from "../lib/api";

type DiscoveryNormalized = { domain: string; counts: { ct: number; brute: number; subdomains: number; resolvedNames: number }; subdomains: string[]; apexIps: string[]; resolved: Record<string, string[]>; errors: Array<{ source: string; error: string }>; };

function safeNum(v: any, fallback = 0) { const n = Number(v); return Number.isFinite(n) ? n : fallback; }
function safeStr(v: any, fallback = "") { const s = String(v ?? "").trim(); return s || fallback; }

function Pill({ label, value }: { label: string; value: number | string }) {
  return <span className="inline-flex items-center gap-2 rounded-full border border-border bg-card/30 px-2.5 py-1 text-xs text-muted-foreground"><span className="font-semibold text-foreground">{label}</span><span className="font-mono">{value}</span></span>;
}

function normalizeDomainInput(v: string) { let d = (v || "").trim().toLowerCase(); d = d.replace(/^https?:\/\//, ""); d = d.split("/")[0] || d; d = d.split("?")[0] || d; d = d.replace(/^\*\./, ""); d = d.replace(/\.+$/, ""); return d; }

export default function QuickDiscoveryCard() {
  const [mode, setMode] = useState<"domain" | "org">("domain");
  const [value, setValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<DiscoveryNormalized | null>(null);

  const placeholder = useMemo(() => mode === "org" ? "e.g., Acme Corp (coming soon)" : "e.g., example.com", [mode]);
  const canRun = useMemo(() => !loading && mode !== "org" && normalizeDomainInput(value).length > 0, [loading, mode, value]);

  const onDiscover = async () => {
    if (!canRun) return;
    const domain = normalizeDomainInput(value);
    try {
      setLoading(true); setError(null); setResult(null);
      const res: QuickDiscoveryResponse = await discoverDomainQuick({ domain, useCt: true, useDnsBrute: true, includeApex: true, resolveIps: true });
      const status = String(res?.status ?? "").toLowerCase();
      if (status && status !== "completed") throw new Error(safeStr(res?.error) || safeStr(res?.details) || `Discovery status: ${status}`);
      setResult({
        domain: safeStr(res.domain, domain),
        counts: { ct: safeNum(res?.counts?.ct), brute: safeNum(res?.counts?.brute), subdomains: safeNum(res?.counts?.subdomains, Array.isArray(res?.subdomains) ? res.subdomains.length : 0), resolvedNames: safeNum(res?.counts?.resolvedNames) },
        subdomains: Array.isArray(res?.subdomains) ? res.subdomains as string[] : [],
        apexIps: Array.isArray(res?.apexIps) ? res.apexIps as string[] : [],
        resolved: res?.resolved && typeof res.resolved === "object" ? res.resolved as Record<string, string[]> : {},
        errors: Array.isArray(res?.errors) ? (res.errors as any[]).map((e) => ({ source: safeStr(e?.source, "unknown"), error: safeStr(e?.error, "error") })) : [],
      });
    } catch (e: any) { setError(e?.message || "Quick discovery failed"); }
    finally { setLoading(false); }
  };

  const topIpsText = useMemo(() => result?.apexIps?.length ? result.apexIps.join(", ") : "—", [result]);
  const subdomainPreview = useMemo(() => result?.subdomains?.slice(0, 60) || [], [result]);

  return (
    <div className="rounded-2xl border border-border bg-card/40 backdrop-blur overflow-hidden h-full flex flex-col shadow-[0_0_80px_rgba(6,182,212,0.10)]">
      <div className="px-6 pt-6 pb-4">
        <div className="flex items-center gap-2 mb-1"><Globe2 className="w-5 h-5 text-cyan-400" /><h3 className="text-sm font-semibold text-foreground">Quick Discovery</h3></div>
        <p className="text-xs text-muted-foreground">Discover subdomains and IPs — no account needed</p>
      </div>
      <div className="px-6 pb-4">
        <div className="grid grid-cols-[100px_1fr] gap-2">
          <select value={mode} onChange={(e) => setMode(e.target.value as any)} className="h-10 w-full rounded-lg border border-border bg-background px-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/40"><option value="domain">Domain</option><option value="org" disabled>Org (soon)</option></select>
          <input type="text" placeholder={placeholder} value={value} onChange={(e) => setValue(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") onDiscover(); }} className="h-10 w-full rounded-lg border border-border bg-background px-3 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/40" />
        </div>
        <button onClick={onDiscover} disabled={!canRun} className={`w-full mt-3 rounded-lg px-4 py-2.5 text-sm font-medium transition-all ${!canRun ? "bg-muted text-muted-foreground cursor-not-allowed" : "bg-cyan-600 text-white hover:bg-cyan-600/90"}`}>{loading ? "Discovering…" : "Discover assets"}</button>
        <p className="mt-2 text-[11px] text-muted-foreground/60 text-center">Sign in to see more results</p>
      </div>
      {mode === "org" && <div className="mx-6 mb-4 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">Organization discovery isn&apos;t wired yet. Use Domain for now.</div>}
      {error && <div className="mx-6 mb-4 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">{error}</div>}
      <div className="px-6 pb-6 flex-1">
        <div className="rounded-xl border border-border bg-background/30 p-4 h-full flex flex-col">
          <div className="flex items-center justify-between gap-3 mb-3">
            <div className="text-xs font-semibold text-foreground">Discovery results</div>
            {result ? <span className="text-[11px] text-muted-foreground font-mono truncate">{result.domain}</span> : <div className="text-[11px] text-muted-foreground">Run discovery to see results</div>}
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg border border-border bg-card/30 p-3"><div className="text-[11px] text-muted-foreground">Subdomains found</div><div className="mt-1 text-lg font-semibold text-foreground">{result ? result.counts.subdomains : "—"}</div></div>
            <div className="rounded-lg border border-border bg-card/30 p-3"><div className="text-[11px] text-muted-foreground">Apex IPs</div><div className="mt-1 text-sm font-mono text-foreground break-words">{result ? topIpsText : "—"}</div></div>
          </div>
          {result && <div className="mt-3 flex flex-wrap gap-1.5"><Pill label="Resolved" value={result.counts.resolvedNames} /></div>}
          {result && result.subdomains.length > 0 && (
            <div className="mt-4 flex-1 overflow-auto">
              <div className="text-xs font-semibold text-foreground mb-2">Subdomains ({result.subdomains.length})</div>
              <div className="rounded-lg border border-border bg-card/30 overflow-hidden">
                <div className="max-h-72 overflow-auto divide-y divide-border">
                  {subdomainPreview.map((name) => { const ips = result.resolved?.[name] || []; return (
                    <div key={name} className="px-3 py-2 flex items-start justify-between gap-2">
                      <div className="min-w-0"><div className="text-xs font-mono text-foreground truncate">{name}</div><div className="mt-0.5 text-[10px] text-muted-foreground">{ips.length > 0 ? <span className="font-mono">{ips.join(", ")}</span> : "No IPs resolved"}</div></div>
                      <button className="text-[10px] text-cyan-300 hover:text-cyan-200 border border-border rounded-md px-1.5 py-0.5 bg-background/20 shrink-0" onClick={async () => { try { await navigator.clipboard.writeText(name); } catch {} }} title="Copy">Copy</button>
                    </div>
                  ); })}
                </div>
                {result.subdomains.length > subdomainPreview.length && <div className="px-3 py-2 text-[10px] text-muted-foreground border-t border-border">Showing first {subdomainPreview.length} results</div>}
              </div>
            </div>
          )}
          {result && !result.subdomains.length && <div className="mt-4 text-xs text-muted-foreground">No subdomains returned.</div>}
          {result && result.errors.length > 0 && (<div className="mt-3 rounded-lg border border-border bg-card/30 p-3"><div className="text-[10px] font-semibold text-foreground mb-1">Discovery errors</div><ul className="space-y-0.5 text-[10px] text-muted-foreground">{result.errors.slice(0, 10).map((e, idx) => <li key={`${e.source}-${idx}`} className="break-words"><span className="font-mono">{e.source}:</span> {e.error}</li>)}</ul></div>)}
        </div>
      </div>
    </div>
  );
}