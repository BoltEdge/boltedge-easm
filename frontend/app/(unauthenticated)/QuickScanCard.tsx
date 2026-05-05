"use client";

import { useMemo, useState } from "react";
import { Search } from "lucide-react";

import { quickScanAsset } from "../lib/api";

type Severity = "critical" | "high" | "medium" | "low" | "info";
type QuickScanFinding = { title?: string; name?: string; description?: string; ip?: string; port?: number; transport?: string; product?: string; version?: string; severity?: Severity | string; timestamp?: string; [k: string]: any; };
type QuickScanRawResponse = { status?: string; assetType?: string; assetValue?: string; summary?: { ips_scanned?: string[]; resolved_ips?: string[]; errors?: Array<{ ip: string; error: string }>; [k: string]: any; }; risk?: { maxSeverity?: string; totalFindings?: number; counts?: Record<string, number>; }; findings?: QuickScanFinding[]; maxSeverity?: string; totalFindings?: number; ipsScanned?: string[]; errors?: Array<{ ip: string; error: string }>; [k: string]: any; };
type QuickScanNormalized = { assetType: "domain" | "ip"; assetValue: string; maxSeverity: Severity; totalFindings: number; counts: Record<Severity, number>; ipsScanned: string[]; errors: Array<{ ip: string; error: string }>; findings: QuickScanFinding[]; };

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
function toSeverity(x: any): Severity { const s = String(x ?? "info").toLowerCase(); if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info") return s; return "info"; }

function MaxSeverityBadge({ severity }: { severity: Severity | string }) {
  const cls = useMemo(() => { const s = String(severity || "info").toLowerCase(); if (s === "critical") return "bg-red-500/15 text-red-300 border-red-500/30"; if (s === "high") return "bg-orange-500/15 text-orange-300 border-orange-500/30"; if (s === "medium") return "bg-yellow-500/15 text-yellow-200 border-yellow-500/30"; if (s === "low") return "bg-green-500/15 text-green-300 border-green-500/30"; return "bg-cyan-500/15 text-cyan-300 border-cyan-500/30"; }, [severity]);
  return (<span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium ${cls}`}><span className="inline-block h-2 w-2 rounded-full bg-current opacity-80" />Max: {String(severity || "info").toUpperCase()}</span>);
}

function SeverityPill({ label, value }: { label: Severity; value: number }) {
  const cls = useMemo(() => { const s = label.toLowerCase(); if (s === "critical") return "border-purple-500/35 text-purple-200 bg-purple-500/10"; if (s === "high") return "border-red-500/30 text-red-200 bg-red-500/10"; if (s === "medium") return "border-amber-500/30 text-amber-100 bg-amber-500/10"; if (s === "low") return "border-yellow-400/20 text-yellow-100 bg-yellow-400/5"; return "border-slate-400/20 text-slate-200 bg-slate-400/5"; }, [label]);
  return (<span className={`inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-xs ${cls}`}><span className="font-semibold uppercase">{label}</span><span className="font-mono">{value}</span></span>);
}

function SeverityBadge({ severity }: { severity: Severity | string }) {
  const s = toSeverity(severity);
  const base = "inline-flex items-center rounded-md border px-2.5 py-1 text-[11px] font-semibold uppercase min-w-[72px] justify-center";
  const styles: Record<Severity, string> = { critical: "bg-purple-500/20 border-purple-500/35 text-purple-100", high: "bg-red-500/15 border-red-500/30 text-red-200", medium: "bg-amber-500/15 border-amber-500/30 text-amber-100", low: "bg-yellow-400/10 border-yellow-400/20 text-yellow-100", info: "bg-slate-400/10 border-slate-400/20 text-slate-200" };
  return <span className={`${base} ${styles[s]}`}>{s}</span>;
}

function formatFindingTitle(f: QuickScanFinding) { const explicit = String(f.title || f.name || "").trim(); if (explicit) return explicit; const ip = f.ip ?? "—"; const port = f.port != null ? String(f.port) : "—"; const transport = (f.transport ?? "tcp").toLowerCase(); const product = String(f.product ?? "").trim(); const version = String(f.version ?? "").trim(); const pv = [product, version].filter(Boolean).join(" "); return pv ? `${ip} ${port}/${transport} ${pv}` : `${ip} ${port}/${transport}`; }
function formatFindingSubtitle(f: QuickScanFinding) { const product = String(f.product ?? "").trim(); const version = String(f.version ?? "").trim(); const pv = [product, version].filter(Boolean).join(" "); const parts: string[] = []; if (pv) parts.push(pv); const desc = String(f.description ?? "").trim(); if (!pv && desc) parts.push(desc.slice(0, 90)); return parts.join(" • "); }
function formatSeen(ts?: string) { if (!ts) return null; try { return new Date(ts).toLocaleString(); } catch { return ts; } }

export default function QuickScanCard() {
  const [type, setType] = useState<"domain" | "ip">("domain");
  const [value, setValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<QuickScanNormalized | null>(null);
  const canScan = value.trim().length > 0 && !loading;

  const onScan = async () => {
    if (!canScan) return;
    try {
      setLoading(true); setError(null); setResult(null);
      const res = (await quickScanAsset({ type, value: value.trim() })) as QuickScanRawResponse;
      const rawCounts = (res?.risk?.counts as Record<string, number> | undefined) ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      const normalized: QuickScanNormalized = {
        assetType: (((res?.assetType as any) ?? type) === "ip" ? "ip" : "domain"), assetValue: String(res?.assetValue ?? value.trim()),
        maxSeverity: toSeverity(res?.risk?.maxSeverity ?? res?.maxSeverity ?? "info"),
        totalFindings: typeof res?.risk?.totalFindings === "number" ? res.risk.totalFindings : typeof res?.totalFindings === "number" ? res.totalFindings : 0,
        counts: { critical: Number(rawCounts.critical ?? 0), high: Number(rawCounts.high ?? 0), medium: Number(rawCounts.medium ?? 0), low: Number(rawCounts.low ?? 0), info: Number(rawCounts.info ?? 0) },
        ipsScanned: Array.isArray(res?.summary?.ips_scanned) ? res.summary!.ips_scanned as string[] : Array.isArray(res?.summary?.resolved_ips) ? res.summary!.resolved_ips as string[] : Array.isArray(res?.ipsScanned) ? res.ipsScanned as string[] : [],
        errors: Array.isArray(res?.summary?.errors) ? res.summary!.errors as Array<{ ip: string; error: string }> : Array.isArray(res?.errors) ? res.errors as Array<{ ip: string; error: string }> : [],
        findings: Array.isArray(res?.findings) ? res.findings as QuickScanFinding[] : [],
      };
      if (normalized.totalFindings === 0 && normalized.findings.length > 0) normalized.totalFindings = normalized.findings.length;
      setResult(normalized);
    } catch (e: any) { setError(e?.message || "Quick scan failed"); }
    finally { setLoading(false); }
  };

  const ipsText = useMemo(() => { if (!result?.ipsScanned?.length) return "—"; return result.ipsScanned.join(", "); }, [result]);
  const findingsByIp = useMemo(() => {
    if (!result?.findings?.length) return [];
    const map = new Map<string, QuickScanFinding[]>();
    for (const f of result.findings) { const ip = String(f.ip ?? "—"); if (!map.has(ip)) map.set(ip, []); map.get(ip)!.push(f); }
    const sevIdx = (s: any) => SEV_ORDER.indexOf(toSeverity(s));
    const out = Array.from(map.entries()).map(([ip, list]) => ({ ip, list: [...list].sort((a, b) => { const d = sevIdx(a.severity) - sevIdx(b.severity); return d !== 0 ? d : (a.port ?? 99999) - (b.port ?? 99999); }) }));
    const scannedOrder = new Map<string, number>(); (result.ipsScanned ?? []).forEach((ip, idx) => scannedOrder.set(ip, idx));
    out.sort((a, b) => (scannedOrder.get(a.ip) ?? 9999) - (scannedOrder.get(b.ip) ?? 9999) || a.ip.localeCompare(b.ip));
    return out;
  }, [result]);

  return (
    <div className="rounded-2xl border border-border bg-card/40 backdrop-blur overflow-hidden h-full flex flex-col shadow-[0_0_80px_rgba(139,92,246,0.08)]">
      <div className="px-6 pt-6 pb-4">
        <div className="flex items-center gap-2 mb-1"><Search className="w-5 h-5 text-primary" /><h3 className="text-sm font-semibold text-foreground">Quick Asset Scan</h3></div>
        <p className="text-xs text-muted-foreground">Scan any domain or IP — no account needed</p>
      </div>
      <div className="px-6 pb-4">
        <div className="grid grid-cols-[100px_1fr] gap-2">
          <select value={type} onChange={(e) => setType(e.target.value as any)} className="h-10 w-full rounded-lg border border-border bg-background px-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/40"><option value="domain">Domain</option><option value="ip">IP</option></select>
          <input type="text" placeholder={type === "ip" ? "e.g., 8.8.8.8" : "e.g., example.com"} value={value} onChange={(e) => setValue(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") onScan(); }} className="h-10 w-full rounded-lg border border-border bg-background px-3 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/40" />
        </div>
        <button onClick={onScan} disabled={!canScan} className={`w-full mt-3 rounded-lg px-4 py-2.5 text-sm font-medium transition-all ${!canScan ? "bg-muted text-muted-foreground cursor-not-allowed" : "bg-primary text-primary-foreground hover:bg-primary/90"}`}>{loading ? "Scanning…" : "Scan now"}</button>
        <p className="mt-2 text-[11px] text-muted-foreground/60 text-center">Results are not saved unless you sign in</p>
      </div>
      {error && <div className="mx-6 mb-4 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">{error}</div>}
      <div className="px-6 pb-6 flex-1">
        <div className="rounded-xl border border-border bg-background/30 p-4 h-full flex flex-col">
          <div className="flex items-center justify-between gap-3 mb-3">
            <div className="text-xs font-semibold text-foreground">Scan results</div>
            {result ? <MaxSeverityBadge severity={result.maxSeverity} /> : <div className="text-[11px] text-muted-foreground">Run a scan to see results</div>}
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg border border-border bg-card/30 p-3"><div className="text-[11px] text-muted-foreground">Total findings</div><div className="mt-1 text-lg font-semibold text-foreground">{result ? result.totalFindings : "—"}</div></div>
            <div className="rounded-lg border border-border bg-card/30 p-3"><div className="text-[11px] text-muted-foreground">IPs scanned</div><div className="mt-1 text-sm font-mono text-foreground break-words">{ipsText}</div></div>
          </div>
          {result && <div className="mt-3 flex flex-wrap gap-1.5">{(["critical","high","medium","low","info"] as Severity[]).map((s) => <SeverityPill key={s} label={s} value={result.counts[s] ?? 0} />)}</div>}
          {result && result.findings.length > 0 && (
            <div className="mt-4 flex-1 overflow-auto">
              <div className="text-xs font-semibold text-foreground mb-2">Findings ({result.findings.length})</div>
              <div className="space-y-2">{findingsByIp.map(({ ip, list }) => (
                <details key={ip} className="rounded-lg border border-border bg-card/30 overflow-hidden" open={findingsByIp.length === 1}>
                  <summary className="cursor-pointer select-none px-3 py-2 flex items-center justify-between gap-2"><div className="min-w-0"><div className="text-xs font-semibold text-foreground font-mono truncate">{ip}</div><div className="text-[10px] text-muted-foreground">{list.length} service{list.length === 1 ? "" : "s"}</div></div><span className="text-[10px] text-muted-foreground">▾</span></summary>
                  <div className="border-t border-border divide-y divide-border">{list.map((f, idx) => (<div key={`${ip}-${idx}`} className="px-3 py-2 flex items-start gap-2"><SeverityBadge severity={String(f.severity ?? "info")} /><div className="min-w-0 flex-1"><div className="text-xs text-foreground font-semibold truncate">{formatFindingTitle(f)}</div>{formatFindingSubtitle(f) && <div className="mt-0.5 text-[10px] text-muted-foreground line-clamp-2">{formatFindingSubtitle(f)}</div>}{formatSeen(f.timestamp) && <div className="mt-0.5 text-[10px] text-muted-foreground/60">Seen: {formatSeen(f.timestamp)}</div>}</div></div>))}</div>
                </details>
              ))}</div>
            </div>
          )}
          {result && result.errors.length > 0 && (<div className="mt-3 rounded-lg border border-border bg-card/30 p-3"><div className="text-[10px] font-semibold text-foreground mb-1">Scan errors</div><ul className="space-y-0.5 text-[10px] text-muted-foreground">{result.errors.map((e, idx) => <li key={`${e.ip}-${idx}`} className="font-mono break-words">{e.ip}: {e.error}</li>)}</ul></div>)}
        </div>
      </div>
    </div>
  );
}