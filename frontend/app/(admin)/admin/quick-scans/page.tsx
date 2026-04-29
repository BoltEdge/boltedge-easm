"use client";
import { useEffect, useState, useCallback } from "react";
import {
  getAdminQuickScans, getAdminBlockedIPs, blockAdminIP, unblockAdminIP,
} from "../../../lib/api";
import { Search, ShieldBan, ShieldCheck, ChevronLeft, ChevronRight, X, AlertTriangle } from "lucide-react";

const STATUS_STYLES: Record<string, string> = {
  completed:    "text-emerald-300 bg-emerald-500/10",
  failed:       "text-red-300 bg-red-500/10",
  blocked:      "text-red-400 bg-red-500/10",
  rate_limited: "text-amber-300 bg-amber-500/10",
};

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-400", high: "text-orange-400",
  medium: "text-amber-400", low: "text-blue-400", info: "text-gray-400",
};

function fmtTime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  const diff = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return d.toLocaleDateString();
}

function StatCard({ label, value, highlight }: { label: string; value: number; highlight?: boolean }) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] px-4 py-3 text-center">
      <div className={`text-2xl font-bold ${highlight && value > 0 ? "text-red-400" : "text-white"}`}>{value}</div>
      <div className="text-[11px] text-white/40 mt-0.5">{label}</div>
    </div>
  );
}

export default function AdminQuickScans() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [page, setPage] = useState(1);
  const [searchIP, setSearchIP] = useState("");
  const [searchTarget, setSearchTarget] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");

  // Block list state
  const [blocks, setBlocks] = useState<any[]>([]);
  const [showBlockForm, setShowBlockForm] = useState(false);
  const [blockIP, setBlockIP] = useState("");
  const [blockReason, setBlockReason] = useState("");
  const [blockExpiry, setBlockExpiry] = useState("");
  const [blockBusy, setBlockBusy] = useState(false);
  const [unblockBusy, setUnblockBusy] = useState<number | null>(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [scans, ips] = await Promise.all([
        getAdminQuickScans({ page, ip: searchIP || undefined, target: searchTarget || undefined, status: statusFilter || undefined, source: sourceFilter || undefined }),
        getAdminBlockedIPs(),
      ]);
      setData(scans);
      setBlocks(ips.blocks || []);
    } catch (e: any) {
      setError(e?.message || "Failed to load");
    } finally { setLoading(false); }
  }, [page, searchIP, searchTarget, statusFilter, sourceFilter]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [searchIP, searchTarget, statusFilter, sourceFilter]);
  useEffect(() => {
    if (banner) { const t = setTimeout(() => setBanner(null), 4000); return () => clearTimeout(t); }
  }, [banner]);

  async function handleBlock(e: React.FormEvent) {
    e.preventDefault();
    if (!blockIP.trim()) return;
    setBlockBusy(true);
    try {
      await blockAdminIP({
        ip: blockIP.trim(),
        reason: blockReason.trim() || undefined,
        expiresAt: blockExpiry ? new Date(blockExpiry).toISOString() : null,
      });
      setBanner({ kind: "ok", text: `IP ${blockIP.trim()} blocked.` });
      setBlockIP(""); setBlockReason(""); setBlockExpiry(""); setShowBlockForm(false);
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to block IP" });
    } finally { setBlockBusy(false); }
  }

  async function handleUnblock(b: any) {
    setUnblockBusy(b.id);
    try {
      await unblockAdminIP(b.id);
      setBanner({ kind: "ok", text: `IP ${b.ip} unblocked.` });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to unblock" });
    } finally { setUnblockBusy(null); }
  }

  // Pre-fill block form from a log row
  function prefillBlock(ip: string) {
    setBlockIP(ip); setShowBlockForm(true);
    setTimeout(() => document.getElementById("block-ip-input")?.focus(), 50);
  }

  const stats = data?.stats ?? {};
  const logs: any[] = data?.logs ?? [];
  const topIPs: any[] = data?.topIPs ?? [];

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Public Tool Monitor</h1>
          <p className="text-xs text-white/30 mt-0.5">Unauthenticated quick scan &amp; discovery activity · rate limits · IP block list</p>
        </div>
      </div>

      {banner && (
        <div className={`rounded-lg px-4 py-2.5 text-sm ${banner.kind === "ok" ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20" : "bg-red-500/10 text-red-300 border border-red-500/20"}`}>
          {banner.text}
        </div>
      )}

      {/* Stats row */}
      <div className="grid grid-cols-3 sm:grid-cols-5 gap-3">
        <StatCard label="Scans (24h)" value={stats.total24h ?? 0} />
        <StatCard label="Unique IPs (24h)" value={stats.uniqueIPs24h ?? 0} />
        <StatCard label="Rate limited (24h)" value={stats.rateLimited24h ?? 0} highlight />
        <StatCard label="Blocked attempts (24h)" value={stats.blocked24h ?? 0} highlight />
        <StatCard label="Blocked IPs" value={stats.totalBlockedIPs ?? 0} highlight />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Main log table */}
        <div className="lg:col-span-2 space-y-3">
          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative flex-1 min-w-[160px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/30" />
              <input value={searchIP} onChange={(e) => setSearchIP(e.target.value)}
                placeholder="Filter by IP…"
                className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg pl-8 pr-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40" />
            </div>
            <div className="relative flex-1 min-w-[160px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/30" />
              <input value={searchTarget} onChange={(e) => setSearchTarget(e.target.value)}
                placeholder="Filter by target…"
                className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg pl-8 pr-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40" />
            </div>
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500/40">
              <option value="">All statuses</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="rate_limited">Rate limited</option>
              <option value="blocked">Blocked</option>
            </select>
            <select value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)}
              className="bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500/40">
              <option value="">All sources</option>
              <option value="scan">Quick Scan</option>
              <option value="discovery">Discovery</option>
            </select>
          </div>

          <div className="rounded-xl border border-white/[0.06] overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-white/[0.06] bg-white/[0.02]">
                  <th className="text-left px-3 py-2.5 text-xs font-medium text-white/40">IP</th>
                  <th className="text-left px-3 py-2.5 text-xs font-medium text-white/40">Target</th>
                  <th className="text-left px-3 py-2.5 text-xs font-medium text-white/40">Type</th>
                  <th className="text-left px-3 py-2.5 text-xs font-medium text-white/40">Status</th>
                  <th className="text-left px-3 py-2.5 text-xs font-medium text-white/40">Result</th>
                  <th className="text-left px-3 py-2.5 text-xs font-medium text-white/40">When</th>
                  <th className="px-3 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={7} className="px-4 py-8 text-center text-white/30 text-xs">Loading…</td></tr>
                ) : !logs.length ? (
                  <tr><td colSpan={7} className="px-4 py-8 text-center text-white/30 text-xs">No records found.</td></tr>
                ) : logs.map((log) => {
                  const fc = log.findingCounts || {};
                  const isDiscovery = log.source === "discovery";
                  const hasCrit = (fc.critical || 0) > 0;
                  const hasHigh = (fc.high || 0) > 0;
                  return (
                    <tr key={log.id} className="border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors group">
                      <td className="px-3 py-2.5">
                        <span className="font-mono text-xs text-white/80">{log.ip}</span>
                      </td>
                      <td className="px-3 py-2.5">
                        <span className="text-xs text-white font-mono">{log.target}</span>
                        <span className="ml-1.5 text-[10px] text-white/30">{log.assetType}</span>
                      </td>
                      <td className="px-3 py-2.5">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${isDiscovery ? "text-cyan-300 bg-cyan-500/10" : "text-teal-300 bg-teal-500/10"}`}>
                          {isDiscovery ? "discovery" : "scan"}
                        </span>
                      </td>
                      <td className="px-3 py-2.5">
                        <span className={`text-[11px] px-1.5 py-0.5 rounded font-semibold ${STATUS_STYLES[log.status] || "text-white/40"}`}>
                          {log.status.replace("_", " ")}
                        </span>
                      </td>
                      <td className="px-3 py-2.5">
                        {log.status === "completed" ? (
                          isDiscovery ? (
                            <span className="text-[11px] text-cyan-300/70">
                              {(fc.subdomains ?? 0) > 0 ? `${fc.subdomains} subdomains` : "0 subdomains"}
                            </span>
                          ) : (
                            <div className="flex items-center gap-1 text-[11px]">
                              {["critical","high","medium","low"].filter(s => (fc[s]||0) > 0).map(s => (
                                <span key={s} className={SEV_COLORS[s]}>{fc[s]}{s[0].toUpperCase()}</span>
                              ))}
                              {!hasCrit && !hasHigh && !fc.medium && !fc.low ? <span className="text-white/25">clean</span> : null}
                            </div>
                          )
                        ) : <span className="text-white/20">—</span>}
                      </td>
                      <td className="px-3 py-2.5 text-white/40 text-xs">{fmtTime(log.createdAt)}</td>
                      <td className="px-3 py-2.5">
                        <button
                          onClick={() => prefillBlock(log.ip)}
                          title="Block this IP"
                          className="opacity-0 group-hover:opacity-100 transition-opacity p-1 rounded hover:bg-red-500/10 text-white/30 hover:text-red-400"
                        >
                          <ShieldBan className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {data && data.pages > 1 && (
            <div className="flex items-center justify-between text-xs text-white/40">
              <span>Page {data.page} of {data.pages} · {data.total} total</span>
              <div className="flex items-center gap-2">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                  className="p-1.5 rounded hover:bg-white/[0.04] disabled:opacity-30"><ChevronLeft className="w-4 h-4" /></button>
                <button onClick={() => setPage(p => Math.min(data.pages, p + 1))} disabled={page === data.pages}
                  className="p-1.5 rounded hover:bg-white/[0.04] disabled:opacity-30"><ChevronRight className="w-4 h-4" /></button>
              </div>
            </div>
          )}
        </div>

        {/* Sidebar: Top IPs + Block list */}
        <div className="space-y-4">
          {/* Top IPs */}
          {topIPs.length > 0 && (
            <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
              <h3 className="text-xs font-semibold text-white/40 uppercase tracking-wider mb-3">Top IPs — 24h</h3>
              <div className="space-y-1.5">
                {topIPs.map((row) => (
                  <div key={row.ip} className="flex items-center justify-between group">
                    <span className="font-mono text-xs text-white/70">{row.ip}</span>
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-semibold ${row.count >= 5 ? "text-red-400" : row.count >= 3 ? "text-amber-400" : "text-white/50"}`}>
                        {row.count}×
                      </span>
                      <button onClick={() => prefillBlock(row.ip)} title="Block IP"
                        className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 rounded hover:bg-red-500/10 text-white/30 hover:text-red-400">
                        <ShieldBan className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Block list */}
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-white/40 uppercase tracking-wider">Blocked IPs ({blocks.length})</h3>
              <button onClick={() => setShowBlockForm((v) => !v)}
                className="text-xs text-teal-400 hover:text-teal-300 transition-colors">
                {showBlockForm ? "Cancel" : "+ Block IP"}
              </button>
            </div>

            {showBlockForm && (
              <form onSubmit={handleBlock} className="mb-4 space-y-2 p-3 rounded-lg bg-white/[0.03] border border-white/[0.06]">
                <input id="block-ip-input" value={blockIP} onChange={(e) => setBlockIP(e.target.value)}
                  placeholder="IP address *" required
                  className="w-full bg-white/[0.04] border border-white/[0.08] rounded px-3 py-1.5 text-xs text-white placeholder:text-white/25 focus:outline-none focus:border-red-500/40" />
                <input value={blockReason} onChange={(e) => setBlockReason(e.target.value)}
                  placeholder="Reason (optional)"
                  className="w-full bg-white/[0.04] border border-white/[0.08] rounded px-3 py-1.5 text-xs text-white placeholder:text-white/25 focus:outline-none focus:border-red-500/40" />
                <input type="datetime-local" value={blockExpiry} onChange={(e) => setBlockExpiry(e.target.value)}
                  className="w-full bg-white/[0.04] border border-white/[0.08] rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-red-500/40" />
                <p className="text-[10px] text-white/25">Leave expiry blank for permanent block</p>
                <button type="submit" disabled={blockBusy || !blockIP.trim()}
                  className="w-full py-1.5 rounded text-xs bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition-colors disabled:opacity-40">
                  {blockBusy ? "Blocking…" : "Block IP"}
                </button>
              </form>
            )}

            {!blocks.length ? (
              <p className="text-xs text-white/25 text-center py-3">No blocked IPs.</p>
            ) : (
              <div className="space-y-2">
                {blocks.map((b) => (
                  <div key={b.id} className={`flex items-start gap-2 ${b.expired ? "opacity-40" : ""}`}>
                    <div className="flex-1 min-w-0">
                      <div className="font-mono text-xs text-white/80">{b.ip}</div>
                      {b.reason && <div className="text-[10px] text-white/30 truncate">{b.reason}</div>}
                      {b.expiresAt && (
                        <div className="text-[10px] text-white/25">
                          {b.expired ? "Expired" : `Expires ${fmtTime(b.expiresAt)}`}
                        </div>
                      )}
                    </div>
                    <button onClick={() => handleUnblock(b)} disabled={unblockBusy === b.id}
                      title="Unblock" className="shrink-0 p-1 rounded hover:bg-white/[0.06] text-white/30 hover:text-emerald-400 transition-colors disabled:opacity-30">
                      <ShieldCheck className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
