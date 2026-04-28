"use client";
import { useEffect, useState, useCallback } from "react";
import { getAdminOrganizations, setAdminOrgPlan, archiveAdminOrg, suspendAdminOrg, deleteAdminOrg } from "../../../lib/api";
import { Search, ChevronLeft, ChevronRight, Archive, ArchiveRestore, Trash2, ShieldOff, ShieldCheck } from "lucide-react";

const PLANS = ["free", "starter", "professional", "enterprise_silver", "enterprise_gold"];
const PLAN_LABELS: Record<string, string> = {
  free: "Free", starter: "Starter", professional: "Professional",
  enterprise_silver: "Enterprise Silver", enterprise_gold: "Enterprise Gold",
};
const PLAN_COLORS: Record<string, string> = {
  free: "#6b7280", starter: "#00b8d4", professional: "#7c5cfc",
  enterprise_silver: "#ff8800", enterprise_gold: "#ffd700",
};

type ConfirmAction =
  | { kind: "archive"; org: any }
  | { kind: "suspend"; org: any }
  | { kind: "delete"; org: any };

export default function AdminOrganizations() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [planFilter, setPlanFilter] = useState("");
  const [showArchived, setShowArchived] = useState(false);
  const [page, setPage] = useState(1);
  const [actionOrgId, setActionOrgId] = useState<number | null>(null);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [confirm, setConfirm] = useState<ConfirmAction | null>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setData(await getAdminOrganizations({ page, search, plan: planFilter, showArchived }));
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to load" });
    } finally { setLoading(false); }
  }, [page, search, planFilter, showArchived]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (banner) { const t = setTimeout(() => setBanner(null), 4000); return () => clearTimeout(t); } }, [banner]);
  useEffect(() => { setPage(1); }, [search, planFilter, showArchived]);

  async function handlePlanChange(orgId: number, newPlan: string) {
    setActionOrgId(orgId);
    try {
      await setAdminOrgPlan(orgId, newPlan);
      setBanner({ kind: "ok", text: `Plan updated to ${PLAN_LABELS[newPlan]}.` });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to update plan" });
    } finally { setActionOrgId(null); }
  }

  async function handleConfirm() {
    if (!confirm) return;
    setConfirmBusy(true);
    try {
      if (confirm.kind === "archive") {
        const res = await archiveAdminOrg(confirm.org.id);
        const label = res.org?.isActive ? "restored" : "archived";
        setBanner({ kind: "ok", text: `Organization ${label}.` });
      } else if (confirm.kind === "suspend") {
        const res = await suspendAdminOrg(confirm.org.id);
        const label = res.org?.isSuspended ? "suspended" : "unsuspended";
        setBanner({ kind: "ok", text: `Organization ${label}.` });
      } else {
        await deleteAdminOrg(confirm.org.id);
        setBanner({ kind: "ok", text: `Organization "${confirm.org.name}" deleted.` });
      }
      setConfirm(null);
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Action failed" });
      setConfirm(null);
    } finally { setConfirmBusy(false); }
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-white">Organizations</h1>
        <p className="text-xs text-white/30 mt-0.5">{data ? `${data.total} total` : "…"}</p>
      </div>

      {banner && (
        <div className={`rounded-lg px-4 py-2.5 text-sm ${banner.kind === "ok" ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20" : "bg-red-500/10 text-red-300 border border-red-500/20"}`}>
          {banner.text}
        </div>
      )}

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/30" />
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search by name or slug…"
            className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg pl-8 pr-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40" />
        </div>
        <select value={planFilter} onChange={(e) => setPlanFilter(e.target.value)}
          className="bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white/60 focus:outline-none focus:border-teal-500/40">
          <option value="">All plans</option>
          {PLANS.map((p) => <option key={p} value={p}>{PLAN_LABELS[p]}</option>)}
        </select>
        <label className="flex items-center gap-2 text-xs text-white/40 cursor-pointer select-none">
          <input type="checkbox" checked={showArchived} onChange={(e) => setShowArchived(e.target.checked)}
            className="rounded border-white/20 bg-white/[0.04] accent-teal-500" />
          Show archived
        </label>
      </div>

      <div className="rounded-xl border border-white/[0.06] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/[0.06] bg-white/[0.02]">
              {["Organization", "Plan", "Assets", "Members", "Scans/mo", "Created", "Change Plan", "Actions"].map((h) => (
                <th key={h} className="text-left px-4 py-3 text-xs font-medium text-white/40">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={8} className="px-4 py-8 text-center text-white/30 text-xs">Loading…</td></tr>
            ) : !data?.organizations?.length ? (
              <tr><td colSpan={8} className="px-4 py-8 text-center text-white/30 text-xs">No organizations found.</td></tr>
            ) : data.organizations.map((org: any) => {
              const color = PLAN_COLORS[org.plan] || "#6b7280";
              const isActing = actionOrgId === org.id;
              const isArchived = !org.isActive;
              const isSuspended = org.isSuspended;
              return (
                <tr key={org.id} className={`border-b border-white/[0.04] transition-colors ${isArchived ? "opacity-50" : "hover:bg-white/[0.02]"}`}>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-white">{org.name}</span>
                      {isArchived && <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.06] text-white/40">archived</span>}
                      {isSuspended && <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400">suspended</span>}
                    </div>
                    <div className="text-[11px] text-white/30 font-mono">{org.slug}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 rounded text-[11px] font-semibold" style={{ backgroundColor: `${color}15`, color }}>
                      {PLAN_LABELS[org.plan] || org.plan}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-white/60">{org.assetsCount} / {org.assetLimit === -1 ? "∞" : org.assetLimit}</td>
                  <td className="px-4 py-3 text-white/60">{org.memberCount}</td>
                  <td className="px-4 py-3 text-white/60">{org.scansThisMonth}</td>
                  <td className="px-4 py-3 text-white/40 text-xs">{org.createdAt ? new Date(org.createdAt).toLocaleDateString() : "—"}</td>
                  <td className="px-4 py-3">
                    <select value={org.plan} disabled={isActing || isArchived} onChange={(e) => handlePlanChange(org.id, e.target.value)}
                      className="bg-white/[0.04] border border-white/[0.08] rounded px-2 py-1 text-xs text-white/60 focus:outline-none focus:border-teal-500/40 disabled:opacity-50">
                      {PLANS.map((p) => <option key={p} value={p}>{PLAN_LABELS[p]}</option>)}
                    </select>
                    {isActing && <span className="ml-2 text-[10px] text-white/30">Saving…</span>}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => setConfirm({ kind: "suspend", org })}
                        title={isSuspended ? "Unsuspend organization" : "Suspend organization"}
                        className={`p-1.5 rounded transition-colors ${isSuspended ? "text-red-400 hover:bg-red-500/10" : "text-white/30 hover:bg-red-500/10 hover:text-red-400"}`}
                      >
                        {isSuspended ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldOff className="w-3.5 h-3.5" />}
                      </button>
                      <button
                        onClick={() => setConfirm({ kind: "archive", org })}
                        title={isArchived ? "Restore organization" : "Archive organization"}
                        className="p-1.5 rounded hover:bg-white/[0.06] text-white/30 hover:text-amber-400 transition-colors"
                      >
                        {isArchived ? <ArchiveRestore className="w-3.5 h-3.5" /> : <Archive className="w-3.5 h-3.5" />}
                      </button>
                      <button
                        onClick={() => setConfirm({ kind: "delete", org })}
                        title="Permanently delete organization"
                        className="p-1.5 rounded hover:bg-red-500/10 text-white/30 hover:text-red-400 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {data && data.pages > 1 && (
        <div className="flex items-center justify-between text-xs text-white/40">
          <span>Page {data.page} of {data.pages}</span>
          <div className="flex items-center gap-2">
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} className="p-1.5 rounded hover:bg-white/[0.04] disabled:opacity-30 transition-colors"><ChevronLeft className="w-4 h-4" /></button>
            <button onClick={() => setPage((p) => Math.min(data.pages, p + 1))} disabled={page === data.pages} className="p-1.5 rounded hover:bg-white/[0.04] disabled:opacity-30 transition-colors"><ChevronRight className="w-4 h-4" /></button>
          </div>
        </div>
      )}

      {confirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1424] border border-white/[0.08] rounded-xl p-6 w-full max-w-sm shadow-2xl">
            {confirm.kind === "suspend" ? (
            <>
              <h2 className="text-base font-semibold text-white mb-2">
                {confirm.org.isSuspended ? "Unsuspend organization?" : "Suspend organization?"}
              </h2>
              <p className="text-sm text-white/50 mb-5">
                {confirm.org.isSuspended
                  ? `All users in "${confirm.org.name}" will regain access immediately.`
                  : `All users in "${confirm.org.name}" will be blocked from logging in and shown a suspension notice. No data will be deleted.`}
              </p>
              <div className="flex justify-end gap-3">
                <button onClick={() => setConfirm(null)} disabled={confirmBusy}
                  className="px-4 py-2 text-sm text-white/50 hover:text-white transition-colors disabled:opacity-40">Cancel</button>
                <button onClick={handleConfirm} disabled={confirmBusy}
                  className="px-4 py-2 text-sm bg-red-500/10 text-red-400 border border-red-500/20 rounded-lg hover:bg-red-500/20 transition-colors disabled:opacity-40">
                  {confirmBusy ? "Working…" : confirm.org.isSuspended ? "Unsuspend" : "Suspend"}
                </button>
              </div>
            </>
          ) : confirm.kind === "archive" ? (
              <>
                <h2 className="text-base font-semibold text-white mb-2">
                  {confirm.org.isActive ? "Archive organization?" : "Restore organization?"}
                </h2>
                <p className="text-sm text-white/50 mb-5">
                  {confirm.org.isActive
                    ? `"${confirm.org.name}" will be marked inactive. No data will be deleted. You can restore it later.`
                    : `"${confirm.org.name}" will be marked active again.`}
                </p>
                <div className="flex justify-end gap-3">
                  <button onClick={() => setConfirm(null)} disabled={confirmBusy}
                    className="px-4 py-2 text-sm text-white/50 hover:text-white transition-colors disabled:opacity-40">Cancel</button>
                  <button onClick={handleConfirm} disabled={confirmBusy}
                    className="px-4 py-2 text-sm bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded-lg hover:bg-amber-500/20 transition-colors disabled:opacity-40">
                    {confirmBusy ? "Working…" : confirm.org.isActive ? "Archive" : "Restore"}
                  </button>
                </div>
              </>
            ) : (
              <>
                <h2 className="text-base font-semibold text-white mb-2">Delete organization permanently?</h2>
                <p className="text-sm text-white/50 mb-1">
                  <span className="text-white font-medium">"{confirm.org.name}"</span> and all its data — assets, scans,
                  findings, members, API keys — will be permanently deleted.
                </p>
                <p className="text-xs text-red-400/80 mb-5">This cannot be undone.</p>
                <div className="flex justify-end gap-3">
                  <button onClick={() => setConfirm(null)} disabled={confirmBusy}
                    className="px-4 py-2 text-sm text-white/50 hover:text-white transition-colors disabled:opacity-40">Cancel</button>
                  <button onClick={handleConfirm} disabled={confirmBusy}
                    className="px-4 py-2 text-sm bg-red-500/10 text-red-400 border border-red-500/20 rounded-lg hover:bg-red-500/20 transition-colors disabled:opacity-40">
                    {confirmBusy ? "Deleting…" : "Delete permanently"}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
