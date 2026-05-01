"use client";
import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  getAdminOrganization, setAdminOrgPlan, archiveAdminOrg,
  suspendAdminOrg, deleteAdminOrg, setAdminOrgLimits,
} from "../../../../lib/api";
import {
  ArrowLeft, Globe, Archive, ArchiveRestore, ShieldOff, ShieldCheck,
  Trash2, ShieldAlert, ExternalLink, SlidersHorizontal, RotateCcw,
} from "lucide-react";
import Link from "next/link";

const PLANS = ["free", "starter", "professional", "enterprise_silver", "enterprise_gold"];
const PLAN_LABELS: Record<string, string> = {
  free: "Free", starter: "Starter", professional: "Professional",
  enterprise_silver: "Enterprise Silver", enterprise_gold: "Enterprise Gold",
};
const PLAN_COLORS: Record<string, string> = {
  free: "#6b7280", starter: "#00b8d4", professional: "#7c5cfc",
  enterprise_silver: "#ff8800", enterprise_gold: "#ffd700",
};
const ROLE_COLORS: Record<string, string> = {
  owner: "text-purple-300 bg-purple-500/10",
  admin: "text-blue-300 bg-blue-500/10",
  analyst: "text-emerald-300 bg-emerald-500/10",
  viewer: "text-gray-300 bg-gray-500/10",
};

function formatDate(d?: string) {
  if (!d) return "—";
  return new Date(d).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function UsageBar({ label, used, limit, color }: { label: string; used: number; limit: number; color: string }) {
  const pct = limit <= 0 ? 0 : Math.min(100, (used / limit) * 100);
  const isUnlimited = limit === -1;
  return (
    <div>
      <div className="flex items-center justify-between text-xs mb-1.5">
        <span className="text-white/50">{label}</span>
        <span className="text-white/70 font-mono">
          {used.toLocaleString()} {isUnlimited ? "/ ∞" : `/ ${limit.toLocaleString()}`}
        </span>
      </div>
      {!isUnlimited && (
        <div className="h-1.5 bg-white/[0.04] rounded-full overflow-hidden">
          <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
        </div>
      )}
    </div>
  );
}

export default function OrgDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [org, setOrg] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [actionBusy, setActionBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [limitsOpen, setLimitsOpen] = useState(false);
  const [limitDraft, setLimitDraft] = useState<Record<string, string>>({});
  const [limitsBusy, setLimitsBusy] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setOrg(await getAdminOrganization(Number(id)));
    } catch (e: any) {
      setError(e?.message || "Failed to load organization");
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (banner) { const t = setTimeout(() => setBanner(null), 4000); return () => clearTimeout(t); }
  }, [banner]);

  async function handlePlanChange(newPlan: string) {
    setActionBusy(true);
    try {
      await setAdminOrgPlan(Number(id), newPlan);
      setBanner({ kind: "ok", text: `Plan updated to ${PLAN_LABELS[newPlan]}.` });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to update plan" });
    } finally { setActionBusy(false); }
  }

  async function handleArchive() {
    setActionBusy(true);
    try {
      const res = await archiveAdminOrg(Number(id));
      setBanner({ kind: "ok", text: `Organization ${res.org?.isActive ? "restored" : "archived"}.` });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed" });
    } finally { setActionBusy(false); }
  }

  async function handleSuspend() {
    setActionBusy(true);
    try {
      const res = await suspendAdminOrg(Number(id));
      setBanner({ kind: "ok", text: `Organization ${res.org?.isSuspended ? "suspended" : "unsuspended"}.` });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed" });
    } finally { setActionBusy(false); }
  }

  async function handleDelete() {
    setDeleting(true);
    try {
      await deleteAdminOrg(Number(id));
      router.replace("/admin/organizations");
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to delete" });
      setDeleting(false);
      setConfirmDelete(false);
    }
  }

  function openLimitsEditor() {
    // Seed draft with current overrides (displayed as strings for inputs)
    const overrides = org.limitOverrides || {};
    const draft: Record<string, string> = {};
    for (const key of ["assets", "scans_per_month", "team_members", "scheduled_scans", "api_keys"]) {
      draft[key] = key in overrides ? String(overrides[key]) : "";
    }
    setLimitDraft(draft);
    setLimitsOpen(true);
  }

  async function handleSaveLimits() {
    setLimitsBusy(true);
    try {
      const payload: Record<string, number | null> = {};
      for (const [key, val] of Object.entries(limitDraft)) {
        if (val === "" || val === null) {
          payload[key] = null; // remove override
        } else {
          const n = parseInt(val, 10);
          if (isNaN(n)) continue;
          payload[key] = n;
        }
      }
      await setAdminOrgLimits(Number(id), payload);
      setBanner({ kind: "ok", text: "Custom limits saved." });
      setLimitsOpen(false);
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to save limits" });
    } finally {
      setLimitsBusy(false); }
  }

  if (loading) return <div className="text-white/40 text-sm">Loading…</div>;
  if (error) return <div className="text-red-400 text-sm">{error}</div>;
  if (!org) return null;

  const planColor = PLAN_COLORS[org.plan] || "#6b7280";
  const isArchived = !org.isActive;
  const isSuspended = org.isSuspended;

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Back + header */}
      <div>
        <Link href="/admin/organizations" className="flex items-center gap-1.5 text-xs text-white/30 hover:text-white transition-colors mb-4">
          <ArrowLeft className="w-3.5 h-3.5" />Back to Organizations
        </Link>

        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-xl font-semibold text-white">{org.name}</h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-semibold"
                style={{ backgroundColor: `${planColor}15`, color: planColor }}>
                {PLAN_LABELS[org.plan] || org.plan}
              </span>
              {isArchived && <span className="text-[11px] px-2 py-0.5 rounded bg-white/[0.06] text-white/40">archived</span>}
              {isSuspended && <span className="text-[11px] px-2 py-0.5 rounded bg-red-500/10 text-red-400">suspended</span>}
            </div>
            <div className="flex items-center gap-3 mt-1 text-xs text-white/30 flex-wrap">
              <span className="font-mono">{org.slug}</span>
              {org.website && (
                <a href={org.website} target="_blank" rel="noopener noreferrer"
                  className="flex items-center gap-1 hover:text-white transition-colors">
                  <Globe className="w-3 h-3" />{org.website}
                </a>
              )}
              <span>Created {formatDate(org.createdAt)}</span>
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2 flex-wrap">
            <select
              value={org.plan}
              disabled={actionBusy}
              onChange={(e) => handlePlanChange(e.target.value)}
              className="bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-1.5 text-xs text-white/60 focus:outline-none focus:border-teal-500/40 disabled:opacity-50"
            >
              {PLANS.map((p) => <option key={p} value={p}>{PLAN_LABELS[p]}</option>)}
            </select>

            <button onClick={handleSuspend} disabled={actionBusy}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border transition-colors disabled:opacity-40 ${
                isSuspended
                  ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20 hover:bg-emerald-500/20"
                  : "bg-red-500/10 text-red-400 border-red-500/20 hover:bg-red-500/20"
              }`}>
              {isSuspended ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldOff className="w-3.5 h-3.5" />}
              {isSuspended ? "Unsuspend" : "Suspend"}
            </button>

            <button onClick={handleArchive} disabled={actionBusy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-white/[0.04] text-white/50 border border-white/[0.08] hover:bg-white/[0.08] hover:text-white transition-colors disabled:opacity-40">
              {isArchived ? <ArchiveRestore className="w-3.5 h-3.5" /> : <Archive className="w-3.5 h-3.5" />}
              {isArchived ? "Restore" : "Archive"}
            </button>

            <button onClick={openLimitsEditor}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-white/[0.04] text-white/50 border border-white/[0.08] hover:bg-white/[0.08] hover:text-white transition-colors">
              <SlidersHorizontal className="w-3.5 h-3.5" />Custom Limits
            </button>

            <button onClick={() => setConfirmDelete(true)} disabled={actionBusy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition-colors disabled:opacity-40">
              <Trash2 className="w-3.5 h-3.5" />Delete
            </button>
          </div>
        </div>
      </div>

      {banner && (
        <div className={`rounded-lg px-4 py-2.5 text-sm ${banner.kind === "ok"
          ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20"
          : "bg-red-500/10 text-red-300 border border-red-500/20"}`}>
          {banner.text}
        </div>
      )}

      {/* Usage */}
      <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5 space-y-4">
        <h2 className="text-sm font-semibold text-white">Usage</h2>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-6">
          <div className="text-center">
            <div className="text-2xl font-bold text-white">{(org.usage.assets ?? 0).toLocaleString()}</div>
            <div className="text-xs text-white/40 mt-0.5">Assets</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-white">{org.usage.members}</div>
            <div className="text-xs text-white/40 mt-0.5">Members</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-white">{org.usage.scansThisMonth.toLocaleString()}</div>
            <div className="text-xs text-white/40 mt-0.5">Scans this month</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-white">{org.usage.scheduledScans}</div>
            <div className="text-xs text-white/40 mt-0.5">Active schedules</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-white">{org.usage.apiKeys}</div>
            <div className="text-xs text-white/40 mt-0.5">API keys</div>
          </div>
        </div>
        <UsageBar
          label="Assets vs limit"
          used={org.usage.assets}
          limit={org.usage.assetLimit}
          color={planColor}
        />
      </div>

      {/* Effective limits */}
      {(() => {
        const eff = org.effectiveLimits || {};
        const def = org.planDefaults || {};
        const overrides = org.limitOverrides || {};
        const hasOverrides = Object.keys(overrides).length > 0;
        const rows = [
          { key: "assets", label: "Assets" },
          { key: "scans_per_month", label: "Scans / month" },
          { key: "team_members", label: "Team members" },
          { key: "scheduled_scans", label: "Scheduled scans" },
          { key: "api_keys", label: "API keys" },
        ];
        return (
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-semibold text-white">Limits</h2>
                {hasOverrides && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-teal-500/10 text-teal-400 border border-teal-500/20">
                    {Object.keys(overrides).length} override{Object.keys(overrides).length !== 1 ? "s" : ""} active
                  </span>
                )}
              </div>
              <button onClick={openLimitsEditor}
                className="flex items-center gap-1 text-xs text-white/30 hover:text-teal-400 transition-colors">
                <SlidersHorizontal className="w-3 h-3" />Edit
              </button>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              {rows.map(({ key, label }) => {
                const val = eff[key];
                const isOverridden = key in overrides;
                const planVal = def[key];
                return (
                  <div key={key} className={`rounded-lg p-3 border ${isOverridden ? "border-teal-500/20 bg-teal-500/[0.04]" : "border-white/[0.05] bg-white/[0.02]"}`}>
                    <div className="text-[10px] text-white/40 mb-1">{label}</div>
                    <div className={`text-lg font-bold ${isOverridden ? "text-teal-400" : "text-white"}`}>
                      {val === -1 ? "∞" : val?.toLocaleString() ?? "—"}
                    </div>
                    {isOverridden && (
                      <div className="text-[10px] text-white/30 mt-0.5">
                        plan: {planVal === -1 ? "∞" : planVal}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })()}

      {/* Plan info */}
      <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
        <h2 className="text-sm font-semibold text-white mb-3">Plan Details</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
          <div>
            <div className="text-white/30 mb-0.5">Plan</div>
            <div className="font-semibold" style={{ color: planColor }}>{PLAN_LABELS[org.plan] || org.plan}</div>
          </div>
          <div>
            <div className="text-white/30 mb-0.5">Status</div>
            <div className="text-white/70 capitalize">{org.planStatus}</div>
          </div>
          <div>
            <div className="text-white/30 mb-0.5">Started</div>
            <div className="text-white/70">{formatDate(org.planStartedAt)}</div>
          </div>
          <div>
            <div className="text-white/30 mb-0.5">Expires</div>
            <div className="text-white/70">{org.planExpiresAt ? formatDate(org.planExpiresAt) : "Never"}</div>
          </div>
        </div>
      </div>

      {/* Members */}
      <div className="rounded-xl border border-white/[0.06] overflow-hidden">
        <div className="px-5 py-3.5 border-b border-white/[0.06] bg-white/[0.02] flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">Members <span className="text-white/30 font-normal ml-1">({org.members.length})</span></h2>
          <Link
            href={`/admin/audit-log?org_id=${org.id}`}
            className="flex items-center gap-1 text-xs text-white/30 hover:text-teal-400 transition-colors"
          >
            <ExternalLink className="w-3 h-3" />View audit log
          </Link>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/[0.04]">
              <th className="text-left px-5 py-2.5 text-xs font-medium text-white/30">User</th>
              <th className="text-left px-5 py-2.5 text-xs font-medium text-white/30">Role</th>
              <th className="text-left px-5 py-2.5 text-xs font-medium text-white/30">Joined</th>
            </tr>
          </thead>
          <tbody>
            {org.members.length === 0 ? (
              <tr><td colSpan={3} className="px-5 py-6 text-center text-white/30 text-xs">No members.</td></tr>
            ) : org.members.map((m: any) => (
              <tr key={m.id} className="border-b border-white/[0.03] hover:bg-white/[0.02] transition-colors last:border-0">
                <td className="px-5 py-3">
                  <div className="flex items-center gap-2">
                    <span className="text-white/80">{m.name || m.email}</span>
                    {m.isSuperadmin && <ShieldAlert className="w-3.5 h-3.5 text-teal-400" title="Superadmin" />}
                  </div>
                  {m.name && <div className="text-[11px] text-white/30">{m.email}</div>}
                </td>
                <td className="px-5 py-3">
                  <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${ROLE_COLORS[m.role] || "text-white/40"}`}>
                    {m.role}
                  </span>
                </td>
                <td className="px-5 py-3 text-xs text-white/40">{formatDate(m.joinedAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Delete confirmation modal */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1424] border border-white/[0.08] rounded-xl p-6 w-full max-w-sm shadow-2xl">
            <h2 className="text-base font-semibold text-white mb-2">Delete organization permanently?</h2>
            <p className="text-sm text-white/50 mb-1">
              <span className="text-white font-medium">"{org.name}"</span> and all its data — assets, scans,
              findings, members, API keys — will be permanently deleted.
            </p>
            <p className="text-xs text-red-400/80 mb-5">This cannot be undone.</p>
            <div className="flex justify-end gap-3">
              <button onClick={() => setConfirmDelete(false)} disabled={deleting}
                className="px-4 py-2 text-sm text-white/50 hover:text-white transition-colors disabled:opacity-40">
                Cancel
              </button>
              <button onClick={handleDelete} disabled={deleting}
                className="px-4 py-2 text-sm bg-red-500/10 text-red-400 border border-red-500/20 rounded-lg hover:bg-red-500/20 transition-colors disabled:opacity-40">
                {deleting ? "Deleting…" : "Delete permanently"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Custom limits editor modal */}
      {limitsOpen && org && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1424] border border-white/[0.08] rounded-xl p-6 w-full max-w-md shadow-2xl">
            <h2 className="text-base font-semibold text-white mb-1">Custom Limits</h2>
            <p className="text-xs text-white/40 mb-5">
              Override plan defaults for <span className="text-white/60">{org.name}</span>.
              Leave a field blank to use the plan default. Enter <span className="font-mono text-white/60">-1</span> for unlimited.
            </p>

            <div className="space-y-3">
              {[
                { key: "assets", label: "Assets", planVal: org.planDefaults?.assets },
                { key: "scans_per_month", label: "Scans per month", planVal: org.planDefaults?.scans_per_month },
                { key: "team_members", label: "Team members", planVal: org.planDefaults?.team_members },
                { key: "scheduled_scans", label: "Scheduled scans", planVal: org.planDefaults?.scheduled_scans },
                { key: "api_keys", label: "API keys", planVal: org.planDefaults?.api_keys },
              ].map(({ key, label, planVal }) => (
                <div key={key} className="flex items-center gap-3">
                  <label className="text-xs text-white/50 w-36 shrink-0">{label}</label>
                  <input
                    type="number"
                    min="-1"
                    value={limitDraft[key] ?? ""}
                    onChange={(e) => setLimitDraft((d) => ({ ...d, [key]: e.target.value }))}
                    placeholder={`Plan default: ${planVal === -1 ? "∞" : planVal}`}
                    className="flex-1 bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/20 focus:outline-none focus:border-teal-500/40"
                  />
                  {limitDraft[key] !== "" && (
                    <button
                      onClick={() => setLimitDraft((d) => ({ ...d, [key]: "" }))}
                      title="Reset to plan default"
                      className="text-white/20 hover:text-white/60 transition-colors shrink-0"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              ))}
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <button onClick={() => setLimitsOpen(false)} disabled={limitsBusy}
                className="px-4 py-2 text-sm text-white/50 hover:text-white transition-colors disabled:opacity-40">
                Cancel
              </button>
              <button onClick={handleSaveLimits} disabled={limitsBusy}
                className="px-4 py-2 text-sm bg-teal-500/10 text-teal-400 border border-teal-500/20 rounded-lg hover:bg-teal-500/20 transition-colors disabled:opacity-40">
                {limitsBusy ? "Saving…" : "Save limits"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
