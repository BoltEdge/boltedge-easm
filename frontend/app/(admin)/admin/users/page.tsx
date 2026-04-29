"use client";
import { useEffect, useState, useCallback } from "react";
import { useSearchParams } from "next/navigation";
import { getAdminUsers, suspendAdminUser, deleteAdminUser, sendAdminPasswordReset, impersonateAdminUser } from "../../../lib/api";
import { startImpersonation } from "../../../lib/auth";
import { Search, ChevronLeft, ChevronRight, ShieldAlert, ShieldOff, ShieldCheck, Trash2, KeyRound, Copy, Check, X, UserCog } from "lucide-react";

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

const ROLES = ["owner", "admin", "analyst", "viewer"];

export default function AdminUsers() {
  const searchParams = useSearchParams();
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [suspendedFilter, setSuspendedFilter] = useState<"" | "true" | "false">("");
  const [superadminFilter, setSuperadminFilter] = useState(false);
  // org filter can be seeded from ?org_id= query param (e.g. coming from org detail page)
  const [orgFilter, setOrgFilter] = useState<number | undefined>(
    searchParams?.get("org_id") ? Number(searchParams.get("org_id")) : undefined
  );
  const [orgFilterName, setOrgFilterName] = useState<string>(
    searchParams?.get("org_name") || (searchParams?.get("org_id") ? `Org #${searchParams.get("org_id")}` : "")
  );
  const [page, setPage] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [confirmUser, setConfirmUser] = useState<any | null>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);
  const [suspendBusy, setSuspendBusy] = useState<number | null>(null);
  const [resetModal, setResetModal] = useState<{ user: any; link?: string; emailSent?: boolean; busy: boolean } | null>(null);
  const [copied, setCopied] = useState(false);
  const [impersonateBusy, setImpersonateBusy] = useState<number | null>(null);

  const activeFilters = [roleFilter, suspendedFilter, superadminFilter, orgFilter].filter(Boolean).length;

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await getAdminUsers({
        page,
        search: search || undefined,
        role: roleFilter || undefined,
        orgId: orgFilter,
        suspended: suspendedFilter === "" ? undefined : suspendedFilter === "true",
        superadmin: superadminFilter || undefined,
      }));
    } catch (e: any) {
      setError(e?.message || "Failed to load");
    } finally { setLoading(false); }
  }, [page, search, roleFilter, suspendedFilter, superadminFilter, orgFilter]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [search, roleFilter, suspendedFilter, superadminFilter, orgFilter]);
  useEffect(() => { if (banner) { const t = setTimeout(() => setBanner(null), 4000); return () => clearTimeout(t); } }, [banner]);

  function clearFilters() {
    setRoleFilter("");
    setSuspendedFilter("");
    setSuperadminFilter(false);
    setOrgFilter(undefined);
    setOrgFilterName("");
  }

  async function handleImpersonate(u: any) {
    setImpersonateBusy(u.id);
    try {
      const res = await impersonateAdminUser(u.id);
      startImpersonation(res.accessToken, res.user, res.organization ?? null, res.role ?? null);
      window.location.href = "/dashboard";
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to impersonate user" });
      setImpersonateBusy(null);
    }
  }

  async function handleResetPassword(u: any) {
    setResetModal({ user: u, busy: true });
    try {
      const res = await sendAdminPasswordReset(u.id);
      setResetModal({ user: u, link: res.link, emailSent: res.emailSent, busy: false });
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to generate reset link" });
      setResetModal(null);
    }
  }

  function handleCopy(link: string) {
    navigator.clipboard.writeText(link);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  async function handleSuspend(u: any) {
    setSuspendBusy(u.id);
    try {
      const res = await suspendAdminUser(u.id);
      const label = res.isSuspended ? "suspended" : "unsuspended";
      setBanner({ kind: "ok", text: `User "${u.email}" ${label}.` });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to update user" });
    } finally { setSuspendBusy(null); }
  }

  async function handleDelete() {
    if (!confirmUser) return;
    setConfirmBusy(true);
    try {
      await deleteAdminUser(confirmUser.id);
      setBanner({ kind: "ok", text: `User "${confirmUser.email}" deleted.` });
      setConfirmUser(null);
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to delete user" });
      setConfirmUser(null);
    } finally { setConfirmBusy(false); }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Users</h1>
          <p className="text-xs text-white/30 mt-0.5">{data ? `${data.total} total` : "…"}</p>
        </div>
      </div>

      {banner && (
        <div className={`rounded-lg px-4 py-2.5 text-sm ${banner.kind === "ok" ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20" : "bg-red-500/10 text-red-300 border border-red-500/20"}`}>
          {banner.text}
        </div>
      )}

      {error && (
        <div className="rounded-lg px-4 py-2.5 text-sm bg-red-500/10 text-red-300 border border-red-500/20">{error}</div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative max-w-sm flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/30" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by name or email…"
            className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg pl-8 pr-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40"
          />
        </div>

        <select
          value={roleFilter}
          onChange={(e) => setRoleFilter(e.target.value)}
          className="bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500/40"
        >
          <option value="">All roles</option>
          {ROLES.map((r) => <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>)}
        </select>

        <select
          value={suspendedFilter}
          onChange={(e) => setSuspendedFilter(e.target.value as "" | "true" | "false")}
          className="bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500/40"
        >
          <option value="">All users</option>
          <option value="true">Suspended only</option>
          <option value="false">Active only</option>
        </select>

        <label className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/[0.04] border border-white/[0.08] text-sm text-white/60 cursor-pointer select-none hover:border-white/[0.14] transition-colors">
          <input
            type="checkbox"
            checked={superadminFilter}
            onChange={(e) => setSuperadminFilter(e.target.checked)}
            className="accent-teal-500 w-3.5 h-3.5"
          />
          Superadmins
        </label>

        {orgFilterName && (
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-teal-500/10 border border-teal-500/20 text-xs text-teal-300">
            <span>Org: {orgFilterName}</span>
            <button
              onClick={() => { setOrgFilter(undefined); setOrgFilterName(""); }}
              className="hover:text-white transition-colors"
            >
              <X className="w-3 h-3" />
            </button>
          </div>
        )}

        {activeFilters > 0 && (
          <button
            onClick={clearFilters}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm text-white/40 hover:text-white hover:bg-white/[0.04] transition-colors"
          >
            <X className="w-3.5 h-3.5" />
            Clear
            <span className="ml-0.5 px-1.5 py-0.5 rounded-full bg-white/[0.08] text-xs text-white/60">{activeFilters}</span>
          </button>
        )}
      </div>

      <div className="rounded-xl border border-white/[0.06] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/[0.06] bg-white/[0.02]">
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40">User</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Organization</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Role</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Joined</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-white/30 text-xs">Loading…</td></tr>
            ) : !data?.users?.length ? (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-white/30 text-xs">No users found.</td></tr>
            ) : data.users.map((u: any) => {
              const planColor = PLAN_COLORS[u.organization?.plan] || "#6b7280";
              return (
                <tr key={u.id} className="border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-white">{u.name || u.email}</span>
                      {u.isSuperadmin && (
                        <span title="Superadmin"><ShieldAlert className="w-3.5 h-3.5 text-teal-400" /></span>
                      )}
                      {u.isSuspended && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400">suspended</span>
                      )}
                    </div>
                    <div className="text-[11px] text-white/30">{u.email} · <span className="font-mono">#{u.id}</span></div>
                  </td>
                  <td className="px-4 py-3">
                    {u.organization ? (
                      <>
                        <div className="text-white/70">{u.organization.name}</div>
                        <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded" style={{ backgroundColor: `${planColor}15`, color: planColor }}>
                          {u.organization.plan}
                        </span>
                      </>
                    ) : (
                      <span className="text-white/20">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {u.role ? (
                      <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${ROLE_COLORS[u.role] || "text-white/40"}`}>
                        {u.role}
                      </span>
                    ) : "—"}
                  </td>
                  <td className="px-4 py-3 text-white/40 text-xs">
                    {u.createdAt ? new Date(u.createdAt).toLocaleDateString() : "—"}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => handleImpersonate(u)}
                        disabled={u.isSuperadmin || impersonateBusy === u.id}
                        title={u.isSuperadmin ? "Cannot impersonate superadmin" : "Impersonate user"}
                        className="p-1.5 rounded hover:bg-purple-500/10 text-white/30 hover:text-purple-400 transition-colors disabled:opacity-20 disabled:cursor-not-allowed"
                      >
                        <UserCog className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleResetPassword(u)}
                        title="Send password reset link"
                        className="p-1.5 rounded hover:bg-teal-500/10 text-white/30 hover:text-teal-400 transition-colors"
                      >
                        <KeyRound className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleSuspend(u)}
                        disabled={u.isSuperadmin || suspendBusy === u.id}
                        title={u.isSuperadmin ? "Cannot suspend superadmin accounts" : u.isSuspended ? "Unsuspend user" : "Suspend user"}
                        className={`p-1.5 rounded transition-colors disabled:opacity-20 disabled:cursor-not-allowed ${u.isSuspended ? "text-red-400 hover:bg-red-500/10" : "text-white/30 hover:bg-red-500/10 hover:text-red-400"}`}
                      >
                        {u.isSuspended ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldOff className="w-3.5 h-3.5" />}
                      </button>
                      <button
                        onClick={() => setConfirmUser(u)}
                        disabled={u.isSuperadmin}
                        title={u.isSuperadmin ? "Cannot delete superadmin accounts" : "Delete user"}
                        className="p-1.5 rounded hover:bg-red-500/10 text-white/30 hover:text-red-400 transition-colors disabled:opacity-20 disabled:cursor-not-allowed"
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
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}
              className="p-1.5 rounded hover:bg-white/[0.04] disabled:opacity-30 transition-colors">
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button onClick={() => setPage((p) => Math.min(data.pages, p + 1))} disabled={page === data.pages}
              className="p-1.5 rounded hover:bg-white/[0.04] disabled:opacity-30 transition-colors">
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Password reset modal */}
      {resetModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1424] border border-white/[0.08] rounded-xl p-6 w-full max-w-md shadow-2xl">
            <h2 className="text-base font-semibold text-white mb-1">Password Reset Link</h2>
            <p className="text-xs text-white/40 mb-4">For <span className="text-white/70">{resetModal.user.email}</span></p>

            {resetModal.busy ? (
              <div className="text-sm text-white/40 py-4 text-center">Generating link…</div>
            ) : (
              <>
                {resetModal.emailSent && (
                  <div className="mb-3 rounded-lg px-3 py-2 bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 text-xs">
                    Reset email sent successfully to {resetModal.user.email}.
                  </div>
                )}
                {!resetModal.emailSent && (
                  <div className="mb-3 rounded-lg px-3 py-2 bg-amber-500/10 text-amber-300 border border-amber-500/20 text-xs">
                    No email provider configured — share this link with the user manually.
                  </div>
                )}
                <div className="flex items-center gap-2 bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 mb-4">
                  <code className="text-[11px] text-white/60 font-mono flex-1 truncate">{resetModal.link}</code>
                  <button
                    onClick={() => handleCopy(resetModal.link!)}
                    className="shrink-0 p-1 rounded hover:bg-white/[0.08] text-white/40 hover:text-white transition-colors"
                    title="Copy link"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <p className="text-xs text-white/30 mb-4">This link expires in 24 hours and can only be used once.</p>
              </>
            )}

            <div className="flex justify-end">
              <button onClick={() => { setResetModal(null); setCopied(false); }}
                className="px-4 py-2 text-sm text-white/50 hover:text-white transition-colors">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirmation modal */}
      {confirmUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1424] border border-white/[0.08] rounded-xl p-6 w-full max-w-sm shadow-2xl">
            <h2 className="text-base font-semibold text-white mb-2">Delete user permanently?</h2>
            <p className="text-sm text-white/50 mb-1">
              <span className="text-white font-medium">{confirmUser.email}</span> will be permanently removed along with
              their memberships, API keys, and scan history.
            </p>
            <p className="text-xs text-red-400/80 mb-5">This cannot be undone.</p>
            <div className="flex justify-end gap-3">
              <button onClick={() => setConfirmUser(null)} disabled={confirmBusy}
                className="px-4 py-2 text-sm text-white/50 hover:text-white transition-colors disabled:opacity-40">Cancel</button>
              <button onClick={handleDelete} disabled={confirmBusy}
                className="px-4 py-2 text-sm bg-red-500/10 text-red-400 border border-red-500/20 rounded-lg hover:bg-red-500/20 transition-colors disabled:opacity-40">
                {confirmBusy ? "Deleting…" : "Delete permanently"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
