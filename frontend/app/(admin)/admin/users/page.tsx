"use client";
import { useEffect, useState, useCallback } from "react";
import { getAdminUsers, suspendAdminUser, deleteAdminUser } from "../../../lib/api";
import { Search, ChevronLeft, ChevronRight, ShieldAlert, ShieldOff, ShieldCheck, Trash2 } from "lucide-react";

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

export default function AdminUsers() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [confirmUser, setConfirmUser] = useState<any | null>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);
  const [suspendBusy, setSuspendBusy] = useState<number | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await getAdminUsers({ page, search }));
    } catch (e: any) {
      setError(e?.message || "Failed to load");
    } finally { setLoading(false); }
  }, [page, search]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [search]);
  useEffect(() => { if (banner) { const t = setTimeout(() => setBanner(null), 4000); return () => clearTimeout(t); } }, [banner]);

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

      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/30" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by name or email…"
          className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg pl-8 pr-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40"
        />
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
                    <div className="text-[11px] text-white/30">{u.email}</div>
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
