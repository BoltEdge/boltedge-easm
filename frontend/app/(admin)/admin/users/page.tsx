"use client";
import { useEffect, useState, useCallback, useMemo } from "react";
import { useSearchParams } from "next/navigation";
import {
  getAdminUsers, suspendAdminUser, deleteAdminUser, sendAdminPasswordReset,
  impersonateAdminUser, adminForceVerifyEmail, adminResendVerification,
  sendAdminUserEmail, createAdminUserRequest, bulkAdminUserAction,
  resetAdminUserMfa,
  type BulkUserAction, type BulkUserActionResponse,
} from "../../../lib/api";
import { startImpersonation, getIsRootAdmin } from "../../../lib/auth";
import {
  Search, ChevronLeft, ChevronRight, ShieldAlert, ShieldOff, ShieldCheck,
  Trash2, KeyRound, Copy, Check, X, UserCog, Mail, MailCheck, MailWarning,
  ExternalLink, Send, MessageSquarePlus, Loader2, Lock, Unlock, Crown,
} from "lucide-react";
import Link from "next/link";

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
  const isMeRoot = getIsRootAdmin();
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [suspendedFilter, setSuspendedFilter] = useState<"" | "true" | "false">("");
  const [superadminFilter, setSuperadminFilter] = useState(false);
  const [verifiedFilter, setVerifiedFilter] = useState<"" | "true" | "false">("");
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
  const [verifyBusy, setVerifyBusy] = useState<number | null>(null);
  const [resendBusy, setResendBusy] = useState<number | null>(null);
  const [mfaResetBusy, setMfaResetBusy] = useState<number | null>(null);
  const [mfaResetConfirm, setMfaResetConfirm] = useState<any | null>(null);

  // Selection (for bulk actions). Keyed by user id; reset whenever
  // the filtered/paginated list changes so we don't operate on
  // stale ids the admin can no longer see.
  const [selectedIds, setSelectedIds] = useState<Set<number>>(() => new Set());
  const [bulkBusy, setBulkBusy] = useState<BulkUserAction | null>(null);
  const [bulkConfirm, setBulkConfirm] = useState<{ action: BulkUserAction; ids: number[] } | null>(null);
  const [bulkSummary, setBulkSummary] = useState<BulkUserActionResponse | null>(null);

  // Compose modals — always operate on a single target user.
  const [emailModal, setEmailModal] = useState<{
    user: any;
    subject: string;
    body: string;
    busy: boolean;
  } | null>(null);
  const [requestModal, setRequestModal] = useState<{
    user: any;
    requestType: "general" | "trial" | "demo";
    subject: string;
    message: string;
    internalNote: string;
    busy: boolean;
  } | null>(null);

  const activeFilters = [roleFilter, suspendedFilter, superadminFilter, orgFilter, verifiedFilter].filter(Boolean).length;

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
        verified: verifiedFilter === "" ? undefined : verifiedFilter === "true",
      }));
    } catch (e: any) {
      setError(e?.message || "Failed to load");
    } finally { setLoading(false); }
  }, [page, search, roleFilter, suspendedFilter, superadminFilter, orgFilter, verifiedFilter]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [search, roleFilter, suspendedFilter, superadminFilter, orgFilter, verifiedFilter]);
  useEffect(() => { if (banner) { const t = setTimeout(() => setBanner(null), 4000); return () => clearTimeout(t); } }, [banner]);

  function clearFilters() {
    setRoleFilter("");
    setSuspendedFilter("");
    setSuperadminFilter(false);
    setOrgFilter(undefined);
    setOrgFilterName("");
    setVerifiedFilter("");
  }

  async function handleForceVerify(u: any) {
    setVerifyBusy(u.id);
    try {
      await adminForceVerifyEmail(u.id);
      setBanner({ kind: "ok", text: `${u.email} marked as verified.` });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to verify user" });
    } finally { setVerifyBusy(null); }
  }

  async function handleResendVerification(u: any) {
    setResendBusy(u.id);
    try {
      const res = await adminResendVerification(u.id);
      setBanner({
        kind: res.emailSent ? "ok" : "err",
        text: res.message || (res.emailSent ? "Verification email sent." : "Send failed."),
      });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to send verification email" });
    } finally { setResendBusy(null); }
  }

  function relativeTime(iso?: string | null): string {
    if (!iso) return "never";
    const ms = Date.now() - new Date(iso).getTime();
    if (Number.isNaN(ms)) return "—";
    const min = Math.floor(ms / 60_000);
    if (min < 1) return "just now";
    if (min < 60) return `${min}m ago`;
    const hr = Math.floor(min / 60);
    if (hr < 24) return `${hr}h ago`;
    const d = Math.floor(hr / 24);
    return `${d}d ago`;
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

  async function handleResetMfa() {
    if (!mfaResetConfirm) return;
    const u = mfaResetConfirm;
    setMfaResetBusy(u.id);
    try {
      const res = await resetAdminUserMfa(u.id);
      setBanner({
        kind: "ok",
        text: res.message || `MFA reset for ${u.email}.`,
      });
      setMfaResetConfirm(null);
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to reset MFA" });
      setMfaResetConfirm(null);
    } finally {
      setMfaResetBusy(null);
    }
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

  // Visible page contents — used to "select all on page" so the
  // admin only operates on what they can actually see.
  const visibleUsers: any[] = data?.users || [];
  const selectableIds = useMemo(
    () => visibleUsers.filter((u) => !u.isSuperadmin).map((u) => u.id as number),
    [visibleUsers],
  );
  const allOnPageSelected =
    selectableIds.length > 0 && selectableIds.every((id) => selectedIds.has(id));
  const someOnPageSelected =
    !allOnPageSelected && selectableIds.some((id) => selectedIds.has(id));

  function toggleRow(uid: number) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(uid)) next.delete(uid); else next.add(uid);
      return next;
    });
  }
  function toggleAllOnPage() {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (allOnPageSelected) {
        for (const id of selectableIds) next.delete(id);
      } else {
        for (const id of selectableIds) next.add(id);
      }
      return next;
    });
  }
  function clearSelection() {
    setSelectedIds(new Set());
  }

  // Whether a bulk action is destructive enough to require explicit
  // confirmation. Suspend/delete clearly are. Resend/force-verify
  // aren't — they're recoverable / additive.
  function isDestructive(action: BulkUserAction): boolean {
    return action === "delete" || action === "suspend";
  }

  async function executeBulk(action: BulkUserAction) {
    if (selectedIds.size === 0) return;
    const ids = Array.from(selectedIds);
    if (isDestructive(action)) {
      setBulkConfirm({ action, ids });
      return;
    }
    await runBulk(action, ids);
  }

  async function runBulk(action: BulkUserAction, ids: number[]) {
    setBulkBusy(action);
    try {
      const res = await bulkAdminUserAction({ action, userIds: ids });
      setBulkSummary(res);
      // Drop only the ids we actually operated on so a partial
      // failure leaves the rest of the selection intact.
      const handled = new Set([
        ...res.processed.map((p) => p.userId),
        ...res.skipped.map((s) => s.userId),
      ]);
      setSelectedIds((prev) => {
        const next = new Set(prev);
        for (const id of handled) next.delete(id);
        return next;
      });
      setBanner({
        kind: res.summary.errorsCount > 0 ? "err" : "ok",
        text: (
          `Bulk ${action.replace("_", " ")}: `
          + `${res.summary.processedCount} done`
          + (res.summary.skippedCount ? `, ${res.summary.skippedCount} skipped` : "")
          + (res.summary.errorsCount ? `, ${res.summary.errorsCount} errored` : "")
          + "."
        ),
      });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || `Bulk ${action} failed.` });
    } finally {
      setBulkBusy(null);
      setBulkConfirm(null);
    }
  }

  async function handleSendEmail() {
    if (!emailModal) return;
    const subject = emailModal.subject.trim();
    const body = emailModal.body.trim();
    if (!subject || !body) return;
    setEmailModal({ ...emailModal, busy: true });
    try {
      await sendAdminUserEmail(emailModal.user.id, { subject, body });
      setBanner({ kind: "ok", text: `Email sent to ${emailModal.user.email}.` });
      setEmailModal(null);
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to send email" });
      setEmailModal((m) => (m ? { ...m, busy: false } : null));
    }
  }

  async function handleCreateRequest() {
    if (!requestModal) return;
    const message = requestModal.message.trim();
    if (!message) return;
    setRequestModal({ ...requestModal, busy: true });
    try {
      const res = await createAdminUserRequest(requestModal.user.id, {
        requestType: requestModal.requestType,
        subject: requestModal.subject.trim() || undefined,
        message,
        internalNote: requestModal.internalNote.trim() || undefined,
      });
      setBanner({
        kind: "ok",
        text: `Request ${res.request.publicId || `#${res.request.id}`} opened for ${requestModal.user.email}.`,
      });
      setRequestModal(null);
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to create request" });
      setRequestModal((m) => (m ? { ...m, busy: false } : null));
    }
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

        <select
          value={verifiedFilter}
          onChange={(e) => setVerifiedFilter(e.target.value as "" | "true" | "false")}
          className="bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500/40"
        >
          <option value="">Any email status</option>
          <option value="false">Pending verification</option>
          <option value="true">Verified only</option>
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

      {/* Bulk action bar — shown only when there's a selection. Sticks
          to the top of the page so it's reachable even after scrolling
          a long list. */}
      {selectedIds.size > 0 && (
        <div className="sticky top-0 z-30 -mx-6 px-6 py-2.5 bg-[#0d1424]/95 backdrop-blur border-b border-teal-500/30 flex items-center gap-3 flex-wrap">
          <span className="text-sm text-white">
            <span className="text-teal-400 font-semibold">{selectedIds.size}</span> selected
          </span>
          <span className="text-white/20">·</span>
          <button
            onClick={() => executeBulk("suspend")}
            disabled={!!bulkBusy}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs text-amber-300 bg-amber-500/10 border border-amber-500/20 hover:bg-amber-500/20 disabled:opacity-40 transition-colors"
          >
            {bulkBusy === "suspend" ? <Loader2 className="w-3 h-3 animate-spin" /> : <ShieldOff className="w-3 h-3" />}
            Suspend
          </button>
          <button
            onClick={() => executeBulk("unsuspend")}
            disabled={!!bulkBusy}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs text-emerald-300 bg-emerald-500/10 border border-emerald-500/20 hover:bg-emerald-500/20 disabled:opacity-40 transition-colors"
          >
            {bulkBusy === "unsuspend" ? <Loader2 className="w-3 h-3 animate-spin" /> : <ShieldCheck className="w-3 h-3" />}
            Unsuspend
          </button>
          <button
            onClick={() => executeBulk("resend_verification")}
            disabled={!!bulkBusy}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs text-amber-300 bg-amber-500/10 border border-amber-500/20 hover:bg-amber-500/20 disabled:opacity-40 transition-colors"
          >
            {bulkBusy === "resend_verification" ? <Loader2 className="w-3 h-3 animate-spin" /> : <Mail className="w-3 h-3" />}
            Resend verify
          </button>
          <button
            onClick={() => executeBulk("force_verify")}
            disabled={!!bulkBusy}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs text-emerald-300 bg-emerald-500/10 border border-emerald-500/20 hover:bg-emerald-500/20 disabled:opacity-40 transition-colors"
          >
            {bulkBusy === "force_verify" ? <Loader2 className="w-3 h-3 animate-spin" /> : <MailCheck className="w-3 h-3" />}
            Force verify
          </button>
          <button
            onClick={() => executeBulk("delete")}
            disabled={!!bulkBusy}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs text-red-300 bg-red-500/10 border border-red-500/20 hover:bg-red-500/20 disabled:opacity-40 transition-colors"
          >
            {bulkBusy === "delete" ? <Loader2 className="w-3 h-3 animate-spin" /> : <Trash2 className="w-3 h-3" />}
            Delete
          </button>
          <button
            onClick={clearSelection}
            disabled={!!bulkBusy}
            className="ml-auto text-xs text-white/40 hover:text-white transition-colors disabled:opacity-40"
          >
            Clear selection
          </button>
        </div>
      )}

      <div className="rounded-xl border border-white/[0.06] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/[0.06] bg-white/[0.02]">
              <th className="px-3 py-3 w-8">
                <input
                  type="checkbox"
                  aria-label="Select all on page"
                  checked={allOnPageSelected}
                  ref={(el) => { if (el) el.indeterminate = someOnPageSelected; }}
                  onChange={toggleAllOnPage}
                  disabled={selectableIds.length === 0}
                  className="accent-teal-500 w-3.5 h-3.5 cursor-pointer disabled:opacity-30"
                />
              </th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40">User</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Organization</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Role</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Email status</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Joined</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-white/30 text-xs">Loading…</td></tr>
            ) : !data?.users?.length ? (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-white/30 text-xs">No users found.</td></tr>
            ) : data.users.map((u: any) => {
              const planColor = PLAN_COLORS[u.organization?.plan] || "#6b7280";
              return (
                <tr key={u.id} className={`border-b border-white/[0.04] transition-colors ${selectedIds.has(u.id) ? "bg-teal-500/[0.04]" : "hover:bg-white/[0.02]"}`}>
                  <td className="px-3 py-3 w-8">
                    <input
                      type="checkbox"
                      aria-label={`Select ${u.email}`}
                      checked={selectedIds.has(u.id)}
                      onChange={() => toggleRow(u.id)}
                      disabled={u.isSuperadmin}
                      title={u.isSuperadmin ? "Superadmin accounts can't be selected for bulk actions" : ""}
                      className="accent-teal-500 w-3.5 h-3.5 cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed"
                    />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Link
                        href={`/admin/users/${u.id}`}
                        className="font-medium text-white hover:text-teal-300 hover:underline transition-colors"
                      >
                        {u.name || u.email}
                      </Link>
                      {u.isRootAdmin && (
                        <span title="Root admin (CLI-only modifications)">
                          <Crown className="w-3.5 h-3.5 text-amber-400" />
                        </span>
                      )}
                      {u.isSuperadmin && !u.isRootAdmin && (
                        <span title="Superadmin"><ShieldAlert className="w-3.5 h-3.5 text-teal-400" /></span>
                      )}
                      {u.mfaEnabled && (
                        <span title={`MFA enabled${u.mfaEnrolledAt ? ` since ${new Date(u.mfaEnrolledAt).toLocaleDateString()}` : ""}`}>
                          <Lock className="w-3.5 h-3.5 text-emerald-400" />
                        </span>
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
                  <td className="px-4 py-3">
                    {u.emailVerified ? (
                      <div className="flex items-center gap-1.5">
                        <MailCheck className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-[11px] text-emerald-300">Verified</span>
                        {u.oauthProvider && (
                          <span className="text-[10px] text-white/30">via {u.oauthProvider}</span>
                        )}
                      </div>
                    ) : (
                      <div className="flex flex-col gap-0.5">
                        <div className="flex items-center gap-1.5">
                          <MailWarning className="w-3.5 h-3.5 text-amber-400" />
                          <span className="text-[11px] text-amber-300">Pending</span>
                        </div>
                        <span className="text-[10px] text-white/30">
                          {u.emailVerificationSentAt
                            ? `Last sent ${relativeTime(u.emailVerificationSentAt)}`
                            : "Never sent"}
                        </span>
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-white/40 text-xs">
                    {u.createdAt ? new Date(u.createdAt).toLocaleDateString() : "—"}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => setEmailModal({ user: u, subject: "", body: "", busy: false })}
                        title="Send email to user"
                        className="p-1.5 rounded hover:bg-teal-500/10 text-white/30 hover:text-teal-400 transition-colors"
                      >
                        <Send className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => setRequestModal({
                          user: u, requestType: "general",
                          subject: "", message: "", internalNote: "", busy: false,
                        })}
                        title="Open a request on user's behalf"
                        className="p-1.5 rounded hover:bg-blue-500/10 text-white/30 hover:text-blue-400 transition-colors"
                      >
                        <MessageSquarePlus className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleImpersonate(u)}
                        disabled={u.isRootAdmin || (u.isSuperadmin && !isMeRoot) || impersonateBusy === u.id}
                        title={
                          u.isRootAdmin
                            ? "Root admins can only be modified via the CLI"
                            : u.isSuperadmin && !isMeRoot
                            ? "Only a root admin can impersonate an admin account"
                            : "Impersonate user"
                        }
                        className="p-1.5 rounded hover:bg-purple-500/10 text-white/30 hover:text-purple-400 transition-colors disabled:opacity-20 disabled:cursor-not-allowed"
                      >
                        <UserCog className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleResetPassword(u)}
                        disabled={u.isRootAdmin}
                        title={u.isRootAdmin ? "Root admins can only be modified via the CLI" : "Send password reset link"}
                        className="p-1.5 rounded hover:bg-teal-500/10 text-white/30 hover:text-teal-400 transition-colors disabled:opacity-20 disabled:cursor-not-allowed"
                      >
                        <KeyRound className="w-3.5 h-3.5" />
                      </button>
                      {u.mfaEnabled && (
                        <button
                          onClick={() => setMfaResetConfirm(u)}
                          disabled={u.isRootAdmin || mfaResetBusy === u.id}
                          title={u.isRootAdmin ? "Root admins can only be modified via the CLI" : "Reset MFA — user will re-enrol on next login"}
                          className="p-1.5 rounded hover:bg-amber-500/10 text-white/30 hover:text-amber-400 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                        >
                          <Unlock className="w-3.5 h-3.5" />
                        </button>
                      )}
                      {!u.emailVerified && (
                        <>
                          <button
                            onClick={() => handleResendVerification(u)}
                            disabled={resendBusy === u.id}
                            title="Resend verification email"
                            className="p-1.5 rounded hover:bg-amber-500/10 text-white/30 hover:text-amber-400 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                          >
                            <Mail className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => handleForceVerify(u)}
                            disabled={verifyBusy === u.id}
                            title="Manually mark email as verified"
                            className="p-1.5 rounded hover:bg-emerald-500/10 text-white/30 hover:text-emerald-400 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                          >
                            <MailCheck className="w-3.5 h-3.5" />
                          </button>
                        </>
                      )}
                      <Link
                        href={`/admin/audit-log?q=${encodeURIComponent(u.email)}`}
                        title="View activity in audit log"
                        className="p-1.5 rounded hover:bg-white/[0.06] text-white/30 hover:text-white/70 transition-colors"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </Link>
                      <button
                        onClick={() => handleSuspend(u)}
                        disabled={u.isRootAdmin || (u.isSuperadmin && !isMeRoot) || suspendBusy === u.id}
                        title={
                          u.isRootAdmin
                            ? "Root admins can only be modified via the CLI"
                            : u.isSuperadmin && !isMeRoot
                            ? "Only a root admin can suspend an admin account"
                            : u.isSuspended ? "Unsuspend user" : "Suspend user"
                        }
                        className={`p-1.5 rounded transition-colors disabled:opacity-20 disabled:cursor-not-allowed ${u.isSuspended ? "text-red-400 hover:bg-red-500/10" : "text-white/30 hover:bg-red-500/10 hover:text-red-400"}`}
                      >
                        {u.isSuspended ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldOff className="w-3.5 h-3.5" />}
                      </button>
                      <button
                        onClick={() => setConfirmUser(u)}
                        disabled={u.isRootAdmin || (u.isSuperadmin && !isMeRoot)}
                        title={
                          u.isRootAdmin
                            ? "Root admins can only be modified via the CLI"
                            : u.isSuperadmin && !isMeRoot
                            ? "Only a root admin can delete an admin account"
                            : "Delete user"
                        }
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

      {/* Send-email modal */}
      {emailModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-[#0d1424] border border-white/[0.08] rounded-xl p-6 w-full max-w-lg shadow-2xl">
            <div className="flex items-start gap-2 mb-1">
              <Send className="w-4 h-4 text-teal-400 mt-1" />
              <div className="flex-1 min-w-0">
                <h2 className="text-base font-semibold text-white">Send email</h2>
                <p className="text-xs text-white/40 mt-0.5">
                  To <span className="text-white/70">{emailModal.user.email}</span>
                  {emailModal.user.name ? <> ({emailModal.user.name})</> : null}
                </p>
              </div>
            </div>
            <div className="space-y-3 mt-4">
              <label className="block">
                <span className="text-xs font-medium text-white/60">Subject</span>
                <input
                  type="text"
                  autoFocus
                  value={emailModal.subject}
                  onChange={(e) => setEmailModal({ ...emailModal, subject: e.target.value })}
                  maxLength={200}
                  disabled={emailModal.busy}
                  placeholder="Quick check-in / Account update / …"
                  className="mt-1 w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40 disabled:opacity-50"
                />
              </label>
              <label className="block">
                <span className="text-xs font-medium text-white/60">Message</span>
                <textarea
                  value={emailModal.body}
                  onChange={(e) => setEmailModal({ ...emailModal, body: e.target.value })}
                  maxLength={8000}
                  rows={8}
                  disabled={emailModal.busy}
                  placeholder="Plain text. Newlines preserved. Sent from no-reply@nanoeasm.com with the standard branded shell."
                  className="mt-1 w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40 disabled:opacity-50 resize-y"
                />
                <span className="text-[10px] text-white/30 mt-1 block">
                  {emailModal.body.length}/8000 characters · audit-logged
                </span>
              </label>
            </div>
            <div className="flex justify-end gap-3 mt-5">
              <button
                onClick={() => setEmailModal(null)}
                disabled={emailModal.busy}
                className="px-4 py-2 text-sm text-white/50 hover:text-white transition-colors disabled:opacity-40"
              >
                Cancel
              </button>
              <button
                onClick={handleSendEmail}
                disabled={emailModal.busy || !emailModal.subject.trim() || !emailModal.body.trim()}
                className="px-4 py-2 text-sm bg-teal-500/10 text-teal-300 border border-teal-500/30 rounded-lg hover:bg-teal-500/20 transition-colors disabled:opacity-40 flex items-center gap-2"
              >
                {emailModal.busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                {emailModal.busy ? "Sending…" : "Send email"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create-request modal */}
      {requestModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-[#0d1424] border border-white/[0.08] rounded-xl p-6 w-full max-w-lg shadow-2xl">
            <div className="flex items-start gap-2 mb-1">
              <MessageSquarePlus className="w-4 h-4 text-blue-400 mt-1" />
              <div className="flex-1 min-w-0">
                <h2 className="text-base font-semibold text-white">Open a request on behalf of user</h2>
                <p className="text-xs text-white/40 mt-0.5">
                  As <span className="text-white/70">{requestModal.user.email}</span> — appears in your contact-requests queue.
                </p>
              </div>
            </div>
            <div className="space-y-3 mt-4">
              <label className="block">
                <span className="text-xs font-medium text-white/60">Type</span>
                <select
                  value={requestModal.requestType}
                  onChange={(e) => setRequestModal({
                    ...requestModal,
                    requestType: e.target.value as "general" | "trial" | "demo",
                  })}
                  disabled={requestModal.busy}
                  className="mt-1 w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500/40 disabled:opacity-50"
                >
                  <option value="general">General</option>
                  <option value="trial">Trial request</option>
                  <option value="demo">Demo request</option>
                </select>
              </label>
              <label className="block">
                <span className="text-xs font-medium text-white/60">Subject (optional)</span>
                <input
                  type="text"
                  value={requestModal.subject}
                  onChange={(e) => setRequestModal({ ...requestModal, subject: e.target.value })}
                  maxLength={200}
                  disabled={requestModal.busy}
                  placeholder="Trial of Enterprise Silver / Follow-up call / …"
                  className="mt-1 w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40 disabled:opacity-50"
                />
              </label>
              <label className="block">
                <span className="text-xs font-medium text-white/60">Message</span>
                <textarea
                  value={requestModal.message}
                  onChange={(e) => setRequestModal({ ...requestModal, message: e.target.value })}
                  maxLength={5000}
                  rows={4}
                  disabled={requestModal.busy}
                  placeholder="What did the user ask for? This becomes the body of the request."
                  className="mt-1 w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40 disabled:opacity-50 resize-y"
                />
              </label>
              <label className="block">
                <span className="text-xs font-medium text-white/60">Internal note (optional, never shown to user)</span>
                <textarea
                  value={requestModal.internalNote}
                  onChange={(e) => setRequestModal({ ...requestModal, internalNote: e.target.value })}
                  maxLength={2000}
                  rows={3}
                  disabled={requestModal.busy}
                  placeholder="Context for whoever picks this up. Phone call notes, billing context, …"
                  className="mt-1 w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40 disabled:opacity-50 resize-y"
                />
              </label>
            </div>
            <div className="flex justify-end gap-3 mt-5">
              <button
                onClick={() => setRequestModal(null)}
                disabled={requestModal.busy}
                className="px-4 py-2 text-sm text-white/50 hover:text-white transition-colors disabled:opacity-40"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateRequest}
                disabled={requestModal.busy || !requestModal.message.trim()}
                className="px-4 py-2 text-sm bg-blue-500/10 text-blue-300 border border-blue-500/30 rounded-lg hover:bg-blue-500/20 transition-colors disabled:opacity-40 flex items-center gap-2"
              >
                {requestModal.busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <MessageSquarePlus className="w-3.5 h-3.5" />}
                {requestModal.busy ? "Creating…" : "Create request"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk action confirmation (only for destructive actions) */}
      {bulkConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-[#0d1424] border border-white/[0.08] rounded-xl p-6 w-full max-w-md shadow-2xl">
            <h2 className="text-base font-semibold text-white mb-2">
              {bulkConfirm.action === "delete" ? "Delete users permanently?" : "Suspend users?"}
            </h2>
            <p className="text-sm text-white/50 mb-1">
              You're about to <span className="text-white font-medium">{bulkConfirm.action.replace("_", " ")}</span>{" "}
              <span className="text-white font-medium">{bulkConfirm.ids.length}</span> user{bulkConfirm.ids.length === 1 ? "" : "s"}.
              {bulkConfirm.action === "delete" && (
                <span className="block mt-1 text-red-400/80">All memberships, API keys, and scan history go with them. This cannot be undone.</span>
              )}
            </p>
            <p className="text-xs text-white/40 mt-3">
              Superadmin accounts in the selection are skipped automatically.
            </p>
            <div className="flex justify-end gap-3 mt-5">
              <button
                onClick={() => setBulkConfirm(null)}
                disabled={!!bulkBusy}
                className="px-4 py-2 text-sm text-white/50 hover:text-white transition-colors disabled:opacity-40"
              >
                Cancel
              </button>
              <button
                onClick={() => runBulk(bulkConfirm.action, bulkConfirm.ids)}
                disabled={!!bulkBusy}
                className={`px-4 py-2 text-sm rounded-lg transition-colors disabled:opacity-40 flex items-center gap-2 ${
                  bulkConfirm.action === "delete"
                    ? "bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20"
                    : "bg-amber-500/10 text-amber-300 border border-amber-500/20 hover:bg-amber-500/20"
                }`}
              >
                {bulkBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : null}
                {bulkBusy
                  ? "Working…"
                  : bulkConfirm.action === "delete"
                    ? `Delete ${bulkConfirm.ids.length}`
                    : `Suspend ${bulkConfirm.ids.length}`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk action result summary — shown after a partial failure
          so the admin sees who was skipped/errored. Auto-closes when
          dismissed; the inline banner already gives the headline. */}
      {bulkSummary && (bulkSummary.summary.skippedCount > 0 || bulkSummary.summary.errorsCount > 0) && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-[#0d1424] border border-white/[0.08] rounded-xl p-6 w-full max-w-lg shadow-2xl max-h-[80vh] overflow-y-auto">
            <h2 className="text-base font-semibold text-white mb-1">
              Bulk {bulkSummary.action.replace("_", " ")} — results
            </h2>
            <p className="text-xs text-white/40 mb-4">
              {bulkSummary.summary.processedCount} processed ·
              {" "}{bulkSummary.summary.skippedCount} skipped ·
              {" "}{bulkSummary.summary.errorsCount} errored
            </p>
            {bulkSummary.skipped.length > 0 && (
              <div className="mb-3">
                <h3 className="text-[11px] font-semibold uppercase tracking-wider text-white/40 mb-1.5">Skipped</h3>
                <div className="space-y-0.5 text-xs">
                  {bulkSummary.skipped.map((s) => (
                    <div key={`s-${s.userId}`} className="flex items-center gap-2 text-white/60">
                      <span className="font-mono text-white/30">#{s.userId}</span>
                      {s.email && <span>{s.email}</span>}
                      <span className="text-white/40">— {s.reason.replace(/_/g, " ")}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {bulkSummary.errors.length > 0 && (
              <div className="mb-3">
                <h3 className="text-[11px] font-semibold uppercase tracking-wider text-red-400 mb-1.5">Errors</h3>
                <div className="space-y-0.5 text-xs">
                  {bulkSummary.errors.map((e) => (
                    <div key={`e-${e.userId}`} className="flex items-center gap-2 text-red-300">
                      <span className="font-mono text-red-300/50">#{e.userId}</span>
                      <span>{e.error}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            <div className="flex justify-end mt-2">
              <button
                onClick={() => setBulkSummary(null)}
                className="px-4 py-2 text-sm text-white/60 hover:text-white transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reset MFA confirmation modal */}
      {mfaResetConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1424] border border-white/[0.08] rounded-xl p-6 w-full max-w-sm shadow-2xl">
            <h2 className="text-base font-semibold text-white mb-2">Reset MFA for this user?</h2>
            <p className="text-sm text-white/50 mb-1">
              <span className="text-white font-medium">{mfaResetConfirm.email}</span> will lose
              their authenticator and recovery key. They will need to re-enrol on next login.
            </p>
            <p className="text-xs text-amber-400/80 mb-5">
              Confirm the user&apos;s identity through a separate channel before doing this.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setMfaResetConfirm(null)}
                disabled={mfaResetBusy === mfaResetConfirm.id}
                className="px-4 py-2 text-sm text-white/50 hover:text-white transition-colors disabled:opacity-40"
              >
                Cancel
              </button>
              <button
                onClick={handleResetMfa}
                disabled={mfaResetBusy === mfaResetConfirm.id}
                className="px-4 py-2 text-sm bg-amber-500/10 text-amber-300 border border-amber-500/20 rounded-lg hover:bg-amber-500/20 transition-colors disabled:opacity-40"
              >
                {mfaResetBusy === mfaResetConfirm.id ? "Resetting…" : "Reset MFA"}
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
