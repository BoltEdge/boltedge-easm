"use client";
import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  getAdminUserDetail, suspendAdminUser, deleteAdminUser, sendAdminPasswordReset,
  impersonateAdminUser, adminForceVerifyEmail, adminResendVerification,
  sendAdminUserEmail, createAdminUserRequest, resetAdminUserMfa,
  type AdminUserDetail,
} from "../../../../lib/api";
import { startImpersonation, getIsRootAdmin } from "../../../../lib/auth";
import {
  ArrowLeft, ShieldAlert, ShieldOff, ShieldCheck, Trash2, KeyRound,
  Copy, Check, X, UserCog, Mail, MailCheck, MailWarning, ExternalLink,
  Send, MessageSquarePlus, Loader2, Building2, Calendar, Globe,
  Briefcase, Clock, AlertCircle, ScrollText, MessageSquare, Lock, Unlock,
  Crown,
} from "lucide-react";

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

const REQUEST_STATUS_COLORS: Record<string, string> = {
  open: "text-amber-300 bg-amber-500/10 border-amber-500/20",
  in_progress: "text-blue-300 bg-blue-500/10 border-blue-500/20",
  replied: "text-emerald-300 bg-emerald-500/10 border-emerald-500/20",
  closed: "text-white/40 bg-white/5 border-white/10",
  spam: "text-red-300 bg-red-500/10 border-red-500/20",
};

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
  if (d < 30) return `${d}d ago`;
  const mo = Math.floor(d / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.floor(mo / 12)}y ago`;
}

function formatDateTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

export default function AdminUserDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const userId = Number(id);

  const [user, setUser] = useState<AdminUserDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  // Action busy flags
  const [actionBusy, setActionBusy] = useState<string | null>(null);

  // Modal state
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [resetModal, setResetModal] = useState<{ link?: string; emailSent?: boolean; busy: boolean } | null>(null);
  const [copied, setCopied] = useState(false);
  const [emailModal, setEmailModal] = useState<{ subject: string; body: string; busy: boolean } | null>(null);
  const [mfaResetConfirmOpen, setMfaResetConfirmOpen] = useState(false);
  const [requestModal, setRequestModal] = useState<{
    requestType: "general" | "trial" | "demo";
    subject: string;
    message: string;
    internalNote: string;
    busy: boolean;
  } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setUser(await getAdminUserDetail(userId));
    } catch (e: any) {
      setError(e?.message || "Failed to load user");
    } finally {
      setLoading(false);
    }
  }, [userId]);

  useEffect(() => { if (Number.isFinite(userId)) load(); }, [userId, load]);
  useEffect(() => {
    if (banner) {
      const t = setTimeout(() => setBanner(null), 4500);
      return () => clearTimeout(t);
    }
  }, [banner]);

  async function handleSuspend() {
    if (!user) return;
    setActionBusy("suspend");
    try {
      const res = await suspendAdminUser(user.id);
      const label = res.isSuspended ? "suspended" : "unsuspended";
      setBanner({ kind: "ok", text: `User ${label}.` });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to update user" });
    } finally { setActionBusy(null); }
  }

  async function handleForceVerify() {
    if (!user) return;
    setActionBusy("verify");
    try {
      await adminForceVerifyEmail(user.id);
      setBanner({ kind: "ok", text: "Email marked as verified." });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to verify" });
    } finally { setActionBusy(null); }
  }

  async function handleResendVerification() {
    if (!user) return;
    setActionBusy("resend");
    try {
      const res = await adminResendVerification(user.id);
      setBanner({
        kind: res.emailSent ? "ok" : "err",
        text: res.message || (res.emailSent ? "Verification email sent." : "Send failed."),
      });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to send" });
    } finally { setActionBusy(null); }
  }

  async function handleImpersonate() {
    if (!user) return;
    setActionBusy("impersonate");
    try {
      const res = await impersonateAdminUser(user.id);
      startImpersonation(res.accessToken, res.user, res.organization ?? null, res.role ?? null);
      window.location.href = "/dashboard";
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to impersonate" });
      setActionBusy(null);
    }
  }

  async function handleResetPassword() {
    if (!user) return;
    setResetModal({ busy: true });
    try {
      const res = await sendAdminPasswordReset(user.id);
      setResetModal({ link: res.link, emailSent: res.emailSent, busy: false });
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to generate reset link" });
      setResetModal(null);
    }
  }

  async function handleResetMfa() {
    if (!user) return;
    setActionBusy("reset_mfa");
    try {
      const res = await resetAdminUserMfa(user.id);
      setBanner({
        kind: "ok",
        text: res.message || `MFA reset for ${user.email}.`,
      });
      setMfaResetConfirmOpen(false);
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to reset MFA" });
      setMfaResetConfirmOpen(false);
    } finally {
      setActionBusy(null);
    }
  }

  async function handleDelete() {
    if (!user) return;
    setActionBusy("delete");
    try {
      await deleteAdminUser(user.id);
      setBanner({ kind: "ok", text: "User deleted." });
      // Bounce back to the list — there's nothing to show on this
      // page anymore.
      setTimeout(() => router.push("/admin/users"), 600);
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to delete" });
      setActionBusy(null);
    }
  }

  async function handleSendEmail() {
    if (!user || !emailModal) return;
    if (!emailModal.subject.trim() || !emailModal.body.trim()) return;
    setEmailModal({ ...emailModal, busy: true });
    try {
      await sendAdminUserEmail(user.id, {
        subject: emailModal.subject.trim(),
        body: emailModal.body.trim(),
      });
      setBanner({ kind: "ok", text: `Email sent to ${user.email}.` });
      setEmailModal(null);
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to send" });
      setEmailModal((m) => (m ? { ...m, busy: false } : null));
    }
  }

  async function handleCreateRequest() {
    if (!user || !requestModal) return;
    if (!requestModal.message.trim()) return;
    setRequestModal({ ...requestModal, busy: true });
    try {
      const res = await createAdminUserRequest(user.id, {
        requestType: requestModal.requestType,
        subject: requestModal.subject.trim() || undefined,
        message: requestModal.message.trim(),
        internalNote: requestModal.internalNote.trim() || undefined,
      });
      setBanner({
        kind: "ok",
        text: `Request ${res.request.publicId || `#${res.request.id}`} opened.`,
      });
      setRequestModal(null);
      load(); // refresh contact-request list
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to create" });
      setRequestModal((m) => (m ? { ...m, busy: false } : null));
    }
  }

  if (!Number.isFinite(userId)) {
    return <div className="text-sm text-red-400">Invalid user id.</div>;
  }

  if (loading && !user) {
    return (
      <div className="flex items-center gap-2 text-sm text-white/40">
        <Loader2 className="w-4 h-4 animate-spin" /> Loading user…
      </div>
    );
  }

  if (error || !user) {
    return (
      <div className="space-y-3">
        <Link href="/admin/users" className="text-xs text-white/40 hover:text-white inline-flex items-center gap-1.5">
          <ArrowLeft className="w-3 h-3" /> Back to users
        </Link>
        <div className="rounded-lg px-4 py-3 text-sm bg-red-500/10 text-red-300 border border-red-500/20">
          {error || "User not found."}
        </div>
      </div>
    );
  }

  const primaryMembership = user.memberships.find((m) => m.isActive) || user.memberships[0];
  const planColor = primaryMembership ? (PLAN_COLORS[primaryMembership.plan] || "#6b7280") : "#6b7280";

  return (
    <div className="space-y-5">
      <Link
        href="/admin/users"
        className="text-xs text-white/40 hover:text-white inline-flex items-center gap-1.5"
      >
        <ArrowLeft className="w-3 h-3" /> Back to users
      </Link>

      {banner && (
        <div className={`rounded-lg px-4 py-2.5 text-sm ${
          banner.kind === "ok"
            ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20"
            : "bg-red-500/10 text-red-300 border border-red-500/20"
        }`}>
          {banner.text}
        </div>
      )}

      {/* ── Header card ─────────────────────────────────────────────── */}
      <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
        <div className="flex items-start gap-4">
          <div className="w-14 h-14 rounded-xl bg-teal-500/10 border border-teal-500/20 flex items-center justify-center text-teal-300 text-xl font-semibold shrink-0">
            {user.avatarUrl ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img src={user.avatarUrl} alt="" className="w-full h-full rounded-xl object-cover" />
            ) : (
              (user.firstName?.[0] || user.email[0] || "?").toUpperCase()
            )}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-xl font-semibold text-white truncate">
                {user.name || user.email}
              </h1>
              {user.isRootAdmin && (
                <span className="inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded px-1.5 py-0.5">
                  <Crown className="w-3 h-3" /> Root admin
                </span>
              )}
              {user.isSuperadmin && !user.isRootAdmin && (
                <span className="inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-teal-400 bg-teal-500/10 border border-teal-500/20 rounded px-1.5 py-0.5">
                  <ShieldAlert className="w-3 h-3" /> Superadmin
                </span>
              )}
              {user.mfaEnabled && (
                <span className="inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded px-1.5 py-0.5">
                  <Lock className="w-3 h-3" /> MFA
                </span>
              )}
              {user.isSuspended && (
                <span className="text-[10px] font-semibold uppercase tracking-wider text-red-400 bg-red-500/10 border border-red-500/20 rounded px-1.5 py-0.5">
                  Suspended
                </span>
              )}
            </div>
            <div className="text-sm text-white/50 mt-0.5">{user.email}</div>
            <div className="text-[11px] text-white/30 mt-1 font-mono">
              {user.displayId || `#${user.id}`}
            </div>
          </div>
          {/* Top-right action buttons */}
          <div className="flex flex-wrap items-center gap-1.5 justify-end">
            <button
              onClick={() => setEmailModal({ subject: "", body: "", busy: false })}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs text-teal-300 bg-teal-500/10 border border-teal-500/20 hover:bg-teal-500/20 transition-colors"
            >
              <Send className="w-3 h-3" /> Email
            </button>
            <button
              onClick={() => setRequestModal({ requestType: "general", subject: "", message: "", internalNote: "", busy: false })}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs text-blue-300 bg-blue-500/10 border border-blue-500/20 hover:bg-blue-500/20 transition-colors"
            >
              <MessageSquarePlus className="w-3 h-3" /> Open request
            </button>
            <button
              onClick={handleImpersonate}
              disabled={user.isSuperadmin || actionBusy === "impersonate"}
              title={user.isSuperadmin ? "Cannot impersonate an admin account" : "Impersonate user"}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs text-purple-300 bg-purple-500/10 border border-purple-500/20 hover:bg-purple-500/20 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
            >
              {actionBusy === "impersonate" ? <Loader2 className="w-3 h-3 animate-spin" /> : <UserCog className="w-3 h-3" />}
              Impersonate
            </button>
            <button
              onClick={handleResetPassword}
              disabled={user.isRootAdmin}
              title={user.isRootAdmin ? "Root admins can only be modified via the CLI" : ""}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs text-white/60 bg-white/[0.04] border border-white/[0.08] hover:bg-white/[0.08] hover:text-white transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <KeyRound className="w-3 h-3" /> Reset password
            </button>
          </div>
        </div>
      </div>

      {/* ── Two-column body ─────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left column: profile + memberships */}
        <div className="lg:col-span-1 space-y-4">

          {/* Profile facts */}
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
            <h2 className="text-[10px] font-semibold uppercase tracking-wider text-white/40 mb-3">Profile</h2>
            <dl className="space-y-2.5 text-sm">
              <Row icon={Briefcase} label="Job title" value={user.jobTitle} />
              <Row icon={Building2} label="Company" value={user.company} />
              <Row icon={Globe} label="Country" value={user.country} />
              <Row
                icon={Calendar}
                label="Joined"
                value={user.createdAt ? formatDateTime(user.createdAt) : null}
                hint={user.createdAt ? relativeTime(user.createdAt) : undefined}
              />
              <Row
                icon={Clock}
                label="Last updated"
                value={user.updatedAt ? formatDateTime(user.updatedAt) : null}
                hint={user.updatedAt ? relativeTime(user.updatedAt) : undefined}
              />
            </dl>
          </div>

          {/* Auth + verification */}
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
            <h2 className="text-[10px] font-semibold uppercase tracking-wider text-white/40 mb-3">Authentication</h2>
            <div className="space-y-2.5 text-sm">
              <div className="flex items-start gap-2">
                {user.emailVerified ? (
                  <MailCheck className="w-3.5 h-3.5 text-emerald-400 mt-0.5 shrink-0" />
                ) : (
                  <MailWarning className="w-3.5 h-3.5 text-amber-400 mt-0.5 shrink-0" />
                )}
                <div className="flex-1 min-w-0">
                  <div className={user.emailVerified ? "text-emerald-300" : "text-amber-300"}>
                    {user.emailVerified ? "Email verified" : "Pending verification"}
                  </div>
                  <div className="text-[11px] text-white/40">
                    {user.emailVerified
                      ? user.oauthProvider
                        ? `via ${user.oauthProvider}`
                        : "via email link"
                      : user.emailVerificationSentAt
                        ? `Last sent ${relativeTime(user.emailVerificationSentAt)}`
                        : "Verification email never sent"}
                  </div>
                </div>
              </div>

              {user.oauthProvider && (
                <Row icon={ShieldCheck} label="OAuth provider" value={user.oauthProvider} />
              )}

              <Row
                icon={Mail}
                label="Welcome email"
                value={user.welcomeEmailSentAt ? "Sent" : "Not yet sent"}
                hint={user.welcomeEmailSentAt ? relativeTime(user.welcomeEmailSentAt) : undefined}
              />

              <div className="flex items-start gap-2">
                {user.mfaEnabled ? (
                  <Lock className="w-3.5 h-3.5 text-emerald-400 mt-0.5 shrink-0" />
                ) : (
                  <Unlock className="w-3.5 h-3.5 text-white/30 mt-0.5 shrink-0" />
                )}
                <div className="flex-1 min-w-0">
                  <div className={user.mfaEnabled ? "text-emerald-300" : "text-white/50"}>
                    {user.mfaEnabled ? "MFA enabled" : "MFA not enabled"}
                  </div>
                  <div className="text-[11px] text-white/40">
                    {user.mfaEnabled && user.mfaEnrolledAt
                      ? `Enrolled ${relativeTime(user.mfaEnrolledAt)}`
                      : user.mfaEnabled
                      ? "Enrolled — date unknown"
                      : "User has not set up two-factor authentication"}
                  </div>
                </div>
              </div>
            </div>

            {user.mfaEnabled && (
              <div className="flex items-center gap-2 mt-3 pt-3 border-t border-white/[0.06]">
                <button
                  onClick={() => setMfaResetConfirmOpen(true)}
                  disabled={user.isRootAdmin || actionBusy === "reset_mfa"}
                  title={user.isRootAdmin ? "Root admins can only be modified via the CLI" : undefined}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] text-amber-300 bg-amber-500/10 border border-amber-500/20 hover:bg-amber-500/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {actionBusy === "reset_mfa" ? (
                    <Loader2 className="w-3 h-3 animate-spin" />
                  ) : (
                    <Unlock className="w-3 h-3" />
                  )}
                  Reset MFA
                </button>
              </div>
            )}

            {!user.emailVerified && (
              <div className="flex items-center gap-2 mt-3 pt-3 border-t border-white/[0.06]">
                <button
                  onClick={handleResendVerification}
                  disabled={actionBusy === "resend"}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] text-amber-300 bg-amber-500/10 border border-amber-500/20 hover:bg-amber-500/20 transition-colors disabled:opacity-40"
                >
                  {actionBusy === "resend" ? <Loader2 className="w-3 h-3 animate-spin" /> : <Mail className="w-3 h-3" />}
                  Resend link
                </button>
                <button
                  onClick={handleForceVerify}
                  disabled={actionBusy === "verify"}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] text-emerald-300 bg-emerald-500/10 border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors disabled:opacity-40"
                >
                  {actionBusy === "verify" ? <Loader2 className="w-3 h-3 animate-spin" /> : <MailCheck className="w-3 h-3" />}
                  Force verify
                </button>
              </div>
            )}
          </div>

          {/* Account state controls */}
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
            <h2 className="text-[10px] font-semibold uppercase tracking-wider text-white/40 mb-3">Account state</h2>
            <div className="space-y-2">
              <button
                onClick={handleSuspend}
                disabled={user.isRootAdmin || (user.isSuperadmin && !getIsRootAdmin()) || actionBusy === "suspend"}
                title={
                  user.isRootAdmin
                    ? "Root admins can only be modified via the CLI"
                    : user.isSuperadmin && !getIsRootAdmin()
                    ? "Only a root admin can suspend an admin account"
                    : ""
                }
                className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors disabled:opacity-30 disabled:cursor-not-allowed ${
                  user.isSuspended
                    ? "text-emerald-300 bg-emerald-500/10 border border-emerald-500/20 hover:bg-emerald-500/20"
                    : "text-amber-300 bg-amber-500/10 border border-amber-500/20 hover:bg-amber-500/20"
                }`}
              >
                {actionBusy === "suspend" ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : (user.isSuspended ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldOff className="w-3.5 h-3.5" />)}
                {user.isSuspended ? "Unsuspend account" : "Suspend account"}
              </button>
              <button
                onClick={() => setConfirmDelete(true)}
                disabled={user.isRootAdmin || (user.isSuperadmin && !getIsRootAdmin())}
                title={
                  user.isRootAdmin
                    ? "Root admins can only be modified via the CLI"
                    : user.isSuperadmin && !getIsRootAdmin()
                    ? "Only a root admin can delete an admin account"
                    : ""
                }
                className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-red-400 bg-red-500/10 border border-red-500/20 hover:bg-red-500/20 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <Trash2 className="w-3.5 h-3.5" /> Delete user…
              </button>
            </div>
          </div>

          {/* Memberships */}
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
            <h2 className="text-[10px] font-semibold uppercase tracking-wider text-white/40 mb-3">
              Organizations ({user.memberships.length})
            </h2>
            {user.memberships.length === 0 ? (
              <p className="text-xs text-white/40">User has no organization memberships.</p>
            ) : (
              <div className="space-y-2">
                {user.memberships.map((m) => {
                  const c = PLAN_COLORS[m.plan] || "#6b7280";
                  return (
                    <Link
                      key={m.organizationId}
                      href={`/admin/organizations/${m.organizationId}`}
                      className={`block rounded-lg border px-3 py-2 transition-colors ${
                        m.isActive
                          ? "border-white/[0.08] bg-white/[0.02] hover:bg-white/[0.04]"
                          : "border-white/[0.04] bg-white/[0.01] opacity-60 hover:opacity-80"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 mb-0.5">
                        <span className="text-sm text-white truncate">{m.organizationName}</span>
                        {!m.isActive && (
                          <span className="text-[9px] uppercase tracking-wider text-white/30 px-1.5 py-0.5 rounded bg-white/[0.04] border border-white/[0.06]">left</span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 text-[11px]">
                        <span className={`px-1.5 py-0.5 rounded font-semibold ${ROLE_COLORS[m.role] || "text-white/40"}`}>
                          {m.role}
                        </span>
                        <span className="font-semibold px-1.5 py-0.5 rounded" style={{ backgroundColor: `${c}15`, color: c }}>
                          {m.plan}
                        </span>
                        {m.joinedAt && (
                          <span className="text-white/30">· joined {relativeTime(m.joinedAt)}</span>
                        )}
                      </div>
                    </Link>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Right column: activity */}
        <div className="lg:col-span-2 space-y-4">

          {/* Contact requests */}
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <MessageSquare className="w-3.5 h-3.5 text-white/40" />
                <h2 className="text-[10px] font-semibold uppercase tracking-wider text-white/40">
                  Requests ({user.counts.contactRequestsTotal})
                </h2>
              </div>
              <Link
                href={`/admin/contact-requests?q=${encodeURIComponent(user.email)}`}
                className="text-[11px] text-white/40 hover:text-white inline-flex items-center gap-1"
              >
                See all <ExternalLink className="w-3 h-3" />
              </Link>
            </div>
            {user.contactRequests.length === 0 ? (
              <p className="text-xs text-white/40">No requests from this user yet.</p>
            ) : (
              <div className="space-y-1.5">
                {user.contactRequests.map((r) => (
                  <div
                    key={r.id}
                    className="flex items-center gap-3 px-3 py-2 rounded-lg bg-white/[0.02] border border-white/[0.04]"
                  >
                    <span className="text-[10px] font-mono text-white/30 shrink-0 w-14">{r.displayId || `#${r.id}`}</span>
                    <span className="text-[10px] uppercase font-semibold text-white/50 shrink-0 w-14">{r.type}</span>
                    <span className="text-sm text-white/80 flex-1 min-w-0 truncate">
                      {r.subject || <span className="text-white/30">(no subject)</span>}
                    </span>
                    <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border shrink-0 ${REQUEST_STATUS_COLORS[r.status] || "text-white/40 bg-white/5 border-white/10"}`}>
                      {r.status}
                    </span>
                    <span className="text-[11px] text-white/30 shrink-0 w-16 text-right">
                      {relativeTime(r.createdAt)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Recent audit log */}
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <ScrollText className="w-3.5 h-3.5 text-white/40" />
                <h2 className="text-[10px] font-semibold uppercase tracking-wider text-white/40">
                  Recent activity ({user.counts.auditLogTotal})
                </h2>
              </div>
              <Link
                href={`/admin/audit-log?q=${encodeURIComponent(user.email)}`}
                className="text-[11px] text-white/40 hover:text-white inline-flex items-center gap-1"
              >
                See all <ExternalLink className="w-3 h-3" />
              </Link>
            </div>
            {user.recentAuditLog.length === 0 ? (
              <p className="text-xs text-white/40">No activity yet.</p>
            ) : (
              <div className="space-y-1">
                {user.recentAuditLog.map((e) => (
                  <div
                    key={e.id}
                    className="flex items-start gap-3 px-3 py-2 rounded-lg hover:bg-white/[0.02] transition-colors"
                  >
                    <span className="text-[10px] font-mono text-white/30 shrink-0 w-16 mt-0.5">
                      {e.category || "—"}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="text-[12px] text-white/80 font-mono truncate">
                        {e.action}
                      </div>
                      {e.description && (
                        <div className="text-[11px] text-white/50 truncate" title={e.description}>
                          {e.description}
                        </div>
                      )}
                    </div>
                    <span className="text-[11px] text-white/30 shrink-0 mt-0.5" title={e.createdAt ? formatDateTime(e.createdAt) : ""}>
                      {relativeTime(e.createdAt)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Reset MFA confirm */}
      {mfaResetConfirmOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-[#0d1424] border border-white/[0.08] rounded-xl p-6 w-full max-w-md shadow-2xl">
            <h2 className="text-base font-semibold text-white mb-2">Reset MFA for this user?</h2>
            <p className="text-sm text-white/50 mb-1">
              <span className="text-white font-medium">{user.email}</span> will lose
              their authenticator and recovery key. They will need to re-enrol on next login.
            </p>
            <p className="text-xs text-amber-400/80 mb-5">
              Confirm the user&apos;s identity through a separate channel before doing this.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setMfaResetConfirmOpen(false)}
                disabled={actionBusy === "reset_mfa"}
                className="px-4 py-2 text-sm text-white/50 hover:text-white transition-colors disabled:opacity-40"
              >
                Cancel
              </button>
              <button
                onClick={handleResetMfa}
                disabled={actionBusy === "reset_mfa"}
                className="px-4 py-2 text-sm bg-amber-500/10 text-amber-300 border border-amber-500/20 rounded-lg hover:bg-amber-500/20 transition-colors disabled:opacity-40 flex items-center gap-2"
              >
                {actionBusy === "reset_mfa" && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                {actionBusy === "reset_mfa" ? "Resetting…" : "Reset MFA"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirm */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-[#0d1424] border border-white/[0.08] rounded-xl p-6 w-full max-w-md shadow-2xl">
            <h2 className="text-base font-semibold text-white mb-2">Delete user permanently?</h2>
            <p className="text-sm text-white/50 mb-1">
              <span className="text-white font-medium">{user.email}</span> will be permanently removed along with
              their memberships, API keys, and scan history.
            </p>
            <p className="text-xs text-red-400/80 mb-5">This cannot be undone.</p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setConfirmDelete(false)}
                disabled={actionBusy === "delete"}
                className="px-4 py-2 text-sm text-white/50 hover:text-white transition-colors disabled:opacity-40"
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                disabled={actionBusy === "delete"}
                className="px-4 py-2 text-sm bg-red-500/10 text-red-400 border border-red-500/20 rounded-lg hover:bg-red-500/20 transition-colors disabled:opacity-40 flex items-center gap-2"
              >
                {actionBusy === "delete" && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                {actionBusy === "delete" ? "Deleting…" : "Delete permanently"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reset password modal */}
      {resetModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-[#0d1424] border border-white/[0.08] rounded-xl p-6 w-full max-w-md shadow-2xl">
            <h2 className="text-base font-semibold text-white mb-1">Password reset link</h2>
            <p className="text-xs text-white/40 mb-4">For <span className="text-white/70">{user.email}</span></p>
            {resetModal.busy ? (
              <div className="text-sm text-white/40 py-4 text-center">Generating link…</div>
            ) : (
              <>
                {resetModal.emailSent && (
                  <div className="mb-3 rounded-lg px-3 py-2 bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 text-xs">
                    Reset email sent successfully to {user.email}.
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
                    onClick={() => {
                      if (resetModal.link) {
                        navigator.clipboard.writeText(resetModal.link);
                        setCopied(true);
                        setTimeout(() => setCopied(false), 2000);
                      }
                    }}
                    className="shrink-0 p-1 rounded hover:bg-white/[0.08] text-white/40 hover:text-white transition-colors"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
                <p className="text-xs text-white/30 mb-4">This link expires in 24 hours and can only be used once.</p>
              </>
            )}
            <div className="flex justify-end">
              <button
                onClick={() => { setResetModal(null); setCopied(false); }}
                className="px-4 py-2 text-sm text-white/50 hover:text-white transition-colors"
              >
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
              <div className="flex-1">
                <h2 className="text-base font-semibold text-white">Send email</h2>
                <p className="text-xs text-white/40 mt-0.5">To <span className="text-white/70">{user.email}</span></p>
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
                  className="mt-1 w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500/40 disabled:opacity-50"
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
                  placeholder="Plain text. Newlines preserved. Sent from no-reply@nanoasm.com with the standard branded shell."
                  className="mt-1 w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40 disabled:opacity-50 resize-y"
                />
                <span className="text-[10px] text-white/30 mt-1 block">
                  {emailModal.body.length}/8000 · audit-logged
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
              <div className="flex-1">
                <h2 className="text-base font-semibold text-white">Open a request</h2>
                <p className="text-xs text-white/40 mt-0.5">As <span className="text-white/70">{user.email}</span></p>
              </div>
            </div>
            <div className="space-y-3 mt-4">
              <label className="block">
                <span className="text-xs font-medium text-white/60">Type</span>
                <select
                  value={requestModal.requestType}
                  onChange={(e) => setRequestModal({ ...requestModal, requestType: e.target.value as "general" | "trial" | "demo" })}
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
                  className="mt-1 w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500/40 disabled:opacity-50"
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
                  className="mt-1 w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500/40 disabled:opacity-50 resize-y"
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
    </div>
  );
}

// ─── Small helper for the profile/auth fact rows ────────────────
function Row({
  icon: Icon, label, value, hint,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: React.ReactNode;
  hint?: string;
}) {
  return (
    <div className="flex items-start gap-2">
      <Icon className="w-3.5 h-3.5 text-white/30 mt-0.5 shrink-0" />
      <div className="flex-1 min-w-0">
        <div className="text-[11px] text-white/40 uppercase tracking-wider">{label}</div>
        <div className="text-sm text-white/80 truncate">
          {value || <span className="text-white/30">—</span>}
        </div>
        {hint && <div className="text-[11px] text-white/30">{hint}</div>}
      </div>
    </div>
  );
}
