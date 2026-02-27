// FILE: app/(authenticated)/settings/account/page.tsx
// Combined Account & Team — profile, org info, team members, invitations
"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  User, Mail, Shield, Save, Crown, Eye, EyeOff,
  Users, UserPlus, Trash2, Copy, Check, Info, X, Lock,
  RefreshCcw, Briefcase, Building2, Globe, Hash,
} from "lucide-react";
import { cn } from "../../../lib/utils";
import { Button } from "../../../ui/button";
import { Input } from "../../../ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../../ui/dialog";
import {
  getMembers, inviteMember, getInvitations, revokeInvitation,
  updateMemberRole, removeMember, apiFetch, isPlanError,
} from "../../../lib/api";
import { useOrg } from "../../contexts/OrgContext";
import { usePlanLimit, PlanLimitDialog } from "../../../ui/plan-limit-dialog";

// ─── Helpers ──────────────────────────────────────

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  let d: Date;
  if (typeof iso === "string" && !iso.endsWith("Z") && !iso.includes("+")) d = new Date(iso + "Z");
  else d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

const ROLE_COLORS: Record<string, string> = {
  owner: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  admin: "bg-purple-500/15 text-purple-300 border-purple-500/30",
  analyst: "bg-blue-500/15 text-blue-300 border-blue-500/30",
  viewer: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
};
const ROLE_ICONS: Record<string, React.ElementType> = {
  owner: Crown, admin: Shield, analyst: Eye, viewer: EyeOff,
};

const PLAN_COLORS: Record<string, string> = {
  free: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
  starter: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
  professional: "bg-purple-500/15 text-purple-300 border-purple-500/30",
  enterprise_silver: "bg-orange-500/15 text-orange-300 border-orange-500/30",
  enterprise_gold: "bg-yellow-500/15 text-yellow-300 border-yellow-500/30",
};

const INDUSTRY_OPTIONS = [
  "Managed Security (MSSP/MSP)",
  "Financial Services",
  "Healthcare",
  "Technology / SaaS",
  "Government",
  "Education",
  "Retail / E-commerce",
  "Manufacturing",
  "Energy / Utilities",
  "Telecommunications",
  "Legal / Professional Services",
  "Media / Entertainment",
  "Non-profit",
  "Other",
];

const SIZE_OPTIONS = [
  { value: "", label: "Select..." },
  { value: "1-10", label: "1–10 employees" },
  { value: "11-50", label: "11–50 employees" },
  { value: "51-200", label: "51–200 employees" },
  { value: "201-500", label: "201–500 employees" },
  { value: "501-1000", label: "501–1,000 employees" },
  { value: "1001+", label: "1,000+ employees" },
];

// ─── Page ──────────────────────────────────────

export default function AccountPage() {
  const { user, organization, role, canDo, plan, planLabel, refresh: refreshOrg } = useOrg();
  const planLimit = usePlanLimit();

  // Profile state
  const [name, setName] = useState("");
  const [jobTitle, setJobTitle] = useState("");
  const [savingProfile, setSavingProfile] = useState(false);

  // Password state
  const [showPasswordSection, setShowPasswordSection] = useState(false);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [savingPassword, setSavingPassword] = useState(false);

  // Organization state
  const [orgName, setOrgName] = useState("");
  const [orgIndustry, setOrgIndustry] = useState("");
  const [orgSize, setOrgSize] = useState("");
  const [orgWebsite, setOrgWebsite] = useState("");
  const [savingOrg, setSavingOrg] = useState(false);

  // Team state
  const [members, setMembers] = useState<any[]>([]);
  const [invitations, setInvitations] = useState<any[]>([]);
  const [loadingTeam, setLoadingTeam] = useState(true);
  const [refreshingTeam, setRefreshingTeam] = useState(false);

  // Invite modal
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("analyst");
  const [inviting, setInviting] = useState(false);
  const [inviteLink, setInviteLink] = useState<string | null>(null);
  const [inviteCopied, setInviteCopied] = useState(false);

  // Role edit
  const [roleEditId, setRoleEditId] = useState<string | null>(null);

  // Remove modal
  const [deleteTarget, setDeleteTarget] = useState<any>(null);
  const [deleting, setDeleting] = useState(false);

  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  // Permissions
  const canInvite = canDo("invite_users");
  const canManageRoles = canDo("manage_roles");
  const canRemove = canDo("remove_users");
  const canEditOrg = role === "owner" || role === "admin";

  // Auto-clear banner
  useEffect(() => { if (banner) { const t = setTimeout(() => setBanner(null), 5000); return () => clearTimeout(t); } }, [banner]);

  // Load profile data from OrgContext
  useEffect(() => {
    if (user) {
      setName(user.name || "");
      setJobTitle((user as any).jobTitle || (user as any).job_title || "");
    }
  }, [user]);

  // Load organization data from OrgContext
  useEffect(() => {
    if (organization) {
      setOrgName((organization as any).name || "");
      setOrgIndustry((organization as any).industry || "");
      setOrgSize((organization as any).size || (organization as any).company_size || "");
      setOrgWebsite((organization as any).website || "");
    }
  }, [organization]);

  // Load team
  const loadTeam = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshingTeam(true); else setLoadingTeam(true);
    try {
      const [m, i] = await Promise.all([
        getMembers(),
        canInvite ? getInvitations().catch(() => []) : Promise.resolve([]),
      ]);
      setMembers(m);
      setInvitations(i);
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed to load team" });
    } finally { setLoadingTeam(false); setRefreshingTeam(false); }
  }, [canInvite, planLimit]);

  useEffect(() => { loadTeam(); }, [canInvite]);

  // ─── Handlers ──────────────────────────────────────

  async function handleSaveProfile() {
    if (!name.trim()) return;
    try {
      setSavingProfile(true);
      await apiFetch<any>("/settings/me", {
        method: "PATCH",
        body: JSON.stringify({ name: name.trim(), jobTitle: jobTitle.trim() || null }),
      });
      setBanner({ kind: "ok", text: "Profile updated." });
      refreshOrg();
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed to update." });
    } finally { setSavingProfile(false); }
  }

  async function handleSaveOrg() {
    if (!orgName.trim()) return;
    try {
      setSavingOrg(true);
      await apiFetch<any>("/settings/organization", {
        method: "PATCH",
        body: JSON.stringify({
          name: orgName.trim(),
          industry: orgIndustry || null,
          size: orgSize || null,
          website: orgWebsite.trim() || null,
        }),
      });
      setBanner({ kind: "ok", text: "Organization updated." });
      refreshOrg();
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed to update organization." });
    } finally { setSavingOrg(false); }
  }

  async function handleChangePassword() {
    if (!currentPassword || !newPassword) return;
    if (newPassword !== confirmPassword) {
      setBanner({ kind: "err", text: "New passwords don't match." });
      return;
    }
    if (newPassword.length < 8) {
      setBanner({ kind: "err", text: "Password must be at least 8 characters." });
      return;
    }
    try {
      setSavingPassword(true);
      await apiFetch<any>("/auth/change-password", {
        method: "POST",
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      setBanner({ kind: "ok", text: "Password changed." });
      setCurrentPassword(""); setNewPassword(""); setConfirmPassword("");
      setShowPasswordSection(false);
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to change password." });
    } finally { setSavingPassword(false); }
  }

  async function handleInvite() {
    if (!inviteEmail.trim()) return;
    try {
      setInviting(true);
      const result = await inviteMember({ email: inviteEmail.trim(), role: inviteRole });
      setInviteLink(`${window.location.origin}/invite/${result.token}`);
      setInviteEmail("");
      await loadTeam(true);
    } catch (e: any) {
      if (isPlanError(e)) { setInviteOpen(false); planLimit.handle(e.planError); }
      else setBanner({ kind: "err", text: e?.message || "Failed" });
    } finally { setInviting(false); }
  }

  async function handleRevokeInvite(id: string) {
    try {
      await revokeInvitation(id);
      setBanner({ kind: "ok", text: "Invitation revoked." });
      await loadTeam(true);
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed" }); }
  }

  async function handleRoleChange(memberId: string, newRole: string) {
    try {
      await updateMemberRole(memberId, newRole);
      setBanner({ kind: "ok", text: "Role updated." });
      setRoleEditId(null);
      await loadTeam(true);
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed" });
    }
  }

  async function handleRemove() {
    if (!deleteTarget) return;
    try {
      setDeleting(true);
      await removeMember(deleteTarget.id);
      setBanner({ kind: "ok", text: "Member removed." });
      setDeleteTarget(null);
      await loadTeam(true);
    } catch (e: any) {
      if (isPlanError(e)) { setDeleteTarget(null); planLimit.handle(e.planError); }
      else setBanner({ kind: "err", text: e?.message || "Failed" });
    } finally { setDeleting(false); }
  }

  const RIcon = ROLE_ICONS[role || "viewer"] || User;
  const profileDirty = name.trim() !== (user?.name || "") || (jobTitle.trim() || "") !== ((user as any)?.jobTitle || (user as any)?.job_title || "");
  const orgDirty =
    orgName.trim() !== ((organization as any)?.name || "") ||
    (orgIndustry || "") !== ((organization as any)?.industry || "") ||
    (orgSize || "") !== ((organization as any)?.size || (organization as any)?.company_size || "") ||
    (orgWebsite.trim() || "") !== ((organization as any)?.website || "");

  return (
    <main className="flex-1 overflow-y-auto bg-background">
      <div className="p-8 space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-semibold text-foreground flex items-center gap-3">
            <User className="w-7 h-7 text-primary" />Account & Team
          </h1>
          <p className="text-muted-foreground mt-1">Manage your profile, organization, and team members.</p>
        </div>

        {/* Banner */}
        {banner && (
          <div className={cn("rounded-xl border px-4 py-3 text-sm flex items-center justify-between",
            banner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>
            <span>{banner.text}</span>
            <button onClick={() => setBanner(null)} className="hover:opacity-70"><X className="w-4 h-4" /></button>
          </div>
        )}

        {/* ═══ TWO-COLUMN LAYOUT ═══ */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">

          {/* ──── LEFT: PROFILE + ORG ──── */}
          <div className="space-y-6">

            {/* Profile Card */}
            <div className="bg-card border border-border rounded-xl p-6 space-y-5">
              <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
                <User className="w-5 h-5 text-primary" />Personal Information
              </h2>

              {/* Avatar + identity */}
              <div className="flex items-center gap-4">
                <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center shrink-0">
                  <span className="text-2xl font-bold text-primary">
                    {(user?.name || user?.email || "?")[0].toUpperCase()}
                  </span>
                </div>
                <div className="min-w-0 space-y-1.5">
                  <div>
                    <div className="text-lg font-medium text-foreground truncate leading-tight">{user?.name || "Unnamed"}</div>
                    <div className="text-sm text-muted-foreground flex items-center gap-1.5 mt-1">
                      <Mail className="w-3.5 h-3.5 shrink-0" />
                      <span className="truncate">{user?.email}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10px] font-bold uppercase", ROLE_COLORS[role || "viewer"])}>
                      <RIcon className="w-3 h-3" />{role}
                    </span>
                    <span className={cn("inline-flex items-center px-2 py-0.5 rounded-md border text-[10px] font-bold uppercase", PLAN_COLORS[plan] || PLAN_COLORS.free)}>
                      {planLabel}
                    </span>
                  </div>
                </div>
              </div>

              {/* Editable fields */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-sm font-medium text-foreground block">Display Name</label>
                  <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Your name" />
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium text-foreground block">Job Title</label>
                  <div className="relative">
                    <Briefcase className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input value={jobTitle} onChange={(e) => setJobTitle(e.target.value)} placeholder="e.g., Security Engineer" className="pl-9" />
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setShowPasswordSection(!showPasswordSection)}
                  className="gap-1.5 text-xs"
                >
                  <Lock className="w-3.5 h-3.5" />
                  {showPasswordSection ? "Cancel" : "Change Password"}
                </Button>
                <Button
                  onClick={handleSaveProfile}
                  disabled={savingProfile || !name.trim() || !profileDirty}
                  className="bg-primary hover:bg-primary/90"
                >
                  <Save className="w-4 h-4 mr-2" />{savingProfile ? "Saving..." : "Save Profile"}
                </Button>
              </div>

              {/* Change Password (collapsible) */}
              {showPasswordSection && (
                <div className="border-t border-border pt-4 space-y-4">
                  <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
                    <Lock className="w-4 h-4 text-primary" />Change Password
                  </h3>
                  <div className="space-y-3">
                    <div className="space-y-1.5">
                      <label className="text-xs font-medium text-muted-foreground">Current Password</label>
                      <Input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} placeholder="••••••••" />
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div className="space-y-1.5">
                        <label className="text-xs font-medium text-muted-foreground">New Password</label>
                        <Input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="Min 8 characters" />
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-xs font-medium text-muted-foreground">Confirm Password</label>
                        <Input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} placeholder="Re-enter password" />
                      </div>
                    </div>
                    {newPassword && confirmPassword && newPassword !== confirmPassword && (
                      <p className="text-xs text-red-400">Passwords don't match.</p>
                    )}
                    <Button
                      size="sm"
                      onClick={handleChangePassword}
                      disabled={savingPassword || !currentPassword || !newPassword || newPassword !== confirmPassword}
                      className="bg-primary hover:bg-primary/90"
                    >
                      <Lock className="w-3.5 h-3.5 mr-1.5" />{savingPassword ? "Changing..." : "Update Password"}
                    </Button>
                  </div>
                </div>
              )}
            </div>

            {/* ──── ORGANIZATION CARD ──── */}
            <div className="bg-card border border-border rounded-xl p-6 space-y-5">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
                  <Building2 className="w-5 h-5 text-primary" />Organization
                </h2>
                {!canEditOrg && (
                  <span className="text-xs text-muted-foreground flex items-center gap-1">
                    <Lock className="w-3 h-3" />Only owners and admins can edit
                  </span>
                )}
              </div>

              {/* Org identity display */}
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                  <Building2 className="w-6 h-6 text-primary" />
                </div>
                <div className="min-w-0">
                  <div className="text-base font-medium text-foreground truncate">
                    {(organization as any)?.name || "Unnamed Organization"}
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className={cn(
                      "inline-flex items-center px-2 py-0.5 rounded-md border text-[10px] font-bold uppercase",
                      PLAN_COLORS[plan] || PLAN_COLORS.free
                    )}>
                      {planLabel}
                    </span>
                    {(organization as any)?.slug && (
                      <span className="text-xs text-muted-foreground font-mono">
                        {(organization as any).slug}
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Editable org fields */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-sm font-medium text-foreground block">Organization Name</label>
                  <div className="relative">
                    <Building2 className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      value={orgName}
                      onChange={(e) => setOrgName(e.target.value)}
                      placeholder="Your company name"
                      className="pl-9"
                      disabled={!canEditOrg}
                    />
                  </div>
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium text-foreground block">Industry</label>
                  <select
                    value={orgIndustry}
                    onChange={(e) => setOrgIndustry(e.target.value)}
                    disabled={!canEditOrg}
                    className={cn(
                      "w-full h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground",
                      !canEditOrg && "opacity-60 cursor-not-allowed"
                    )}
                  >
                    <option value="">Select industry...</option>
                    {INDUSTRY_OPTIONS.map((ind) => (
                      <option key={ind} value={ind}>{ind}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-sm font-medium text-foreground block">Company Size</label>
                  <div className="relative">
                    <Hash className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <select
                      value={orgSize}
                      onChange={(e) => setOrgSize(e.target.value)}
                      disabled={!canEditOrg}
                      className={cn(
                        "w-full h-10 rounded-md border border-border bg-background pl-9 pr-3 text-sm text-foreground appearance-none",
                        !canEditOrg && "opacity-60 cursor-not-allowed"
                      )}
                    >
                      {SIZE_OPTIONS.map((opt) => (
                        <option key={opt.value} value={opt.value}>{opt.label}</option>
                      ))}
                    </select>
                  </div>
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium text-foreground block">Website</label>
                  <div className="relative">
                    <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      value={orgWebsite}
                      onChange={(e) => setOrgWebsite(e.target.value)}
                      placeholder="https://yourcompany.com"
                      className="pl-9"
                      disabled={!canEditOrg}
                    />
                  </div>
                </div>
              </div>

              {canEditOrg && (
                <div className="flex justify-end">
                  <Button
                    onClick={handleSaveOrg}
                    disabled={savingOrg || !orgName.trim() || !orgDirty}
                    className="bg-primary hover:bg-primary/90"
                  >
                    <Save className="w-4 h-4 mr-2" />{savingOrg ? "Saving..." : "Save Organization"}
                  </Button>
                </div>
              )}
            </div>

          </div>

          {/* ──── RIGHT: TEAM ──── */}
          <div className="space-y-6">

            {/* Team Header */}
            <div className="bg-card border border-border rounded-xl overflow-hidden">
              <div className="flex items-center justify-between px-6 py-4 border-b border-border">
                <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
                  <Users className="w-5 h-5 text-primary" />Team Members
                  <span className="text-sm font-normal text-muted-foreground">({members.length})</span>
                </h2>
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" onClick={() => loadTeam(true)} disabled={refreshingTeam} className="border-border text-foreground hover:bg-accent">
                    <RefreshCcw className={cn("w-3.5 h-3.5", refreshingTeam && "animate-spin")} />
                  </Button>
                  {canInvite && (
                    <Button size="sm" onClick={() => { setInviteOpen(true); setInviteLink(null); setInviteEmail(""); setInviteRole("analyst"); }} className="bg-primary hover:bg-primary/90">
                      <UserPlus className="w-3.5 h-3.5 mr-1.5" />Invite
                    </Button>
                  )}
                </div>
              </div>

              {/* Column headers */}
              {members.length > 0 && (
                <div className="flex items-center px-6 py-2 border-b border-border bg-muted/30 gap-4">
                  <span className="text-xs font-semibold text-muted-foreground uppercase flex-1">Member</span>
                  <span className="text-xs font-semibold text-muted-foreground uppercase w-20 text-right">Role</span>
                  <span className="text-xs font-semibold text-muted-foreground uppercase w-20 text-right">Joined</span>
                  {canRemove && <span className="w-8" />}
                </div>
              )}

              {/* Members Table */}
              {loadingTeam ? (
                <div className="p-6 text-muted-foreground text-sm">Loading...</div>
              ) : members.length === 0 ? (
                <div className="p-12 text-center">
                  <Users className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" />
                  <p className="text-muted-foreground text-sm">No team members found.</p>
                </div>
              ) : (
                <div className="divide-y divide-border">
                  {members.map((m) => {
                    const MIcon = ROLE_ICONS[m.role] || Eye;
                    return (
                      <div key={m.id} className="flex items-center px-6 py-3.5 hover:bg-accent/30 transition-colors gap-4">
                        <div className="flex items-center gap-3 min-w-0 flex-1">
                          <div className="w-9 h-9 rounded-full bg-primary/10 flex items-center justify-center shrink-0">
                            <span className="text-sm font-bold text-primary">{(m.name || m.email || "?")[0].toUpperCase()}</span>
                          </div>
                          <div className="min-w-0">
                            <div className="text-sm font-medium text-foreground truncate">{m.name || "Unnamed"}</div>
                            <div className="text-xs text-muted-foreground truncate">{m.email}</div>
                          </div>
                        </div>
                        <div className="w-20 flex justify-end shrink-0">
                          {roleEditId === m.id && canManageRoles ? (
                            <select
                              value={m.role}
                              onChange={(e) => handleRoleChange(m.id, e.target.value)}
                              onBlur={() => setRoleEditId(null)}
                              autoFocus
                              className="h-7 rounded-md border border-border bg-background px-1.5 text-xs text-foreground"
                            >
                              <option value="owner">Owner</option>
                              <option value="admin">Admin</option>
                              <option value="analyst">Analyst</option>
                              <option value="viewer">Viewer</option>
                            </select>
                          ) : (
                            <button
                              type="button"
                              onClick={() => canManageRoles && setRoleEditId(m.id)}
                              className={cn(
                                "inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10px] font-bold uppercase whitespace-nowrap",
                                ROLE_COLORS[m.role] || ROLE_COLORS.viewer,
                                canManageRoles && "cursor-pointer hover:opacity-80"
                              )}
                            >
                              <MIcon className="w-3 h-3" />{m.role}
                            </button>
                          )}
                        </div>
                        <span className="text-xs text-muted-foreground w-20 text-right shrink-0 whitespace-nowrap">{formatDate(m.joinedAt)}</span>
                        {canRemove && (
                          <div className="w-8 flex justify-center shrink-0">
                            {m.role !== "owner" ? (
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => setDeleteTarget(m)}
                                className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400 hover:bg-red-500/10"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </Button>
                            ) : <span />}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Pending Invitations */}
            {canInvite && invitations.length > 0 && (
              <div className="bg-card border border-border rounded-xl overflow-hidden">
                <div className="px-6 py-3.5 border-b border-border">
                  <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
                    <Mail className="w-4 h-4 text-primary" />Pending Invitations
                    <span className="text-muted-foreground font-normal">({invitations.length})</span>
                  </h3>
                </div>
                <div className="divide-y divide-border">
                  {invitations.map((inv) => (
                    <div key={inv.id} className="flex items-center justify-between px-6 py-3">
                      <div className="min-w-0">
                        <div className="text-sm text-foreground truncate">{inv.email}</div>
                        <div className="text-xs text-muted-foreground">
                          as <span className="font-semibold">{inv.role}</span> · expires {formatDate(inv.expiresAt)}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            navigator.clipboard.writeText(`${window.location.origin}/invite/${inv.token || inv.id}`);
                            setBanner({ kind: "ok", text: "Invite link copied!" });
                          }}
                          className="text-xs h-7"
                        >
                          <Copy className="w-3 h-3 mr-1" />Copy
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleRevokeInvite(inv.id)}
                          className="border-red-500/50 text-red-400 hover:bg-red-500/10 text-xs h-7"
                        >
                          Revoke
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Viewer/Analyst notice */}
            {!canInvite && (
              <div className="bg-card border border-border rounded-xl p-4 text-sm text-muted-foreground flex items-center gap-2">
                <Info className="w-4 h-4 shrink-0" />
                Only admins and owners can invite new members or manage roles.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ═══ MODALS ═══ */}

      {/* Invite Modal */}
      <Dialog open={inviteOpen} onOpenChange={(o) => { if (!o) { setInviteOpen(false); setInviteLink(null); } else setInviteOpen(true); }}>
        <DialogContent className="bg-card border-border text-foreground sm:max-w-[480px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <UserPlus className="w-5 h-5 text-primary" />Invite Team Member
            </DialogTitle>
          </DialogHeader>
          {inviteLink ? (
            <div className="space-y-4 pt-2">
              <div className="flex items-center gap-2 text-sm text-[#b7f7d9]">
                <Check className="w-4 h-4 text-[#10b981]" />Invitation created!
              </div>
              <div className="flex items-center gap-2">
                <code className="flex-1 bg-muted/30 rounded-lg px-3 py-2.5 font-mono text-xs text-foreground break-all border border-border">
                  {inviteLink}
                </code>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => { navigator.clipboard.writeText(inviteLink!); setInviteCopied(true); setTimeout(() => setInviteCopied(false), 2000); }}
                  className="shrink-0"
                >
                  {inviteCopied ? <><Check className="w-3 h-3 mr-1" />Copied</> : <><Copy className="w-3 h-3 mr-1" />Copy</>}
                </Button>
              </div>
              <p className="text-xs text-muted-foreground flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5" />This link expires in 7 days.
              </p>
              <div className="flex gap-3 justify-end pt-2">
                <Button onClick={() => { setInviteOpen(false); setInviteLink(null); }} className="bg-primary hover:bg-primary/90">Done</Button>
              </div>
            </div>
          ) : (
            <div className="space-y-4 pt-2">
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-foreground block">Email Address</label>
                <Input type="email" placeholder="colleague@company.com" value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} />
              </div>
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-foreground block">Role</label>
                <select value={inviteRole} onChange={(e) => setInviteRole(e.target.value)} className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm">
                  {role === "owner" && <option value="admin">Admin</option>}
                  <option value="analyst">Analyst</option>
                  <option value="viewer">Viewer</option>
                </select>
                <p className="text-xs text-muted-foreground">
                  {inviteRole === "admin" ? "Can manage assets, scans, team, and settings." :
                   inviteRole === "analyst" ? "Can create/edit assets and run scans." :
                   "Read-only access to assets and findings."}
                </p>
              </div>
              <div className="flex gap-3 justify-end pt-2">
                <Button variant="outline" onClick={() => setInviteOpen(false)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
                <Button onClick={handleInvite} disabled={inviting || !inviteEmail.trim()} className="bg-primary hover:bg-primary/90">
                  <UserPlus className="w-4 h-4 mr-2" />{inviting ? "Creating..." : "Create Invitation"}
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Remove Modal */}
      <Dialog open={!!deleteTarget} onOpenChange={(o) => { if (!o) setDeleteTarget(null); }}>
        <DialogContent className="bg-card border-border text-foreground sm:max-w-[440px]">
          <DialogHeader><DialogTitle>Remove Member</DialogTitle></DialogHeader>
          <p className="text-sm text-muted-foreground">
            Remove <span className="text-foreground font-semibold">{deleteTarget?.name || deleteTarget?.email}</span>?
            They will lose all access immediately.
          </p>
          <div className="flex gap-3 justify-end pt-4">
            <Button variant="outline" onClick={() => setDeleteTarget(null)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
            <Button onClick={handleRemove} disabled={deleting} className="bg-[#ef4444] hover:bg-[#dc2626] text-white">
              {deleting ? "Removing..." : "Remove"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Plan Limit Dialog */}
      <PlanLimitDialog {...planLimit} />
    </main>
  );
}