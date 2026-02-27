// app/(authenticated)/contexts/OrgContext.tsx
"use client";

import React, { createContext, useContext, useState, useCallback, useEffect } from "react";
import { me, apiFetch } from "../../lib/api";
import {
  setUser,
  setOrganization,
  setRole,
  getOrganization,
  getRole,
  getUser,
} from "../../lib/auth";
import type {
  AuthUser,
  AuthOrganization,
  AuthRole,
  PlanTier,
  BillingInfo,
  PlanLimits,
} from "../../lib/auth";

// ════════════════════════════════════════════════════════════════
// TYPES
// ════════════════════════════════════════════════════════════════

export type Permissions = Record<string, boolean>;

interface OrgContextValue {
  user: AuthUser | null;
  organization: AuthOrganization | null;
  role: AuthRole | null;

  // ✅ M9: RBAC permissions (from backend get_permissions_for_role)
  permissions: Permissions;
  canDo: (action: string) => boolean;

  // Plan shortcuts
  plan: PlanTier;
  planLabel: string;
  planStatus: string;
  billing: BillingInfo | null;
  isTrialing: boolean;
  trialDaysRemaining: number | null;

  // Limit checks
  limits: PlanLimits | null;
  hasFeature: (feature: keyof PlanLimits) => boolean;
  isWithinLimit: (key: "assets" | "scansPerMonth" | "teamMembers" | "scheduledScans" | "apiKeys") => boolean;
  canUseScanProfile: (profileName: string) => boolean;

  // State
  loading: boolean;
  error: string | null;

  // Actions
  refresh: () => Promise<void>;
}

const PLAN_LABELS: Record<string, string> = {
  free: "Free Plan",
  starter: "Starter",
  professional: "Professional",
  enterprise_silver: "Enterprise Silver",
  enterprise_gold: "Enterprise Gold",
};

// ════════════════════════════════════════════════════════════════
// CONTEXT + HOOK
// ════════════════════════════════════════════════════════════════

const OrgContext = createContext<OrgContextValue | undefined>(undefined);

export function useOrg(): OrgContextValue {
  const ctx = useContext(OrgContext);
  if (!ctx) {
    throw new Error("useOrg() must be used within an <OrgProvider>");
  }
  return ctx;
}

// ════════════════════════════════════════════════════════════════
// PROVIDER
// ════════════════════════════════════════════════════════════════

const EMPTY_PERMISSIONS: Permissions = {};

export function OrgProvider({ children }: { children: React.ReactNode }) {
  const [user, setUserState] = useState<AuthUser | null>(null);
  const [organization, setOrgState] = useState<AuthOrganization | null>(null);
  const [role, setRoleState] = useState<AuthRole | null>(null);
  const [permissions, setPermissions] = useState<Permissions>(EMPTY_PERMISSIONS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Load from localStorage first for instant display
  useEffect(() => {
    const cachedUser = getUser();
    const cachedOrg = getOrganization();
    const cachedRole = getRole();
    if (cachedUser) setUserState(cachedUser);
    if (cachedOrg) setOrgState(cachedOrg);
    if (cachedRole) setRoleState(cachedRole);

    // Load cached permissions
    try {
      const cached = localStorage.getItem("ag_permissions");
      if (cached) setPermissions(JSON.parse(cached));
    } catch {}
  }, []);

  const refresh = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch user/org/role, permissions, and org settings in parallel
      const [meData, mySettings, orgSettings] = await Promise.all([
        me(),
        apiFetch<any>("/settings/me").catch(() => null),
        apiFetch<any>("/settings/organization").catch(() => null),
      ]);

      // Merge org settings (industry, size, website) into organization object
      const mergedOrg = {
        ...meData.organization,
        ...(orgSettings ? {
          industry: orgSettings.industry || null,
          size: orgSettings.size || null,
          website: orgSettings.website || null,
        } : {}),
      };

      // Update localStorage
      setUser(meData.user);
      setOrganization(mergedOrg);
      setRole(meData.role);

      // Update React state
      setUserState(meData.user);
      setOrgState(mergedOrg);
      setRoleState(meData.role);

      // ✅ M9: Update permissions from /settings/me
      if (mySettings?.permissions && typeof mySettings.permissions === "object") {
        setPermissions(mySettings.permissions);
        try {
          localStorage.setItem("ag_permissions", JSON.stringify(mySettings.permissions));
        } catch {}
      }
    } catch (err: any) {
      console.error("OrgProvider: failed to load context:", err);
      setError(err?.message || "Failed to load organization info");
    } finally {
      setLoading(false);
    }
  }, []);

  // Refresh from API on mount
  useEffect(() => {
    refresh();
  }, [refresh]);

  // ── Derived plan info ──
  const plan = (organization?.plan || "free") as PlanTier;
  const planStatus = organization?.planStatus || "active";
  const billing = organization?.billing || null;
  const limits = billing?.limits || null;

  const isTrialing = planStatus === "trialing" && !!billing?.trial && !billing.trial.expired;
  const trialDaysRemaining = billing?.trial?.daysRemaining ?? null;
  const planLabel = PLAN_LABELS[plan] || plan;

  // ── Permission check shortcut ──
  const canDo = useCallback(
    (action: string): boolean => {
      return permissions[action] === true;
    },
    [permissions]
  );

  // ── Feature checks ──
  const hasFeature = useCallback(
    (feature: keyof PlanLimits): boolean => {
      if (!limits) return false;
      const val = limits[feature];
      if (typeof val === "boolean") return val;
      if (typeof val === "number") return val !== 0 && val !== -0;
      if (Array.isArray(val)) return val.length > 0;
      return val !== null && val !== undefined;
    },
    [limits]
  );

  const isWithinLimit = useCallback(
    (key: "assets" | "scansPerMonth" | "teamMembers" | "scheduledScans" | "apiKeys"): boolean => {
      if (!billing) return false;
      const limit = billing.limits[key] as number;
      if (limit === -1) return true; // unlimited
      // Usage keys differ from limit keys for scans
      const usageKeyMap: Record<string, keyof typeof billing.usage> = {
        assets: "assets",
        scansPerMonth: "scansThisMonth",
        teamMembers: "teamMembers",
        scheduledScans: "scheduledScans",
        apiKeys: "apiKeys",
      };
      const usage = billing.usage[usageKeyMap[key]];
      return usage < limit;
    },
    [billing]
  );

  const canUseScanProfile = useCallback(
    (profileName: string): boolean => {
      if (!limits) return false;
      const allowed = limits.scanProfiles;
      if (!allowed || allowed.length === 0) return false;
      // "custom" profiles only on enterprise_gold
      if (allowed.includes("custom")) return true;
      const name = profileName.toLowerCase();
      if (name.includes("quick")) return allowed.includes("quick");
      if (name.includes("standard")) return allowed.includes("standard");
      if (name.includes("deep")) return allowed.includes("deep");
      // Unknown profile name — allow if all standard profiles are available
      return allowed.includes("deep");
    },
    [limits]
  );

  const value: OrgContextValue = {
    user,
    organization,
    role,
    permissions,
    canDo,
    plan,
    planLabel,
    planStatus,
    billing,
    isTrialing,
    trialDaysRemaining,
    limits,
    hasFeature,
    isWithinLimit,
    canUseScanProfile,
    loading,
    error,
    refresh,
  };

  return <OrgContext.Provider value={value}>{children}</OrgContext.Provider>;
}