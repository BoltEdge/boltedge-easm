// app/lib/auth.ts

export type AuthUser = {
  id: string | number;
  email: string;
  name?: string;
  job_title?: string;
  company?: string;
  country?: string;
};

export type PlanLimits = {
  assets: number;
  scansPerMonth: number;
  teamMembers: number;
  scheduledScans: number;
  apiKeys: number;
  scanProfiles: string[];
  monitoring: boolean;
  monitoringFrequency: string | null;
  deepDiscovery: boolean;
  webhooks: boolean;
};

export type PlanUsage = {
  assets: number;
  scansThisMonth: number;
  teamMembers: number;
  scheduledScans: number;
  apiKeys: number;
};

export type TrialInfo = {
  plan: string;
  endsAt: string;
  daysRemaining: number;
  expired: boolean;
};

export type BillingInfo = {
  plan: string;
  planLabel: string;
  planStatus: string;
  billingCycle: string | null;
  planStartedAt: string | null;
  planExpiresAt: string | null;
  trial: TrialInfo | null;
  trialedTiers: string[];
  limits: PlanLimits;
  usage: PlanUsage;
  pricing: {
    monthly: number;
    annualMonthly: number;
    annualTotal: number;
  };
};

export type AuthOrganization = {
  id: string | number;
  name: string;
  slug: string;
  plan: string;
  planStatus?: string;
  country?: string;
  asset_limit?: number;
  assets_count?: number;
  scans_this_month?: number;
  billing?: BillingInfo;
};

export type PlanTier = "free" | "starter" | "professional" | "enterprise_silver" | "enterprise_gold";

export type AuthRole = "owner" | "admin" | "analyst" | "viewer";

const TOKEN_KEY = "asm_access_token";
const USER_KEY = "asm_user";
const ORG_KEY = "asm_organization";
const ROLE_KEY = "asm_role";
const LAST_ACTIVITY_KEY = "asm_last_activity";

// 30 minutes of inactivity triggers auto-logout
const INACTIVITY_TIMEOUT_MS = 30 * 60 * 1000;


function isBrowser() {
  return typeof window !== "undefined";
}

// ---------- Token ----------
export function getAccessToken(): string | null {
  if (!isBrowser()) return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setAccessToken(token: string) {
  if (!isBrowser()) return;
  window.localStorage.setItem(TOKEN_KEY, token);
}

export function clearAccessToken() {
  if (!isBrowser()) return;
  window.localStorage.removeItem(TOKEN_KEY);
}

// ---------- User ----------
export function getUser(): AuthUser | null {
  if (!isBrowser()) return null;
  const raw = window.localStorage.getItem(USER_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as AuthUser;
  } catch {
    window.localStorage.removeItem(USER_KEY);
    return null;
  }
}

export function setUser(user: AuthUser) {
  if (!isBrowser()) return;
  window.localStorage.setItem(USER_KEY, JSON.stringify(user));
}

export function clearUser() {
  if (!isBrowser()) return;
  window.localStorage.removeItem(USER_KEY);
}

// ---------- Organization ----------
export function getOrganization(): AuthOrganization | null {
  if (!isBrowser()) return null;
  const raw = window.localStorage.getItem(ORG_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as AuthOrganization;
  } catch {
    window.localStorage.removeItem(ORG_KEY);
    return null;
  }
}

export function setOrganization(org: AuthOrganization) {
  if (!isBrowser()) return;
  window.localStorage.setItem(ORG_KEY, JSON.stringify(org));
}

export function clearOrganization() {
  if (!isBrowser()) return;
  window.localStorage.removeItem(ORG_KEY);
}

// ---------- Role ----------
export function getRole(): AuthRole | null {
  if (!isBrowser()) return null;
  return window.localStorage.getItem(ROLE_KEY) as AuthRole | null;
}

export function setRole(role: AuthRole) {
  if (!isBrowser()) return;
  window.localStorage.setItem(ROLE_KEY, role);
}

export function clearRole() {
  if (!isBrowser()) return;
  window.localStorage.removeItem(ROLE_KEY);
}

// ---------- Activity tracking (inactivity timeout) ----------

/**
 * Record that the user is active right now.
 * Called on every API request and on session establishment.
 */
export function touchActivity() {
  if (!isBrowser()) return;
  window.localStorage.setItem(LAST_ACTIVITY_KEY, String(Date.now()));
}

/**
 * Check if the user has been inactive for longer than INACTIVITY_TIMEOUT_MS.
 * Returns true if idle for 30+ minutes.
 */
export function isInactive(): boolean {
  if (!isBrowser()) return false;
  const last = window.localStorage.getItem(LAST_ACTIVITY_KEY);
  if (!last) return false; // No activity recorded yet — just logged in
  return Date.now() - Number(last) > INACTIVITY_TIMEOUT_MS;
}

function clearActivity() {
  if (!isBrowser()) return;
  window.localStorage.removeItem(LAST_ACTIVITY_KEY);
}

// ---------- Auth status ----------
export function isLoggedIn(): boolean {
  return !!getAccessToken();
}

export function hasSession(): boolean {
  return !!getAccessToken();
}

// ---------- Plan helpers ----------

/**
 * Get the current plan from localStorage.
 * Returns the effective plan (accounts for trial expiry on the backend).
 */
export function getCurrentPlan(): PlanTier {
  const org = getOrganization();
  return (org?.plan || "free") as PlanTier;
}

/**
 * Get full billing info from localStorage.
 * This is loaded by the OrgProvider on mount.
 */
export function getBillingInfo(): BillingInfo | null {
  const org = getOrganization();
  return org?.billing || null;
}

/**
 * Check if the current plan has a specific feature.
 */
export function hasPlanFeature(feature: keyof PlanLimits): boolean {
  const billing = getBillingInfo();
  if (!billing) return false;
  const val = billing.limits[feature];
  if (typeof val === "boolean") return val;
  if (typeof val === "number") return val !== 0;
  if (Array.isArray(val)) return val.length > 0;
  return !!val;
}

/**
 * Check if the org is within a specific limit.
 * Returns true if under the limit (or limit is unlimited = -1).
 */
export function isWithinLimit(limitKey: "assets" | "scansPerMonth" | "teamMembers" | "scheduledScans" | "apiKeys"): boolean {
  const billing = getBillingInfo();
  if (!billing) return false;
  const limit = billing.limits[limitKey] as number;
  if (limit === -1) return true; // unlimited
  const usageKeyMap: Record<string, keyof PlanUsage> = {
    assets: "assets",
    scansPerMonth: "scansThisMonth",
    teamMembers: "teamMembers",
    scheduledScans: "scheduledScans",
    apiKeys: "apiKeys",
  };
  const usage = billing.usage[usageKeyMap[limitKey]];
  return usage < limit;
}

// ---------- Session helpers ----------
type EstablishSessionInput =
  | { accessToken: string; user?: AuthUser | null; organization?: AuthOrganization | null; role?: AuthRole | null }
  | { token: string; user?: AuthUser | null; organization?: AuthOrganization | null; role?: AuthRole | null };

/**
 * Supports BOTH call styles:
 *  1) establishSession("token", user, org, role)
 *  2) establishSession({ accessToken: "token", user, organization, role })
 */
export function establishSession(
  accessToken: string,
  user?: AuthUser | null,
  organization?: AuthOrganization | null,
  role?: AuthRole | null
): void;
export function establishSession(input: EstablishSessionInput): void;
export function establishSession(
  a: string | EstablishSessionInput,
  b?: AuthUser | null,
  c?: AuthOrganization | null,
  d?: AuthRole | null
) {
  // Style #1: establishSession("token", user, org, role)
  if (typeof a === "string") {
    setAccessToken(a);
    if (b) setUser(b);
    if (c) setOrganization(c);
    if (d) setRole(d);
    touchActivity();
    return;
  }
  
  // Style #2: establishSession({ accessToken, user, organization, role })
  const token = (a as any).accessToken || (a as any).token;
  if (token) setAccessToken(token);
  
  const user = (a as any).user as AuthUser | null | undefined;
  if (user) setUser(user);
  
  const org = (a as any).organization as AuthOrganization | null | undefined;
  if (org) setOrganization(org);
  
  const role = (a as any).role as AuthRole | null | undefined;
  if (role) setRole(role);

  touchActivity();
}

export function clearSession() {
  clearAccessToken();
  clearUser();
  clearOrganization();
  clearRole();
  clearActivity();
}

// ---------- Logout ----------
export function logout(redirectTo: string = "/") {
  if (!isBrowser()) return;
  clearSession();
  window.location.href = redirectTo;
}