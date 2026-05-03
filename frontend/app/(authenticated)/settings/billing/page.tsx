// FILE: app/(authenticated)/settings/billing/page.tsx
// Plans page — current plan, usage, and tier switching.
// When BILLING_ENABLED=false: plans are free tiers, no prices or trial wording shown.
// When BILLING_ENABLED=true: full payment/subscription/trial UI is restored.
"use client";

import React, { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useSearchParams, useRouter } from "next/navigation";
import { Layers, Check, Clock, Zap, Sparkles, Loader2, X, RefreshCcw, Mail, AlertTriangle, Trash2, CreditCard, Lock } from "lucide-react";
import { cn } from "../../../lib/utils";
import { Button } from "../../../ui/button";
import { Input } from "../../../ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../../ui/dialog";
import { apiFetch, isPlanError, createCheckoutSession, createPortalSession, getSubscriptionStatus, type SubscriptionStatus } from "../../../lib/api";
import { useOrg } from "../../contexts/OrgContext";
import { usePlanLimit, PlanLimitDialog } from "../../../ui/plan-limit-dialog";
import { BILLING_ENABLED } from "../../../lib/billing-config";
import { canCheckout } from "../../../lib/stripe-config";
import { logout } from "../../../lib/auth";

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  let d: Date;
  if (typeof iso === "string" && !iso.endsWith("Z") && !iso.includes("+")) d = new Date(iso + "Z");
  else d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

// ── Plan-change delta helpers ──────────────────────────────────────
const FREQ_LABELS: Record<string, string> = {
  every_7_days: "every 7 days",
  every_3_days: "every 3 days",
  every_2_days: "every 2 days",
  daily: "daily",
  every_12_hours: "every 12 hours",
};

type PlanDelta = { kind: "added" | "removed"; text: string };

/**
 * Compute the difference between the user's current plan limits and
 * the target plan's limits. Used to render "what you get" / "what
 * changes" inside the upgrade dialog so the value of the change is
 * front-and-centre, not a generic feature list.
 */
function computeDeltas(currentLimits: any, targetLimits: any): PlanDelta[] {
  if (!currentLimits || !targetLimits) return [];
  const out: PlanDelta[] = [];

  const numericFields: Array<{ key: string; label: string }> = [
    { key: "assets",                label: "assets" },
    { key: "scansPerMonth",         label: "scans per month" },
    { key: "monitoredAssets",       label: "monitored assets" },
    { key: "discoveriesPerMonth",   label: "discoveries per month" },
    { key: "teamMembers",           label: "team members" },
    { key: "scheduledScans",        label: "scheduled scans" },
    { key: "apiKeys",               label: "API keys" },
  ];

  for (const f of numericFields) {
    const cur = currentLimits[f.key];
    const tgt = targetLimits[f.key];
    if (cur == null || tgt == null || cur === tgt) continue;

    // Skip monitored_assets when the monitoring boolean is toggling —
    // the boolean line ("Continuous monitoring (every 7 days)" or
    // "Continuous monitoring removed") already carries the message.
    if (f.key === "monitoredAssets" && currentLimits.monitoring !== targetLimits.monitoring) continue;

    if (tgt === -1) {
      out.push({ kind: "added", text: `Unlimited ${f.label}` });
    } else if (cur === -1) {
      out.push({ kind: "removed", text: `${f.label}: capped at ${tgt}` });
    } else if (tgt === 0 && cur > 0) {
      // "0 X (down from N)" reads awkwardly — just say it's gone.
      out.push({ kind: "removed", text: `${f.label.charAt(0).toUpperCase()}${f.label.slice(1)} no longer included` });
    } else if (tgt > cur) {
      out.push({ kind: "added", text: `${tgt} ${f.label}${cur > 0 ? ` (was ${cur})` : ""}` });
    } else {
      out.push({ kind: "removed", text: `${tgt} ${f.label} (down from ${cur})` });
    }
  }

  // Monitoring — combine on/off with frequency so we don't double-list.
  if (!currentLimits.monitoring && targetLimits.monitoring) {
    const freq = targetLimits.monitoringFrequency
      ? ` (${FREQ_LABELS[targetLimits.monitoringFrequency] || String(targetLimits.monitoringFrequency).replace(/_/g, " ")})`
      : "";
    out.push({ kind: "added", text: `Continuous monitoring${freq}` });
  } else if (currentLimits.monitoring && !targetLimits.monitoring) {
    out.push({ kind: "removed", text: "Continuous monitoring removed" });
  } else if (
    currentLimits.monitoring &&
    targetLimits.monitoring &&
    currentLimits.monitoringFrequency !== targetLimits.monitoringFrequency &&
    targetLimits.monitoringFrequency
  ) {
    const label = FREQ_LABELS[targetLimits.monitoringFrequency] || String(targetLimits.monitoringFrequency).replace(/_/g, " ");
    out.push({ kind: "added", text: `Monitoring runs ${label}` });
  }

  if (!currentLimits.deepDiscovery && targetLimits.deepDiscovery) {
    out.push({ kind: "added", text: "Deep discovery" });
  } else if (currentLimits.deepDiscovery && !targetLimits.deepDiscovery) {
    out.push({ kind: "removed", text: "Deep discovery removed" });
  }

  if (!currentLimits.webhooks && targetLimits.webhooks) {
    out.push({ kind: "added", text: "Webhook integrations" });
  } else if (currentLimits.webhooks && !targetLimits.webhooks) {
    out.push({ kind: "removed", text: "Webhook integrations removed" });
  }

  return out;
}

export default function BillingPage() {
  const { canDo, role, organization, refresh: refreshOrg } = useOrg();
  const planLimit = usePlanLimit();
  const canManageBilling = canDo("manage_billing");
  const canDeleteOrg = role === "owner";
  const orgName = (organization as any)?.name || "";

  const [planData, setPlanData] = useState<any>(null);
  const [plans, setPlans] = useState<any[]>([]);
  const [subStatus, setSubStatus] = useState<SubscriptionStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [actionPlan, setActionPlan] = useState<string | null>(null);
  const [showEndTrial, setShowEndTrial] = useState(false);
  const [endingTrial, setEndingTrial] = useState(false);
  const [showUpgrade, setShowUpgrade] = useState<string | null>(null);
  const [upgrading, setUpgrading] = useState(false);
  const [upgradeCycle, setUpgradeCycle] = useState<"monthly" | "annual">("monthly");
  const [portalLoading, setPortalLoading] = useState(false);
  const [activatingSubscription, setActivatingSubscription] = useState(false);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [showDeleteOrg, setShowDeleteOrg] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState("");
  const [deletingOrg, setDeletingOrg] = useState(false);

  const searchParams = useSearchParams();
  const router = useRouter();
  const pollHandledRef = useRef(false);

  async function loadBilling(isRefresh = false) {
    if (isRefresh) setRefreshing(true); else setLoading(true);
    try {
      const subPromise = BILLING_ENABLED
        ? getSubscriptionStatus().catch(() => null)
        : Promise.resolve(null);
      const [pd, pl, sub] = await Promise.all([
        apiFetch<any>("/billing/plan"),
        apiFetch<any>("/billing/plans"),
        subPromise,
      ]);
      setPlanData(pd);
      setPlans(Array.isArray(pl) ? pl : pl?.plans || []);
      setSubStatus(sub);
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed to load plans" });
    } finally { setLoading(false); setRefreshing(false); }
  }

  useEffect(() => { loadBilling(); }, []);
  useEffect(() => { if (banner) { const t = setTimeout(() => setBanner(null), 5000); return () => clearTimeout(t); } }, [banner]);

  // ── Stripe Checkout return handler ────────────────────────────
  // After Stripe redirects back, we may arrive before the webhook has
  // updated our DB. Poll subscription status for up to 30s, then strip
  // the query param so a refresh doesn't re-trigger the poll.
  useEffect(() => {
    const result = searchParams.get("checkout");
    if (!result || pollHandledRef.current) return;
    pollHandledRef.current = true;

    if (result === "cancel") {
      setBanner({ kind: "err", text: "Checkout was cancelled. No changes were made." });
      router.replace("/settings/billing");
      return;
    }

    if (result !== "success") return;

    setActivatingSubscription(true);
    let elapsed = 0;
    const poll = async (): Promise<boolean> => {
      try {
        const sub = await getSubscriptionStatus();
        return sub.subscriptionStatus === "active" || sub.subscriptionStatus === "trialing";
      } catch {
        return false;
      }
    };

    const interval = setInterval(async () => {
      elapsed += 2000;
      const ready = await poll();
      if (ready) {
        clearInterval(interval);
        setActivatingSubscription(false);
        setBanner({ kind: "ok", text: "Subscription activated." });
        loadBilling(true);
        refreshOrg();
        router.replace("/settings/billing");
      } else if (elapsed >= 30000) {
        clearInterval(interval);
        setActivatingSubscription(false);
        setBanner({
          kind: "ok",
          text: "Checkout complete. If your plan doesn't update in a moment, click Refresh.",
        });
        router.replace("/settings/billing");
      }
    }, 2000);

    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  // ── Stripe Checkout — redirects browser to Stripe-hosted page ──
  async function handleStripeCheckout(planKey: string, billingCycle: "monthly" | "annual" = "monthly") {
    try {
      setUpgrading(true);
      const res = await createCheckoutSession(planKey, billingCycle);
      window.location.href = res.url;
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed to start checkout." });
      setUpgrading(false);
    }
  }

  // ── Stripe Customer Portal — self-serve billing management ─────
  async function handleManageBilling() {
    try {
      setPortalLoading(true);
      const res = await createPortalSession();
      window.location.href = res.url;
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Could not open the billing portal." });
      setPortalLoading(false);
    }
  }

  async function handleStartTrial(planKey: string) {
    try {
      setActionPlan(planKey);
      const res = await apiFetch<any>("/billing/start-trial", {
        method: "POST",
        body: JSON.stringify({ plan: planKey }),
      });
      // Trials are request-based — no plan flip happens here. The user gets
      // a confirmation banner; the admin reviews from /admin/contact-requests.
      setBanner({
        kind: "ok",
        text: res?.message || "Trial request submitted. We'll email you when it's approved.",
      });
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed to submit trial request." });
    } finally { setActionPlan(null); }
  }

  async function handleEndTrial() {
    try {
      setEndingTrial(true);
      await apiFetch<any>("/billing/cancel", { method: "POST" });
      setBanner({ kind: "ok", text: "Trial ended. Back to Free plan." });
      setShowEndTrial(false);
      refreshOrg();
      setTimeout(() => window.location.reload(), 1200);
    } catch (e: any) {
      if (isPlanError(e)) { setShowEndTrial(false); planLimit.handle(e.planError); }
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    } finally { setEndingTrial(false); }
  }

  async function handleDeleteOrg() {
    try {
      setDeletingOrg(true);
      await apiFetch<any>("/billing/organization", { method: "DELETE" });
      logout("/login");
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to delete organization." });
      setShowDeleteOrg(false);
      setDeletingOrg(false);
    }
  }

  async function handleUpgrade(planKey: string) {
    try {
      setUpgrading(true);
      await apiFetch<any>("/billing/upgrade", { method: "POST", body: JSON.stringify({ plan: planKey }) });
      setBanner({ kind: "ok", text: "Plan updated! Refreshing..." });
      setShowUpgrade(null);
      refreshOrg();
      setTimeout(() => window.location.reload(), 1200);
    } catch (e: any) {
      if (isPlanError(e)) { setShowUpgrade(null); planLimit.handle(e.planError); }
      else setBanner({ kind: "err", text: e?.message || "Failed." });
    } finally { setUpgrading(false); }
  }

  const PLAN_ORDER = ["free", "starter", "professional", "enterprise_silver", "enterprise_gold"];
  const TIER_COLORS: Record<string, string> = {
    free: "#6b7280", starter: "#00b8d4", professional: "#7c5cfc",
    enterprise_silver: "#ff8800", enterprise_gold: "#ffd700",
  };

  function UsageBar({ label, current, limit }: { label: string; current: number; limit: number }) {
    const isUnlimited = limit === -1;
    const pct = isUnlimited ? 10 : Math.min((current / limit) * 100, 100);
    const isNear = !isUnlimited && pct >= 80;
    const isAt = !isUnlimited && current >= limit;
    return (
      <div className="space-y-2">
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">{label}</span>
          <span className={cn("font-medium", isAt ? "text-red-400" : isNear ? "text-amber-400" : "text-foreground")}>
            {current} / {isUnlimited ? "∞" : limit}
          </span>
        </div>
        <div className="h-2 bg-muted rounded-full overflow-hidden">
          <div className={cn("h-full rounded-full transition-all", isAt ? "bg-red-500" : isNear ? "bg-amber-500" : "bg-primary")} style={{ width: `${pct}%` }} />
        </div>
      </div>
    );
  }

  if (loading) return <main className="flex-1 bg-background p-8"><div className="text-muted-foreground text-sm">Loading...</div></main>;
  if (!planData) return null;

  const currentPlan = planData.plan;
  const isTrial = planData.planStatus === "trialing";
  const trial = planData.trial;
  const trialDaysLeft = trial?.daysRemaining ?? null;
  const usage = planData.usage;
  const limits = planData.limits;
  const pricing = planData.pricing;
  const trialedTiers = planData.trialedTiers || [];
  const currentIdx = PLAN_ORDER.indexOf(currentPlan);

  const pageTitle = BILLING_ENABLED ? "Payment & Plans" : "Plans";
  const pageSubtitle = BILLING_ENABLED
    ? "Manage your subscription, trial, and usage."
    : "Manage your plan tier and usage limits.";

  // Once an org has a live Stripe subscription, all plan changes go
  // through the Stripe Customer Portal — keeping our DB and Stripe in
  // lockstep. Trying to flip plans via the legacy /upgrade endpoint
  // would charge them on Stripe while our DB shows a different plan.
  const hasActiveStripeSub = !!(
    BILLING_ENABLED &&
    subStatus?.stripeSubscriptionId &&
    (subStatus.subscriptionStatus === "active" ||
      subStatus.subscriptionStatus === "trialing" ||
      subStatus.subscriptionStatus === "past_due")
  );

  return (
    <main className="flex-1 overflow-y-auto bg-background">
      <div className="p-8 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-foreground flex items-center gap-3">
              <Layers className="w-7 h-7 text-primary" />{pageTitle}
            </h1>
            <p className="text-muted-foreground mt-1">{pageSubtitle}</p>
          </div>
          <Button variant="outline" onClick={() => loadBilling(true)} disabled={refreshing} className="border-border text-foreground hover:bg-accent">
            <RefreshCcw className={cn("w-4 h-4 mr-2", refreshing && "animate-spin")} />
            {refreshing ? "Refreshing…" : "Refresh"}
          </Button>
        </div>

        {banner && (
          <div className={cn("rounded-xl border px-4 py-3 text-sm flex items-center justify-between",
            banner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>
            <span>{banner.text}</span>
            <button onClick={() => setBanner(null)} className="hover:opacity-70"><X className="w-4 h-4" /></button>
          </div>
        )}

        {/* Activating subscription — shown after Stripe redirect, while
            the webhook propagates. Cleared once subscription goes active. */}
        {activatingSubscription && (
          <div className="rounded-xl border border-primary/30 bg-primary/10 px-5 py-4 flex items-center gap-3">
            <Loader2 className="w-5 h-5 text-primary animate-spin shrink-0" />
            <div>
              <div className="text-sm font-semibold text-foreground">Activating your subscription…</div>
              <div className="text-xs text-muted-foreground">
                Payment confirmed. Finalising your subscription — this usually takes a few seconds.
              </div>
            </div>
          </div>
        )}

        {/* Trial Banner — only shown when billing is enabled */}
        {BILLING_ENABLED && isTrial && trialDaysLeft !== null && (
          <div className="rounded-xl border border-[#ff8800]/30 bg-[#ff8800]/10 px-5 py-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-[#ff8800]/20 flex items-center justify-center">
                <Clock className="w-5 h-5 text-[#ff8800]" />
              </div>
              <div>
                <div className="text-sm font-semibold text-[#ffcc00]">Trial Active — {trialDaysLeft} day{trialDaysLeft !== 1 ? "s" : ""} remaining</div>
                <div className="text-xs text-[#ff8800]/70">
                  Your {planData.planLabel} trial {trial?.endsAt ? `ends ${formatDate(trial.endsAt)}` : "is active"}. Upgrade anytime to keep your features.
                </div>
              </div>
            </div>
            {canManageBilling && (
              <div className="flex items-center gap-2 shrink-0">
                <Button size="sm" variant="outline" onClick={() => setShowEndTrial(true)} className="text-xs border-border text-muted-foreground hover:bg-muted/30">End Trial</Button>
                <Button size="sm" onClick={() => setShowUpgrade(currentPlan)} className="text-xs bg-[#ff8800] hover:bg-[#ff8800]/90 text-white">
                  <Zap className="w-3 h-3 mr-1.5" />Upgrade Now
                </Button>
              </div>
            )}
          </div>
        )}

        {/* Current Plan */}
        <div className="bg-card border border-primary/30 rounded-xl p-6">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
                <Sparkles className="w-6 h-6 text-primary" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
                  {planData.planLabel} Plan
                  {BILLING_ENABLED && isTrial && (
                    <span className="px-2 py-0.5 rounded-md bg-[#ff8800]/15 text-[#ff8800] text-xs font-semibold border border-[#ff8800]/30">Trial</span>
                  )}
                </h2>
                <p className="text-sm text-muted-foreground">Active since {formatDate(planData.planStartedAt)}</p>
              </div>
            </div>
            {BILLING_ENABLED && (
              <div className="text-right">
                <div className="text-3xl font-bold text-foreground">
                  {pricing.monthly === 0 ? "Free" : pricing.monthly === -1 ? "Custom" : `$${pricing.monthly}`}
                </div>
                {pricing.monthly > 0 && <div className="text-xs text-muted-foreground">{isTrial ? "after trial ends" : "per month"}</div>}
              </div>
            )}
          </div>
          <div className="space-y-4">
            <UsageBar label="Assets" current={usage.assets} limit={limits.assets} />
            <UsageBar label="Scans this month" current={usage.scansThisMonth} limit={limits.scansPerMonth} />
            <UsageBar label="Schedules" current={usage.scheduledScans} limit={limits.scheduledScans} />
            <UsageBar label="Team members" current={usage.teamMembers} limit={limits.teamMembers} />
            <UsageBar label="API keys" current={usage.apiKeys} limit={limits.apiKeys} />
          </div>

          {/* Manage billing — opens Stripe Customer Portal. Only shown when
              billing is enabled and the org is on a paid plan with an
              active subscription, so we know there's a Stripe customer
              to manage. */}
          {BILLING_ENABLED && canManageBilling && currentPlan !== "free" && (
            <div className="mt-6 pt-4 border-t border-border/60 flex items-center justify-between">
              <div>
                <div className="text-sm font-medium text-foreground">Billing & invoices</div>
                <div className="text-xs text-muted-foreground">
                  Update your payment method, download invoices, or cancel anytime.
                </div>
              </div>
              <Button
                variant="outline"
                onClick={handleManageBilling}
                disabled={portalLoading}
                className="border-border text-foreground hover:bg-accent shrink-0"
              >
                {portalLoading
                  ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Opening…</>
                  : <><CreditCard className="w-4 h-4 mr-2" />Manage billing</>}
              </Button>
            </div>
          )}
        </div>

        {/* Available Plans */}
        <div>
          <h2 className="text-lg font-semibold text-foreground mb-1">Available Plans</h2>
          {!BILLING_ENABLED && (
            <p className="text-sm text-muted-foreground mb-4">
              All plans are available as free tiers during the community preview. Upgrade to unlock higher limits.
            </p>
          )}
          {BILLING_ENABLED && <div className="mb-4" />}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {plans.map((p) => {
              const planIdx = PLAN_ORDER.indexOf(p.key);
              const isCurrent = p.isCurrent;
              const isUpgrade = planIdx > currentIdx;
              const isDowngrade = planIdx < currentIdx;
              const isEnterpriseGold = p.key === "enterprise_gold";
              const color = TIER_COLORS[p.key] || "#7c5cfc";
              const canTrial = BILLING_ENABLED && p.canTrial && !isTrial && !p.trialRequiresApproval;
              const needsApproval = BILLING_ENABLED && p.canTrial && p.trialRequiresApproval;

              return (
                <div key={p.key} className={cn("bg-card border rounded-xl p-5 flex flex-col", isCurrent ? "ring-1" : "")}
                  style={{ borderColor: isCurrent ? `${color}80` : undefined, boxShadow: isCurrent ? `0 0 0 1px ${color}30` : undefined }}>
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-foreground font-semibold">{p.label}</h3>
                    {isCurrent && (
                      <span className="px-2 py-0.5 rounded-md text-xs font-semibold border"
                        style={{ backgroundColor: `${color}15`, color, borderColor: `${color}30` }}>
                        {BILLING_ENABLED && isTrial ? "Trial" : "Current"}
                      </span>
                    )}
                  </div>

                  {/* Price — only shown when billing is enabled */}
                  {BILLING_ENABLED && (
                    <div className="mb-4">
                      {p.priceMonthly === 0 ? <span className="text-2xl font-bold text-foreground">Free</span>
                        : p.priceMonthly === -1 ? <span className="text-2xl font-bold text-foreground">Custom</span>
                        : <><span className="text-2xl font-bold text-foreground">${p.priceMonthly}</span><span className="text-sm text-muted-foreground">/mo</span></>}
                      {p.priceAnnualMonthly > 0 && p.priceAnnualMonthly < p.priceMonthly && (
                        <div className="text-xs text-muted-foreground mt-0.5">${p.priceAnnualMonthly}/mo billed annually</div>
                      )}
                    </div>
                  )}

                  <ul className="space-y-2 mb-6 flex-1">
                    <li className="text-xs text-muted-foreground flex items-center gap-1.5"><Check className="w-3 h-3 text-[#10b981]" />{p.limits.assets === -1 ? "Unlimited" : p.limits.assets} assets</li>
                    <li className="text-xs text-muted-foreground flex items-center gap-1.5"><Check className="w-3 h-3 text-[#10b981]" />{p.limits.scansPerMonth === -1 ? "Unlimited" : p.limits.scansPerMonth} scans/month</li>
                    <li className="text-xs text-muted-foreground flex items-center gap-1.5"><Check className="w-3 h-3 text-[#10b981]" />{p.limits.teamMembers === -1 ? "Unlimited" : p.limits.teamMembers} members</li>
                    <li className="text-xs text-muted-foreground flex items-center gap-1.5"><Check className="w-3 h-3 text-[#10b981]" />{p.limits.scheduledScans === -1 ? "Unlimited" : p.limits.scheduledScans} scheduled scans</li>
                    {p.limits.monitoring && <li className="text-xs text-muted-foreground flex items-center gap-1.5"><Check className="w-3 h-3 text-[#10b981]" />Monitoring ({p.limits.monitoringFrequency?.replace(/_/g, " ") || "enabled"})</li>}
                    {p.limits.deepDiscovery && <li className="text-xs text-muted-foreground flex items-center gap-1.5"><Check className="w-3 h-3 text-[#10b981]" />Deep Discovery</li>}
                    {p.limits.webhooks && <li className="text-xs text-muted-foreground flex items-center gap-1.5"><Check className="w-3 h-3 text-[#10b981]" />Webhooks</li>}
                  </ul>

                  <div className="space-y-2">
                    {isCurrent ? (
                      <Button variant="outline" disabled className="w-full border-border text-muted-foreground">Current Plan</Button>
                    ) : isEnterpriseGold ? (
                      /* Enterprise Gold: contact us regardless of billing mode */
                      <Link href="/?type=trial#contact" className="block">
                        <Button className="w-full bg-primary hover:bg-primary/90">
                          <Mail className="w-3.5 h-3.5 mr-1.5" />Contact Us
                        </Button>
                      </Link>
                    ) : !canManageBilling ? (
                      <Button variant="outline" disabled className="w-full border-border text-muted-foreground">Ask admin to change plan</Button>
                    ) : hasActiveStripeSub ? (
                      /* Active subscription — every plan change opens the
                         hosted billing portal so our DB and the payment
                         provider stay in lockstep. */
                      <Button
                        variant={isUpgrade ? "default" : "outline"}
                        onClick={handleManageBilling}
                        disabled={portalLoading}
                        className={cn(
                          "w-full",
                          isUpgrade
                            ? "bg-primary hover:bg-primary/90"
                            : "border-border text-foreground hover:bg-accent",
                        )}
                      >
                        {portalLoading
                          ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />Opening billing portal…</>
                          : isUpgrade
                            ? <>Upgrade to {p.label}</>
                            : <>Downgrade to {p.label}</>}
                      </Button>
                    ) : isUpgrade ? (
                      <Button onClick={() => setShowUpgrade(p.key)} className="w-full bg-primary hover:bg-primary/90">
                        {BILLING_ENABLED ? `Upgrade to ${p.label}` : `Switch to ${p.label}`}
                      </Button>
                    ) : isDowngrade ? (
                      <Button variant="outline" onClick={() => setShowUpgrade(p.key)} className="w-full border-border text-foreground hover:bg-accent">
                        {BILLING_ENABLED ? `Downgrade to ${p.label}` : `Switch to ${p.label}`}
                      </Button>
                    ) : null}

                    {/* Trial request button — submits a contact_request, no auto-grant */}
                    {canManageBilling && canTrial && (
                      <Button variant="outline" size="sm" onClick={() => handleStartTrial(p.key)} disabled={actionPlan !== null}
                        className="w-full text-xs" style={{ borderColor: `${color}40`, color }}>
                        {actionPlan === p.key ? <><Loader2 className="w-3 h-3 mr-1.5 animate-spin" />Submitting…</> : <><Clock className="w-3 h-3 mr-1.5" />Request free trial</>}
                      </Button>
                    )}
                    {BILLING_ENABLED && needsApproval && <div className="text-[10px] text-muted-foreground text-center">Free trial — contact sales</div>}
                    {BILLING_ENABLED && !p.canTrial && !isCurrent && trialedTiers.includes(p.key) && <div className="text-[10px] text-muted-foreground text-center">Trial used</div>}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Danger Zone — owners only */}
        {canDeleteOrg && (
          <div className="bg-card border border-red-500/30 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <h2 className="text-lg font-semibold text-red-300">Danger Zone</h2>
            </div>
            <div className="flex items-start justify-between gap-4">
              <div>
                <h3 className="text-sm font-medium text-foreground">Delete Organization</h3>
                <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
                  Permanently delete <span className="text-foreground font-medium">{orgName}</span> and all its data —
                  assets, scans, findings, members, API keys, and audit history. This cannot be undone.
                </p>
              </div>
              <Button
                onClick={() => { setShowDeleteOrg(true); setDeleteConfirmText(""); }}
                className="bg-red-500 hover:bg-red-600 text-white shrink-0"
              >
                <Trash2 className="w-4 h-4 mr-2" />Delete Organization
              </Button>
            </div>
          </div>
        )}

        {/* Delete Organization Dialog */}
        <Dialog open={showDeleteOrg} onOpenChange={(o) => { if (!o && !deletingOrg) { setShowDeleteOrg(false); setDeleteConfirmText(""); } }}>
          <DialogContent className="bg-card border-border text-foreground sm:max-w-[480px]">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2 text-red-300">
                <AlertTriangle className="w-5 h-5" />Delete Organization
              </DialogTitle>
            </DialogHeader>
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">
                This will permanently delete <span className="text-foreground font-semibold">{orgName}</span> and
                all associated data. Members will lose access immediately. This action cannot be undone.
              </p>
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-foreground block">
                  Type <span className="font-mono text-red-300">{orgName}</span> to confirm
                </label>
                <Input
                  value={deleteConfirmText}
                  onChange={(e) => setDeleteConfirmText(e.target.value)}
                  placeholder={orgName}
                  autoFocus
                />
              </div>
              <div className="flex gap-3 justify-end pt-2">
                <Button
                  variant="outline"
                  onClick={() => { setShowDeleteOrg(false); setDeleteConfirmText(""); }}
                  disabled={deletingOrg}
                  className="border-border text-foreground hover:bg-accent"
                >
                  Cancel
                </Button>
                <Button
                  onClick={handleDeleteOrg}
                  disabled={deletingOrg || deleteConfirmText !== orgName}
                  className="bg-red-500 hover:bg-red-600 text-white disabled:opacity-50"
                >
                  {deletingOrg ? "Deleting..." : "Delete Forever"}
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>

        {/* End Trial Dialog — billing mode only */}
        {BILLING_ENABLED && (
          <Dialog open={showEndTrial} onOpenChange={setShowEndTrial}>
            <DialogContent className="bg-card border-border text-foreground sm:max-w-[440px]">
              <DialogHeader><DialogTitle>End Trial?</DialogTitle></DialogHeader>
              <p className="text-sm text-muted-foreground">
                Your {planData.planLabel} trial still has <span className="text-foreground font-medium">{trialDaysLeft} day{trialDaysLeft !== 1 ? "s" : ""}</span> remaining.
                Ending it will move you back to the <span className="text-foreground font-medium">Free plan</span> immediately.
                You won&apos;t be able to start another {planData.planLabel} trial.
              </p>
              <div className="flex gap-3 justify-end pt-4">
                <Button variant="outline" onClick={() => setShowEndTrial(false)} className="border-border text-foreground hover:bg-accent">Keep Trial</Button>
                <Button onClick={handleEndTrial} disabled={endingTrial} className="bg-[#ef4444] hover:bg-[#dc2626] text-white">{endingTrial ? "Ending..." : "End Trial"}</Button>
              </div>
            </DialogContent>
          </Dialog>
        )}

        {/* Switch / Upgrade / Downgrade Dialog — order-review style */}
        <Dialog open={!!showUpgrade} onOpenChange={(o) => { if (!o) setShowUpgrade(null); }}>
          <DialogContent className="bg-card border-border text-foreground sm:max-w-[520px]">
            <DialogHeader>
              <DialogTitle>
                {(() => {
                  if (!showUpgrade) return "";
                  const isDown = PLAN_ORDER.indexOf(showUpgrade) < currentIdx;
                  const target = plans.find((p) => p.key === showUpgrade);
                  const useStripeTitle = BILLING_ENABLED && !isDown && canCheckout(showUpgrade);
                  const verb = !BILLING_ENABLED
                    ? "Switch to"
                    : isDown
                      ? "Downgrade to"
                      : useStripeTitle
                        ? "Subscribe to"
                        : "Upgrade to";
                  return `${verb} ${target?.label || "plan"}`;
                })()}
              </DialogTitle>
            </DialogHeader>
            {(() => {
              if (!showUpgrade) return null;
              const target = plans.find((p) => p.key === showUpgrade);
              if (!target) return null;

              const isDown = PLAN_ORDER.indexOf(showUpgrade) < currentIdx;
              const useStripe = BILLING_ENABLED && !isDown && canCheckout(showUpgrade);
              const annualMonthly = target.priceAnnualMonthly ?? 0;
              const monthly = target.priceMonthly ?? 0;
              const annualTotal = target.priceAnnualTotal ?? 0;
              const annualSavings = monthly > 0 && annualMonthly > 0 && annualMonthly < monthly
                ? Math.round((1 - annualMonthly / monthly) * 100)
                : 0;
              const todayPrice = useStripe
                ? (upgradeCycle === "annual" ? annualTotal : monthly)
                : 0;
              const tierColor = TIER_COLORS[target.key] || "#7c5cfc";
              const deltas = computeDeltas(limits, target.limits);

              return (
                <div className="space-y-5">
                  {/* ── Plan header ── */}
                  <div className="flex items-center gap-3">
                    <div
                      className="w-12 h-12 rounded-xl flex items-center justify-center shrink-0"
                      style={{ backgroundColor: `${tierColor}15` }}
                    >
                      <Sparkles className="w-5 h-5" style={{ color: tierColor }} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-[11px] uppercase tracking-wide text-muted-foreground">
                        {!BILLING_ENABLED
                          ? "New plan"
                          : isDown
                            ? `Currently ${planData.planLabel}`
                            : useStripe
                              ? "New subscription"
                              : `Currently ${planData.planLabel}`}
                      </div>
                      <div className="text-base font-semibold text-foreground truncate">{target.label}</div>
                    </div>
                    {BILLING_ENABLED && monthly > 0 && (
                      <div className="text-right shrink-0">
                        <div className="text-2xl font-bold text-foreground leading-none">
                          ${useStripe && upgradeCycle === "annual" ? annualMonthly : monthly}
                        </div>
                        <div className="text-[10px] text-muted-foreground mt-1">
                          /month{useStripe && upgradeCycle === "annual" ? " · billed annually" : ""}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* ── Delta — what you get / lose ── */}
                  {deltas.length > 0 ? (
                    <div className="rounded-lg border border-border bg-muted/20 p-4">
                      <div className="text-[11px] font-medium text-muted-foreground uppercase tracking-wide mb-2.5">
                        {isDown ? "What changes" : "What you get"}
                      </div>
                      <ul className="space-y-1.5">
                        {deltas.map((d, i) => (
                          <li key={i} className="flex items-start gap-2 text-sm">
                            {d.kind === "removed"
                              ? <X className="w-4 h-4 mt-0.5 text-red-400 shrink-0" />
                              : <Check className="w-4 h-4 mt-0.5 text-[#10b981] shrink-0" />}
                            <span className={d.kind === "removed" ? "text-muted-foreground" : "text-foreground"}>
                              {d.text}
                            </span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : (
                    <div className="text-sm text-muted-foreground">
                      Your limits and features stay the same — only the plan tier changes.
                    </div>
                  )}

                  {/* ── Billing cycle toggle (paid checkout only) ── */}
                  {useStripe && monthly > 0 && (
                    <div className="space-y-2">
                      <div className="text-[11px] font-medium text-muted-foreground uppercase tracking-wide">Billing cycle</div>
                      <div className="grid grid-cols-2 gap-2">
                        <button
                          type="button"
                          onClick={() => setUpgradeCycle("monthly")}
                          className={cn(
                            "rounded-lg border px-3 py-2.5 text-left transition-colors",
                            upgradeCycle === "monthly"
                              ? "border-primary bg-primary/10"
                              : "border-border hover:bg-accent",
                          )}
                        >
                          <div className="text-sm font-medium text-foreground">Monthly</div>
                          <div className="text-xs text-muted-foreground">${monthly}/mo</div>
                        </button>
                        <button
                          type="button"
                          onClick={() => setUpgradeCycle("annual")}
                          disabled={annualMonthly <= 0}
                          className={cn(
                            "rounded-lg border px-3 py-2.5 text-left transition-colors disabled:opacity-50",
                            upgradeCycle === "annual"
                              ? "border-primary bg-primary/10"
                              : "border-border hover:bg-accent",
                          )}
                        >
                          <div className="text-sm font-medium text-foreground flex items-center gap-1.5">
                            Annual
                            {annualSavings > 0 && (
                              <span className="text-[10px] text-[#10b981] bg-[#10b981]/10 px-1.5 py-0.5 rounded">
                                Save {annualSavings}%
                              </span>
                            )}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {annualMonthly > 0 ? `$${annualMonthly}/mo · billed annually` : "—"}
                          </div>
                        </button>
                      </div>
                    </div>
                  )}

                  {/* ── Order summary (paid checkout only) ── */}
                  {useStripe && monthly > 0 && (
                    <div className="rounded-lg border border-border bg-muted/20 p-3 space-y-1.5">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">
                          {target.label} — {upgradeCycle === "annual" ? "Annual" : "Monthly"}
                        </span>
                        <span className="font-mono text-foreground">${todayPrice.toLocaleString()}.00</span>
                      </div>
                      <div className="flex items-center justify-between text-xs text-muted-foreground">
                        <span>Tax</span>
                        <span>Calculated at checkout</span>
                      </div>
                      <div className="border-t border-border/60 pt-1.5 flex items-center justify-between text-sm font-semibold">
                        <span className="text-foreground">Total today</span>
                        <span className="font-mono text-foreground">${todayPrice.toLocaleString()}.00</span>
                      </div>
                    </div>
                  )}

                  {/* ── Buttons ── */}
                  <div className="flex gap-3 justify-end">
                    <Button variant="outline" onClick={() => setShowUpgrade(null)} className="border-border text-foreground hover:bg-accent">
                      Cancel
                    </Button>
                    <Button
                      onClick={() => {
                        if (!showUpgrade) return;
                        if (useStripe) handleStripeCheckout(showUpgrade, upgradeCycle);
                        else handleUpgrade(showUpgrade);
                      }}
                      disabled={upgrading}
                      className="bg-primary hover:bg-primary/90"
                    >
                      {upgrading
                        ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />{useStripe ? "Redirecting to secure checkout…" : "Processing…"}</>
                        : useStripe
                          ? <><CreditCard className="w-4 h-4 mr-2" />Continue to secure checkout</>
                          : BILLING_ENABLED
                            ? (isDown ? "Confirm downgrade" : "Confirm upgrade")
                            : "Confirm switch"}
                    </Button>
                  </div>

                  {/* ── Trust strip (paid checkout only) ── */}
                  {useStripe && (
                    <div className="flex items-center justify-center flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
                      <span className="inline-flex items-center gap-1">
                        <Lock className="w-3 h-3" />
                        Secure payment
                      </span>
                      <span className="text-muted-foreground/40">·</span>
                      <span>Cancel anytime</span>
                      <span className="text-muted-foreground/40">·</span>
                      <span>No long-term commitment</span>
                    </div>
                  )}
                </div>
              );
            })()}
          </DialogContent>
        </Dialog>
      </div>

      <PlanLimitDialog {...planLimit} />
    </main>
  );
}
