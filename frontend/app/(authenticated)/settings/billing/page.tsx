// FILE: app/(authenticated)/settings/billing/page.tsx
// Payment & Plans — current plan, usage, trials, upgrade/downgrade
"use client";

import React, { useEffect, useState } from "react";
import { CreditCard, Check, Clock, Zap, Sparkles, Loader2, X, RefreshCcw } from "lucide-react";
import { cn } from "../../../lib/utils";
import { Button } from "../../../ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../../ui/dialog";
import { apiFetch, isPlanError } from "../../../lib/api";
import { useOrg } from "../../contexts/OrgContext";
import { usePlanLimit, PlanLimitDialog } from "../../../ui/plan-limit-dialog";

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  let d: Date;
  if (typeof iso === "string" && !iso.endsWith("Z") && !iso.includes("+")) d = new Date(iso + "Z");
  else d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export default function BillingPage() {
  const { canDo, refresh: refreshOrg } = useOrg();
  const planLimit = usePlanLimit();
  const canManageBilling = canDo("manage_billing");

  const [planData, setPlanData] = useState<any>(null);
  const [plans, setPlans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [actionPlan, setActionPlan] = useState<string | null>(null);
  const [showEndTrial, setShowEndTrial] = useState(false);
  const [endingTrial, setEndingTrial] = useState(false);
  const [showUpgrade, setShowUpgrade] = useState<string | null>(null);
  const [upgrading, setUpgrading] = useState(false);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  async function loadBilling(isRefresh = false) {
    if (isRefresh) setRefreshing(true); else setLoading(true);
    try {
      const [pd, pl] = await Promise.all([
        apiFetch<any>("/billing/plan"),
        apiFetch<any>("/billing/plans"),
      ]);
      setPlanData(pd);
      setPlans(Array.isArray(pl) ? pl : pl?.plans || []);
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed to load billing" });
    } finally { setLoading(false); setRefreshing(false); }
  }

  useEffect(() => { loadBilling(); }, []);
  useEffect(() => { if (banner) { const t = setTimeout(() => setBanner(null), 5000); return () => clearTimeout(t); } }, [banner]);

  async function handleStartTrial(planKey: string) {
    try {
      setActionPlan(planKey);
      await apiFetch<any>("/billing/start-trial", { method: "POST", body: JSON.stringify({ plan: planKey }) });
      setBanner({ kind: "ok", text: "Trial started! Refreshing..." });
      refreshOrg();
      setTimeout(() => window.location.reload(), 1200);
    } catch (e: any) {
      if (isPlanError(e)) planLimit.handle(e.planError);
      else setBanner({ kind: "err", text: e?.message || "Failed to start trial." });
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

  return (
    <main className="flex-1 overflow-y-auto bg-background">
      <div className="p-8 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-foreground flex items-center gap-3">
              <CreditCard className="w-7 h-7 text-primary" />Payment & Plans
            </h1>
            <p className="text-muted-foreground mt-1">Manage your subscription, trial, and usage.</p>
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

        {/* Trial Banner */}
        {isTrial && trialDaysLeft !== null && (
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
                  {isTrial && <span className="px-2 py-0.5 rounded-md bg-[#ff8800]/15 text-[#ff8800] text-xs font-semibold border border-[#ff8800]/30">Trial</span>}
                </h2>
                <p className="text-sm text-muted-foreground">Started {formatDate(planData.planStartedAt)}</p>
              </div>
            </div>
            <div className="text-right">
              <div className="text-3xl font-bold text-foreground">
                {pricing.monthly === 0 ? "Free" : pricing.monthly === -1 ? "Custom" : `$${pricing.monthly}`}
              </div>
              {pricing.monthly > 0 && <div className="text-xs text-muted-foreground">{isTrial ? "after trial ends" : "per month"}</div>}
            </div>
          </div>
          <div className="space-y-4">
            <UsageBar label="Assets" current={usage.assets} limit={limits.assets} />
            <UsageBar label="Scans this month" current={usage.scansThisMonth} limit={limits.scansPerMonth} />
            <UsageBar label="Schedules" current={usage.scheduledScans} limit={limits.scheduledScans} />
            <UsageBar label="Team members" current={usage.teamMembers} limit={limits.teamMembers} />
            <UsageBar label="API keys" current={usage.apiKeys} limit={limits.apiKeys} />
          </div>
        </div>

        {/* Available Plans */}
        <div>
          <h2 className="text-lg font-semibold text-foreground mb-4">Available Plans</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {plans.map((p) => {
              const planIdx = PLAN_ORDER.indexOf(p.key);
              const isCurrent = p.isCurrent;
              const isUpgrade = planIdx > currentIdx;
              const isDowngrade = planIdx < currentIdx;
              const color = TIER_COLORS[p.key] || "#7c5cfc";
              const canTrial = p.canTrial && !isTrial && !p.trialRequiresApproval;
              const needsApproval = p.canTrial && p.trialRequiresApproval;

              return (
                <div key={p.key} className={cn("bg-card border rounded-xl p-5 flex flex-col", isCurrent ? "ring-1" : "")}
                  style={{ borderColor: isCurrent ? `${color}80` : undefined, boxShadow: isCurrent ? `0 0 0 1px ${color}30` : undefined }}>
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-foreground font-semibold">{p.label}</h3>
                    {isCurrent && (
                      <span className="px-2 py-0.5 rounded-md text-xs font-semibold border"
                        style={{ backgroundColor: `${color}15`, color, borderColor: `${color}30` }}>
                        {isTrial ? "Trial" : "Current"}
                      </span>
                    )}
                  </div>
                  <div className="mb-4">
                    {p.priceMonthly === 0 ? <span className="text-2xl font-bold text-foreground">Free</span>
                      : p.priceMonthly === -1 ? <span className="text-2xl font-bold text-foreground">Custom</span>
                      : <><span className="text-2xl font-bold text-foreground">${p.priceMonthly}</span><span className="text-sm text-muted-foreground">/mo</span></>}
                    {p.priceAnnualMonthly > 0 && p.priceAnnualMonthly < p.priceMonthly && (
                      <div className="text-xs text-muted-foreground mt-0.5">${p.priceAnnualMonthly}/mo billed annually</div>
                    )}
                  </div>
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
                    ) : canManageBilling && isUpgrade ? (
                      <Button onClick={() => p.priceMonthly === -1 ? null : setShowUpgrade(p.key)} className="w-full bg-primary hover:bg-primary/90">
                        {p.priceMonthly === -1 ? "Contact Sales" : "Upgrade"}
                      </Button>
                    ) : canManageBilling && isDowngrade ? (
                      <Button variant="outline" onClick={() => setShowUpgrade(p.key)} className="w-full border-border text-foreground hover:bg-accent">Downgrade</Button>
                    ) : !canManageBilling && !isCurrent ? (
                      <Button variant="outline" disabled className="w-full border-border text-muted-foreground">Ask admin to upgrade</Button>
                    ) : null}
                    {canManageBilling && canTrial && (
                      <Button variant="outline" size="sm" onClick={() => handleStartTrial(p.key)} disabled={actionPlan !== null}
                        className="w-full text-xs" style={{ borderColor: `${color}40`, color }}>
                        {actionPlan === p.key ? <><Loader2 className="w-3 h-3 mr-1.5 animate-spin" />Starting...</> : <><Clock className="w-3 h-3 mr-1.5" />{p.trialDays}-Day Free Trial</>}
                      </Button>
                    )}
                    {needsApproval && <div className="text-[10px] text-muted-foreground text-center">{p.trialDays}-day trial — contact sales</div>}
                    {!p.canTrial && !isCurrent && trialedTiers.includes(p.key) && <div className="text-[10px] text-muted-foreground text-center">Trial used</div>}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* End Trial Dialog */}
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

        {/* Upgrade/Downgrade Dialog */}
        <Dialog open={!!showUpgrade} onOpenChange={(o) => { if (!o) setShowUpgrade(null); }}>
          <DialogContent className="bg-card border-border text-foreground sm:max-w-[440px]">
            <DialogHeader>
              <DialogTitle>
                {showUpgrade && PLAN_ORDER.indexOf(showUpgrade) < currentIdx ? "Downgrade" : "Upgrade"} Plan
              </DialogTitle>
            </DialogHeader>
            {showUpgrade && (() => {
              const target = plans.find((p) => p.key === showUpgrade);
              const isDown = PLAN_ORDER.indexOf(showUpgrade) < currentIdx;
              return (
                <p className="text-sm text-muted-foreground">
                  {isDown
                    ? <>Downgrading to <span className="text-foreground font-medium">{target?.label}</span> will reduce your limits.</>
                    : <>Upgrade to <span className="text-foreground font-medium">{target?.label}</span>{target?.priceMonthly > 0 ? <> at <span className="text-foreground font-medium">${target.priceMonthly}/mo</span></> : ""}? New limits take effect immediately.</>}
                </p>
              );
            })()}
            <div className="flex gap-3 justify-end pt-4">
              <Button variant="outline" onClick={() => setShowUpgrade(null)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
              <Button onClick={() => showUpgrade && handleUpgrade(showUpgrade)} disabled={upgrading} className="bg-primary hover:bg-primary/90">
                {upgrading ? "Processing..." : showUpgrade && PLAN_ORDER.indexOf(showUpgrade) < currentIdx ? "Confirm Downgrade" : "Confirm Upgrade"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <PlanLimitDialog {...planLimit} />
    </main>
  );
}