// FILE: app/ui/plan-limit-dialog.tsx
// Global dialog for plan limit / feature / permission errors
// Usage: import { usePlanLimit, PlanLimitDialog } from "../ui/plan-limit-dialog"
//
// In your page:
//   const planLimit = usePlanLimit();
//   // In your catch block:
//   planLimit.handle(errorData);
//   // In your JSX:
//   <PlanLimitDialog {...planLimit} />

"use client";

import React, { useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { AlertCircle, Lock, ArrowUpCircle, ShieldAlert } from "lucide-react";
import { Button } from "./button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "./dialog";

// ── Types ──

export type PlanErrorCode =
  | "PLAN_LIMIT_REACHED"
  | "FEATURE_NOT_AVAILABLE"
  | "PROFILE_NOT_AVAILABLE";

export interface PlanErrorData {
  error: string;
  code?: PlanErrorCode;
  resource?: string;
  limit?: number;
  current?: number;
  feature?: string;
  profile?: string;
  allowed_profiles?: string[];
  plan?: string;
  upgrade_url?: string;
  required_role?: string;
  required_permission?: string;
  your_role?: string;
}

export interface PlanLimitState {
  open: boolean;
  data: PlanErrorData | null;
  handle: (data: PlanErrorData) => void;
  close: () => void;
}

// ── Hook ──

export function usePlanLimit(): PlanLimitState {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<PlanErrorData | null>(null);

  const handle = useCallback((d: PlanErrorData) => {
    setData(d);
    setOpen(true);
  }, []);

  const close = useCallback(() => {
    setOpen(false);
    setData(null);
  }, []);

  return { open, data, handle, close };
}

// ── Helper: check if a 403 response is a plan/permission error ──

export function isPlanError(data: any): data is PlanErrorData {
  return (
    data &&
    typeof data.error === "string" &&
    (data.code === "PLAN_LIMIT_REACHED" ||
      data.code === "FEATURE_NOT_AVAILABLE" ||
      data.code === "PROFILE_NOT_AVAILABLE" ||
      data.required_role ||
      data.required_permission)
  );
}

// ── Helper: integrate into your apiFetch ──
// Add this to your api.ts apiFetch function:
//
//   if (res.status === 403) {
//     const data = await res.json();
//     if (isPlanError(data)) {
//       // Option A: throw enriched error so the caller can handle it
//       const err = new Error(data.error) as any;
//       err.planError = data;
//       throw err;
//     }
//   }
//
// Then in your page catch blocks:
//
//   catch (e: any) {
//     if (e.planError) {
//       planLimit.handle(e.planError);
//     } else {
//       setBanner({ kind: "err", text: e.message });
//     }
//   }

// ── Dialog Component ──

export function PlanLimitDialog({ open, data, close }: PlanLimitState) {
  const router = useRouter();

  if (!data) return null;

  const isPlan = data.code === "PLAN_LIMIT_REACHED";
  const isFeature = data.code === "FEATURE_NOT_AVAILABLE";
  const isProfile = data.code === "PROFILE_NOT_AVAILABLE";
  const isRole = !data.code && (data.required_role || data.required_permission);

  const planLabel = (data.plan || "free").replace("_", " ").replace(/\b\w/g, (c) => c.toUpperCase());

  function handleUpgrade() {
    close();
    router.push(data?.upgrade_url || "/settings/billing");
  }

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) close(); }}>
      <DialogContent className="bg-card border-border text-foreground sm:max-w-[440px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {isRole ? (
              <><Lock className="w-5 h-5 text-red-400" />Insufficient Permissions</>
            ) : (
              <><ArrowUpCircle className="w-5 h-5 text-primary" />Upgrade Required</>
            )}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 pt-1">
          {/* Plan Limit Reached */}
          {isPlan && (
            <>
              <div className="flex items-center gap-3 p-4 rounded-xl bg-[#ff8800]/10 border border-[#ff8800]/30">
                <AlertCircle className="w-5 h-5 text-[#ff8800] shrink-0" />
                <div>
                  <p className="text-sm font-semibold text-foreground">
                    {data.resource === "assets" && "Asset limit reached"}
                    {data.resource === "scans_per_month" && "Monthly scan limit reached"}
                    {data.resource === "scheduled_scans" && "Schedule limit reached"}
                    {data.resource === "api_keys" && "API key limit reached"}
                    {data.resource === "team_members" && "Team member limit reached"}
                  </p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    You&apos;re using <span className="font-semibold text-foreground">{data.current}</span> of <span className="font-semibold text-foreground">{data.limit}</span> allowed on the <span className="font-semibold text-foreground">{planLabel}</span> plan.
                  </p>
                </div>
              </div>
              <p className="text-sm text-muted-foreground">
                Upgrade your plan to increase your {data.resource?.replace(/_/g, " ")} limit.
              </p>
            </>
          )}

          {/* Feature Not Available */}
          {isFeature && (
            <>
              <div className="flex items-center gap-3 p-4 rounded-xl bg-primary/10 border border-primary/30">
                <ShieldAlert className="w-5 h-5 text-primary shrink-0" />
                <div>
                  <p className="text-sm font-semibold text-foreground">
                    {data.feature === "monitoring" && "Monitoring is not available"}
                    {data.feature === "deep_discovery" && "Deep Discovery is not available"}
                    {data.feature === "webhooks" && "Webhooks are not available"}
                    {!["monitoring", "deep_discovery", "webhooks"].includes(data.feature || "") && `${data.feature} is not available`}
                  </p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    This feature is not included in the <span className="font-semibold text-foreground">{planLabel}</span> plan.
                  </p>
                </div>
              </div>
              <p className="text-sm text-muted-foreground">
                Upgrade to a plan that includes {data.feature?.replace(/_/g, " ")} to use this feature.
              </p>
            </>
          )}

          {/* Profile Not Available */}
          {isProfile && (
            <>
              <div className="flex items-center gap-3 p-4 rounded-xl bg-[#ff8800]/10 border border-[#ff8800]/30">
                <ShieldAlert className="w-5 h-5 text-[#ff8800] shrink-0" />
                <div>
                  <p className="text-sm font-semibold text-foreground">
                    Scan profile &quot;{data.profile}&quot; is not available
                  </p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Your <span className="font-semibold text-foreground">{planLabel}</span> plan allows: {data.allowed_profiles?.join(", ") || "quick, standard"}
                  </p>
                </div>
              </div>
              <p className="text-sm text-muted-foreground">
                Upgrade your plan to unlock additional scan profiles.
              </p>
            </>
          )}

          {/* Role / Permission Insufficient */}
          {isRole && (
            <>
              <div className="flex items-center gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/30">
                <Lock className="w-5 h-5 text-red-400 shrink-0" />
                <div>
                  <p className="text-sm font-semibold text-foreground">
                    {data.required_role
                      ? `This action requires the ${data.required_role} role or higher.`
                      : `You need the "${data.required_permission?.replace(/_/g, " ")}" permission.`}
                  </p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Your current role: <span className="font-semibold text-foreground">{data.your_role}</span>
                  </p>
                </div>
              </div>
              <p className="text-sm text-muted-foreground">
                Contact your organization&apos;s owner or admin to request access.
              </p>
            </>
          )}

          {/* Actions */}
          <div className="flex gap-3 justify-end pt-2">
            <Button variant="outline" onClick={close} className="border-border text-foreground hover:bg-accent">
              {isRole ? "OK" : "Maybe Later"}
            </Button>
            {!isRole && (
              <Button onClick={handleUpgrade} className="bg-primary hover:bg-primary/90">
                <ArrowUpCircle className="w-4 h-4 mr-2" />Upgrade Plan
              </Button>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}