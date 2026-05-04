// Asset criticality UI primitives.
//
// Tier 1 / 2 / 3 reflect business importance. Findings on a tier_1
// asset count 1.5x in exposure-score rollups; tier_3 count 0.5x.
// Default for any new or unclassified asset is tier_2.

"use client";

import { Crown, Layers, Leaf } from "lucide-react";
import type { AssetCriticality } from "../types";

export const CRITICALITY_META: Record<AssetCriticality, {
  label: string;
  short: string;
  description: string;
  icon: typeof Crown;
  iconColor: string;
  badge: string;
  ring: string;
}> = {
  tier_1: {
    label: "Tier 1 — Mission critical",
    short: "Tier 1",
    description: "Customer-facing, regulated, or revenue-critical. Findings here weigh 1.5×.",
    icon: Crown,
    iconColor: "text-rose-300",
    badge: "bg-rose-500/15 text-rose-200 border-rose-500/30",
    ring: "ring-rose-500/40",
  },
  tier_2: {
    label: "Tier 2 — Standard",
    short: "Tier 2",
    description: "Normal weighting. Default for any new asset.",
    icon: Layers,
    iconColor: "text-foreground/70",
    badge: "bg-muted/40 text-foreground/80 border-border",
    ring: "ring-foreground/20",
  },
  tier_3: {
    label: "Tier 3 — Low impact",
    short: "Tier 3",
    description: "Test, dev, or sandbox. Findings here weigh 0.5×.",
    icon: Leaf,
    iconColor: "text-emerald-300",
    badge: "bg-emerald-500/10 text-emerald-200 border-emerald-500/30",
    ring: "ring-emerald-500/40",
  },
};

const CRITICALITY_ORDER: AssetCriticality[] = ["tier_1", "tier_2", "tier_3"];

function cn(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(" ");
}

export function CriticalityBadge({
  value,
  size = "sm",
  withIcon = true,
}: {
  value: AssetCriticality | null | undefined;
  size?: "xs" | "sm" | "md";
  withIcon?: boolean;
}) {
  const meta = CRITICALITY_META[(value || "tier_2") as AssetCriticality];
  const Icon = meta.icon;
  const sizing =
    size === "xs"
      ? "px-1.5 py-0.5 text-[10px]"
      : size === "md"
      ? "px-2.5 py-1 text-xs"
      : "px-2 py-0.5 text-xs";
  return (
    <span
      title={meta.description}
      className={cn(
        "inline-flex items-center gap-1 rounded-md border font-medium",
        meta.badge,
        sizing,
      )}
    >
      {withIcon && <Icon className={cn("w-3 h-3", meta.iconColor)} />}
      {meta.short}
    </span>
  );
}

export function CriticalitySelector({
  value,
  onChange,
  disabled = false,
}: {
  value: AssetCriticality | null | undefined;
  onChange: (next: AssetCriticality) => void;
  disabled?: boolean;
}) {
  const current = (value || "tier_2") as AssetCriticality;
  return (
    <div className="inline-flex rounded-lg border border-border bg-card overflow-hidden">
      {CRITICALITY_ORDER.map((tier) => {
        const meta = CRITICALITY_META[tier];
        const Icon = meta.icon;
        const active = current === tier;
        return (
          <button
            key={tier}
            type="button"
            disabled={disabled}
            onClick={() => !disabled && !active && onChange(tier)}
            title={meta.description}
            className={cn(
              "inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors border-r border-border last:border-r-0",
              active
                ? cn(meta.badge, "ring-2 ring-inset", meta.ring)
                : "text-muted-foreground hover:bg-accent hover:text-foreground",
              disabled && "opacity-50 cursor-not-allowed",
            )}
          >
            <Icon className={cn("w-3 h-3", active ? meta.iconColor : "")} />
            {meta.short}
          </button>
        );
      })}
    </div>
  );
}
