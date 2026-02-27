"use client";

import { useEffect, useState } from "react";
import { getAssetRisk, type AssetRisk } from "@/app/lib/api";

interface RiskScoreBadgeProps {
  assetId: string | number;
}

type Sev = "critical" | "high" | "medium" | "low" | "info";

function normalizeSev(s: any): Sev {
  const v = String(s || "info").toLowerCase();
  if (v === "critical" || v === "high" || v === "medium" || v === "low" || v === "info") return v;
  return "info";
}

function computeMaxSeverity(counts: Record<Sev, number>): Sev {
  for (const k of ["critical", "high", "medium", "low", "info"] as const) {
    if ((counts[k] || 0) > 0) return k;
  }
  return "info";
}

function normalizeCounts(raw: any): Record<Sev, number> {
  const src = raw || {};
  return {
    critical: Number(src.critical || 0),
    high: Number(src.high || 0),
    medium: Number(src.medium || 0),
    low: Number(src.low || 0),
    info: Number(src.info || 0),
  };
}

/**
 * Adapter: supports both shapes:
 * - expected frontend shape: { totalFindings, counts, maxSeverity }
 * - current backend shape: { openFindings, bySeverity, maxSeverity }
 */
function normalizeRisk(input: any): AssetRisk {
  const counts = normalizeCounts(input?.counts ?? input?.bySeverity);
  const total =
    input?.totalFindings != null
      ? Number(input.totalFindings || 0)
      : input?.openFindings != null
        ? Number(input.openFindings || 0)
        : Object.values(counts).reduce((a, b) => a + Number(b || 0), 0);

  const maxSeverity = normalizeSev(input?.maxSeverity ?? computeMaxSeverity(counts));

  return {
    assetId: String(input?.assetId ?? input?.id ?? ""),
    maxSeverity,
    totalFindings: total,
    counts,
  };
}

function pillClassFor(sev: Sev, total: number) {
  if (total <= 0) return "bg-[#9e9e9e]/20 text-[#9e9e9e]";
  if (sev === "critical") return "bg-[#ff4444]/20 text-[#ff4444]";
  if (sev === "high") return "bg-[#ff8800]/20 text-[#ff8800]";
  if (sev === "medium") return "bg-[#ffcc00]/20 text-[#ffcc00]";
  if (sev === "low") return "bg-[#00b8d4]/20 text-[#00b8d4]";
  return "bg-[#00b8d4]/20 text-[#00b8d4]";
}

function labelFor(sev: Sev, total: number) {
  if (total <= 0) return "No Issues";
  if (sev === "critical") return `Critical (${total})`;
  if (sev === "high") return `High Risk (${total})`;
  if (sev === "medium") return `Medium Risk (${total})`;
  if (sev === "low") return `Low Risk (${total})`;
  return `Info (${total})`;
}

export function RiskScoreBadge({ assetId }: RiskScoreBadgeProps) {
  const [data, setData] = useState<AssetRisk | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        setFailed(false);
        const raw = await getAssetRisk(String(assetId));
        const risk = normalizeRisk(raw);
        if (!cancelled) setData(risk);
      } catch (e) {
        console.error("RiskScoreBadge fetch failed:", e);
        if (!cancelled) {
          setFailed(true);
          setData(null);
        }
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, [assetId]);

  const total = Number(data?.totalFindings || 0);
  const sev = normalizeSev(data?.maxSeverity);

  const cls = failed ? "bg-[#9e9e9e]/20 text-[#9e9e9e]" : pillClassFor(sev, total);

  const text = failed ? "—" : data ? labelFor(sev, total) : "Loading…";

  return (
    <span className={`inline-flex items-center px-2 py-1 rounded-md text-xs font-semibold ${cls}`}>
      {text}
    </span>
  );
}
