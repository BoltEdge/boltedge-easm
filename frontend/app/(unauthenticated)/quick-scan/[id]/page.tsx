// app/(marketing)/quick-scan/[id]/page.tsx
"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

import { getScanJobDetail, getScanJobFindings } from "../../../lib/api";
import type { Finding } from "../../../types";
import { SeverityBadge } from "../../../SeverityBadge";

function rankSev(sev: string) {
  const order = ["critical", "high", "medium", "low", "info"];
  const i = order.indexOf((sev || "info").toLowerCase());
  return i === -1 ? 999 : i;
}

function maxSeverityFromFindings(findings: Finding[]) {
  let best = "info";
  for (const f of findings) {
    const s = (f.severity || "info").toLowerCase();
    if (rankSev(s) < rankSev(best)) best = s;
  }
  return best;
}

export default function QuickScanDetailsPage() {
  const params = useParams<{ id: string }>();
  const jobId = params.id;

  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState<any>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);

  const maxSev = useMemo(() => maxSeverityFromFindings(findings), [findings]);

  useEffect(() => {
    let alive = true;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const d = await getScanJobDetail(jobId);
        const f = await getScanJobFindings(jobId);
        if (!alive) return;
        setDetail(d);
        setFindings(Array.isArray(f) ? f : []);
      } catch (e: any) {
        if (!alive) return;
        setError(e?.message || "Failed to load scan details");
      } finally {
        if (alive) setLoading(false);
      }
    }

    load();
    return () => {
      alive = false;
    };
  }, [jobId]);

  if (loading) {
    return (
      <div className="min-h-screen bg-background text-foreground">
        <div className="mx-auto max-w-4xl px-6 py-10 text-muted-foreground">
          Loading scan details...
        </div>
      </div>
    );
  }

  if (error || !detail) {
    return (
      <div className="min-h-screen bg-background text-foreground">
        <div className="mx-auto max-w-4xl px-6 py-10">
          <div className="text-xl font-semibold">Quick scan not available</div>
          <div className="mt-2 text-sm text-red-300">{error || "Unknown error"}</div>
          <Link href="/" className="mt-6 inline-block text-primary hover:underline">
            ← Back to Home
          </Link>
        </div>
      </div>
    );
  }

  const rj = detail?.result_json || detail?.resultJson || {};
  const ips = rj?.summary?.ips_scanned || rj?.summary?.resolved_ips || rj?.ips_scanned || rj?.resolved_ips || [];

  const assetLabel = detail.asset_value || detail.assetValue || "Unknown asset";

  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="mx-auto max-w-4xl px-6 py-10 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm text-muted-foreground">Quick Scan</div>
            <h1 className="text-2xl font-semibold">{assetLabel}</h1>
            <div className="mt-1 text-sm text-muted-foreground">
              Status: <span className="text-foreground">{detail.status}</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <SeverityBadge severity={maxSev as any} />
            <Link href="/" className="text-sm text-primary hover:underline">
              Back to Home
            </Link>
          </div>
        </div>

        <div className="rounded-xl border border-border bg-card/40 p-4">
          <div className="text-sm font-semibold">Summary</div>
          <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
            <div className="rounded-lg border border-border bg-background/30 p-3">
              <div className="text-xs text-muted-foreground">Total findings</div>
              <div className="mt-1 text-xl font-semibold">{findings.length}</div>
            </div>

            <div className="rounded-lg border border-border bg-background/30 p-3 md:col-span-2">
              <div className="text-xs text-muted-foreground">IPs scanned</div>
              <div className="mt-2 font-mono text-sm">
                {Array.isArray(ips) && ips.length ? ips.join(", ") : "—"}
              </div>
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-border bg-card/40 overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <div className="font-semibold">Findings</div>
            <div className="text-xs text-muted-foreground">{findings.length} results</div>
          </div>

          {findings.length === 0 ? (
            <div className="p-6 text-sm text-muted-foreground">No findings.</div>
          ) : (
            <div className="divide-y divide-border">
              {findings.map((f) => {
                const title = (f.title || (f as any).name || "Finding").toString();
                const desc = (f.description || (f as any).summary || "—").toString();

                return (
                  <div key={String(f.id)} className="p-4 hover:bg-accent/30 transition">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="font-medium truncate">{title}</div>
                        <div className="mt-1 text-sm text-muted-foreground line-clamp-2">
                          {desc}
                        </div>
                      </div>
                      <SeverityBadge severity={(f.severity || "info") as any} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
