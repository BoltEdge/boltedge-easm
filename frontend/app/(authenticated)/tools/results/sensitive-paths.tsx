"use client";

import React from "react";
import { cn } from "../../../lib/utils";
import {
  Collapsible, IssuesList, ResultEmptyOk, SEV_BORDER, type Issue,
} from "./_shared";

const PATH_CAT_ICONS: Record<string, string> = {
  source_control: "🔓",
  secrets: "🔑",
  config: "⚙️",
  data_leak: "💾",
  info_leak: "ℹ️",
  recon: "🔍",
};

export interface SensitivePathsResponse {
  domain?: string;
  pathsChecked?: number;
  pathsFound?: number;
  issues?: Issue[];
  severityCounts?: { critical?: number; high?: number; medium?: number; low?: number };
  findings?: Array<{
    title: string;
    description?: string;
    path: string;
    status?: number;
    severity: string;
    category?: string;
    confirmed?: boolean;
    snippet?: string;
  }>;
}

export function SensitivePathsResult({ data }: { data: SensitivePathsResponse }) {
  const findings = data.findings || [];
  const sevCounts = data.severityCounts || {};
  return (
    <div className="space-y-4">
      <div>
        <div className="text-sm font-medium text-foreground">{data.domain}</div>
        <div className="text-xs text-muted-foreground">
          Checked {data.pathsChecked} paths · Found {data.pathsFound} exposed
        </div>
      </div>
      {(data.pathsFound ?? 0) > 0 && (
        <div className="flex gap-2 flex-wrap">
          {!!sevCounts.critical && <span className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/20">{sevCounts.critical} Critical</span>}
          {!!sevCounts.high && <span className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-orange-500/15 text-orange-400 border border-orange-500/20">{sevCounts.high} High</span>}
          {!!sevCounts.medium && <span className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-yellow-500/15 text-yellow-400 border border-yellow-500/20">{sevCounts.medium} Medium</span>}
        </div>
      )}
      <IssuesList issues={data.issues} />
      {findings.length > 0 && (
        <Collapsible title={`Exposed Paths (${findings.length})`} defaultOpen>
          <div className="pt-3 space-y-2">
            {findings.map((f, i) => {
              const icon = PATH_CAT_ICONS[f.category ?? "recon"] ?? PATH_CAT_ICONS.recon;
              return (
                <div key={i} className={cn(
                  "p-3 rounded-lg border-l-2 bg-card/30 border border-border",
                  SEV_BORDER[f.severity] || SEV_BORDER.info,
                )}>
                  <div className="flex items-center gap-2 mb-1">
                    <span>{icon}</span>
                    <span className="text-sm font-medium text-foreground">{f.title}</span>
                    <span className="ml-auto px-1.5 py-0.5 rounded text-[10px] font-semibold bg-muted/30 text-muted-foreground border border-border/50">HTTP {f.status}</span>
                    {f.confirmed && (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Confirmed</span>
                    )}
                  </div>
                  <div className="text-xs font-mono text-primary">{f.path}</div>
                  {f.description && <div className="text-xs text-muted-foreground mt-1">{f.description}</div>}
                  {f.snippet && (
                    <div className="mt-2 p-2 rounded bg-background/30 border border-border text-xs font-mono text-muted-foreground max-h-20 overflow-y-auto whitespace-pre-wrap">
                      {f.snippet}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Collapsible>
      )}
      {data.pathsFound === 0 && <ResultEmptyOk message="No exposed sensitive files detected." />}
    </div>
  );
}
