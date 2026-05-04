"use client";

import React from "react";
import { CheckCircle2, AlertTriangle } from "lucide-react";
import { cn } from "../../../lib/utils";
import { Collapsible, IssuesList, ResultHeaderRow, type Issue } from "./_shared";

export interface HeaderCheckResponse {
  domain?: string;
  grade?: string | null;
  issues?: Issue[];
  https?: {
    statusCode?: number;
    headers?: Record<string, string>;
  };
  httpRedirectsToHttps?: boolean;
  headerSummary?: Record<string, { present: boolean }>;
}

export function HeaderResult({ data }: { data: HeaderCheckResponse }) {
  const summary = data.headerSummary || {};
  return (
    <div className="space-y-4">
      <ResultHeaderRow
        grade={data.grade}
        label={data.domain ?? "Unknown"}
        subtitle={(
          <>
            {data.https ? `HTTPS: ${data.https.statusCode}` : "HTTPS unavailable"}
            {data.httpRedirectsToHttps !== undefined && (
              <span className={cn("ml-2", data.httpRedirectsToHttps ? "text-emerald-400" : "text-red-400")}>
                {data.httpRedirectsToHttps ? "· HTTP → HTTPS ✓" : "· No HTTP redirect"}
              </span>
            )}
          </>
        )}
      />
      {Object.keys(summary).length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
          {Object.entries(summary).map(([alias, info]) => (
            <div key={alias} className={cn(
              "flex items-center gap-2 px-3 py-2 rounded-lg border text-xs",
              info.present
                ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-400"
                : "border-red-500/20 bg-red-500/5 text-red-400",
            )}>
              {info.present
                ? <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                : <AlertTriangle className="w-3.5 h-3.5 shrink-0" />}
              <span className="font-semibold">{alias}</span>
            </div>
          ))}
        </div>
      )}
      <IssuesList issues={data.issues} />
      {data.https?.headers && (
        <Collapsible title="Raw Headers">
          <div className="pt-3 space-y-0.5 max-h-64 overflow-y-auto">
            {Object.entries(data.https.headers).map(([k, v]) => (
              <div key={k} className="text-xs font-mono">
                <span className="text-primary">{k}:</span> <span className="text-foreground break-all">{v}</span>
              </div>
            ))}
          </div>
        </Collapsible>
      )}
    </div>
  );
}
