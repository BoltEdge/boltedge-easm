"use client";

import React from "react";
import { cn } from "../../../lib/utils";
import { Collapsible, IssuesList, SendTo, type Issue } from "./_shared";

export interface ReverseDNSResponse {
  ip?: string;
  hostnames?: string[];
  issues?: Issue[];
  ptrRecords?: Array<{ hostname: string; ttl: number | null }>;
  forwardConfirmation?: Array<{
    hostname: string;
    confirmed: boolean;
    forwardIps?: string[];
  }>;
  infrastructure?: Array<{ hostname: string; type: string }>;
}

export function ReverseDNSResult({ data }: { data: ReverseDNSResponse }) {
  return (
    <div className="space-y-4">
      <div>
        <div className="text-sm font-medium text-foreground">{data.ip}</div>
        <div className="text-xs text-muted-foreground">
          {data.hostnames?.length ? `→ ${data.hostnames.join(", ")}` : "No PTR records"}
        </div>
      </div>
      <IssuesList issues={data.issues} />
      {data.ptrRecords?.length ? (
        <Collapsible title="PTR Records" defaultOpen>
          <div className="pt-3 space-y-1">
            {data.ptrRecords.map((r, i) => (
              <div key={i} className="text-xs font-mono p-2 rounded bg-background/30 border border-border text-foreground flex items-center gap-2">
                <span className="flex-1 break-all">{r.hostname}</span>
                {r.ttl !== null && <span className="text-muted-foreground">TTL: {r.ttl}</span>}
                <SendTo value={r.hostname} kind="hostname" />
              </div>
            ))}
          </div>
        </Collapsible>
      ) : null}
      {data.forwardConfirmation?.length ? (
        <Collapsible title="Forward Confirmation">
          <div className="pt-3 space-y-1">
            {data.forwardConfirmation.map((fc, i) => (
              <div key={i} className={cn("text-xs p-2 rounded border bg-background/30",
                fc.confirmed ? "border-emerald-500/30" : "border-red-500/30")}>
                <span className="font-mono text-foreground">{fc.hostname}</span>
                <span className="ml-2">→ {fc.forwardIps?.join(", ") || "no IPs"}</span>
                <span className={cn("ml-2 font-semibold",
                  fc.confirmed ? "text-emerald-400" : "text-red-400")}>
                  {fc.confirmed ? "✓ Confirmed" : "✗ Mismatch"}
                </span>
              </div>
            ))}
          </div>
        </Collapsible>
      ) : null}
      {data.infrastructure?.length ? (
        <Collapsible title="Infrastructure Indicators">
          <div className="pt-3 space-y-1">
            {data.infrastructure.map((inf, i) => (
              <div key={i} className="text-xs p-2 rounded border border-border bg-background/30">
                <span className="text-foreground font-mono">{inf.hostname}</span>
                <span className="text-primary ml-2">{inf.type}</span>
              </div>
            ))}
          </div>
        </Collapsible>
      ) : null}
    </div>
  );
}
