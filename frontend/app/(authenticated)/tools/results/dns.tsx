"use client";

import React from "react";
import { Collapsible, IssuesList, ResultHeaderRow, SendTo, type Issue } from "./_shared";

export interface DNSLookupResponse {
  domain?: string;
  grade?: string | null;
  issues?: Issue[];
  resolvedIps?: string[];
  records?: Record<string, Array<{ value: string; ttl?: number; priority?: number }>>;
  dkim?: {
    found?: boolean;
    selectors?: Array<{ selector: string; record: string }>;
  };
}

export function DNSResult({ data }: { data: DNSLookupResponse }) {
  const records = data.records || {};
  return (
    <div className="space-y-4">
      <ResultHeaderRow
        grade={data.grade}
        label={data.domain ?? "Unknown"}
        subtitle={data.resolvedIps?.length ? `Resolves to ${data.resolvedIps.join(", ")}` : "No A records"}
      />
      {data.resolvedIps?.length ? (
        <div className="flex items-center gap-1.5 flex-wrap text-xs">
          <span className="text-muted-foreground/60">Resolved:</span>
          {data.resolvedIps.map((ip) => (
            <span key={ip} className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-card/50 border border-border font-mono text-foreground">
              {ip}
              <SendTo value={ip} kind="ip" />
            </span>
          ))}
        </div>
      ) : null}
      <IssuesList issues={data.issues} />
      {Object.keys(records).length > 0 && (
        <Collapsible title="DNS Records" defaultOpen>
          <div className="pt-3 space-y-3">
            {Object.entries(records).map(([type, recs]) => (
              <div key={type}>
                <div className="text-xs font-semibold text-primary mb-1">{type} Records</div>
                <div className="space-y-1">
                  {recs.map((r, i) => (
                    <div key={i} className="text-xs font-mono p-2 rounded bg-background/30 border border-border text-foreground">
                      {r.priority !== undefined && <span className="text-muted-foreground mr-2">{r.priority}</span>}
                      {r.value}
                      <span className="text-muted-foreground ml-2">TTL: {r.ttl}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Collapsible>
      )}
      {data.dkim && (
        <Collapsible title={`DKIM (${data.dkim.found ? `${data.dkim.selectors?.length ?? 0} found` : "not found"})`}>
          <div className="pt-3">
            {data.dkim.selectors?.map((s) => (
              <div key={s.selector} className="text-xs p-2 rounded border border-border bg-background/30 mb-1">
                <span className="font-semibold text-foreground">{s.selector}</span>
                <span className="text-muted-foreground ml-2">{s.record}</span>
              </div>
            ))}
            {!data.dkim.found && <div className="text-xs text-muted-foreground">No DKIM selectors found.</div>}
          </div>
        </Collapsible>
      )}
    </div>
  );
}
