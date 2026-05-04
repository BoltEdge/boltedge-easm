"use client";

import React from "react";
import { cn } from "../../../lib/utils";
import { Collapsible, IssuesList, KV, type Issue } from "./_shared";

export interface ConnectivityResponse {
  host?: string;
  resolvedIp?: string;
  port?: number | null;
  result?: {
    reachable?: boolean;
    latencyMs?: number;
    service?: string;
    banner?: string;
    error?: string;
    tls?: { version?: string; cipher?: string };
  };
  ports?: Array<{
    port: number;
    reachable: boolean;
    latencyMs?: number;
    expectedService?: string;
    error?: string;
  }>;
  totalChecked?: number;
  openPorts?: number;
  closedPorts?: number;
  issues?: Issue[];
}

export function ConnectivityResult({ data }: { data: ConnectivityResponse }) {
  const single = data.result;
  const ports = data.ports;
  return (
    <div className="space-y-4">
      <div>
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-foreground font-mono">{data.host}</span>
          {data.resolvedIp && data.resolvedIp !== data.host && (
            <span className="text-xs text-muted-foreground">→ {data.resolvedIp}</span>
          )}
        </div>
        {data.port && (
          <div className="text-xs text-muted-foreground mt-0.5">
            Port {data.port}
            {single?.reachable
              ? <span className="text-emerald-400 ml-2">· Reachable ({single.latencyMs}ms)</span>
              : <span className="text-red-400 ml-2">· Not reachable</span>}
          </div>
        )}
        {!data.port && ports && (
          <div className="text-xs text-muted-foreground mt-0.5">
            Scanned {data.totalChecked} ports · <span className="text-emerald-400">{data.openPorts} open</span> · {data.closedPorts} closed
          </div>
        )}
      </div>
      <IssuesList issues={data.issues} />
      {single && (
        <Collapsible title="Connection Details" defaultOpen>
          <div className="pt-3 space-y-0.5">
            <KV label="Reachable" value={single.reachable} />
            <KV label="Latency" value={single.latencyMs ? `${single.latencyMs}ms` : null} />
            <KV label="Service" value={single.service} />
            <KV label="Banner" value={single.banner} mono />
            {single.tls && (
              <>
                <KV label="TLS Version" value={single.tls.version} />
                <KV label="Cipher" value={single.tls.cipher} mono />
              </>
            )}
          </div>
        </Collapsible>
      )}
      {ports && (
        <Collapsible title={`Port Results (${ports.length})`} defaultOpen>
          <div className="pt-3 grid grid-cols-1 gap-1.5">
            {ports.map((p) => (
              <div key={p.port} className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg border text-xs",
                p.reachable ? "border-emerald-500/20 bg-emerald-500/5" : "border-border bg-card/20",
              )}>
                <div className={cn("w-2 h-2 rounded-full shrink-0", p.reachable ? "bg-emerald-400" : "bg-muted-foreground/30")} />
                <span className="font-mono font-semibold text-foreground w-14">{p.port}</span>
                <span className="text-muted-foreground w-20">{p.expectedService || ""}</span>
                {p.reachable ? (
                  <>
                    <span className="text-emerald-400 font-medium">Open</span>
                    <span className="text-muted-foreground ml-auto">{p.latencyMs}ms</span>
                  </>
                ) : (
                  <span className="text-muted-foreground">{p.error?.includes("refused") ? "Closed" : "Filtered"}</span>
                )}
              </div>
            ))}
          </div>
        </Collapsible>
      )}
    </div>
  );
}
