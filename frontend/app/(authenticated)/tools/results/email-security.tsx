"use client";

import React from "react";
import {
  Collapsible, IssuesList, KV, ProtocolBadge, ResultHeaderRow, type Issue,
} from "./_shared";

export interface EmailSecurityResponse {
  domain?: string;
  grade?: string | null;
  issues?: Issue[];
  spf?: {
    found?: boolean;
    record?: string;
    allQualifier?: string;
    lookupCount?: number;
    mechanisms?: Array<{ qualifier: string; mechanism: string }>;
  };
  dkim?: {
    found?: boolean;
    selectorCount?: number;
    selectors?: Array<{ selector: string; record: string; valid: boolean }>;
  };
  dmarc?: {
    found?: boolean;
    record?: string;
    policy?: string;
    subdomainPolicy?: string;
  };
}

export function EmailSecurityResult({ data }: { data: EmailSecurityResponse }) {
  const spf = data.spf || {};
  const dkim = data.dkim || {};
  const dmarc = data.dmarc || {};
  const spfDetail = spf.found
    ? `${spf.allQualifier === "-" ? "Hard fail" : spf.allQualifier === "~" ? "Soft fail" : "Other"} · ${spf.lookupCount} lookups`
    : undefined;
  const dkimDetail = dkim.found ? `${dkim.selectorCount ?? 0} selector${(dkim.selectorCount ?? 0) !== 1 ? "s" : ""}` : undefined;
  const dmarcDetail = dmarc.found ? `Policy: ${dmarc.policy || "none"}` : undefined;

  return (
    <div className="space-y-4">
      <ResultHeaderRow
        grade={data.grade}
        label={data.domain ?? ""}
        subtitle="Email authentication assessment"
      />
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
        <ProtocolBadge label="SPF" found={!!spf.found} detail={spfDetail} />
        <ProtocolBadge label="DKIM" found={!!dkim.found} detail={dkimDetail} />
        <ProtocolBadge label="DMARC" found={!!dmarc.found} detail={dmarcDetail} />
      </div>
      <IssuesList issues={data.issues} />
      {spf.found && (
        <Collapsible title="SPF Record" defaultOpen>
          <div className="pt-3 space-y-2">
            <div className="text-xs font-mono p-2.5 rounded-lg bg-background/30 border border-border text-foreground break-all">{spf.record}</div>
            <KV label="DNS Lookups" value={`${spf.lookupCount} / 10`} />
            {spf.mechanisms?.length ? (
              <div className="flex flex-wrap gap-1.5">
                {spf.mechanisms.map((m, i) => (
                  <span key={i} className="px-2 py-1 rounded text-xs font-mono bg-card/50 border border-border text-foreground">
                    {m.qualifier !== "+" && <span className="text-muted-foreground">{m.qualifier}</span>}
                    {m.mechanism}
                  </span>
                ))}
              </div>
            ) : null}
          </div>
        </Collapsible>
      )}
      {dkim.selectors?.length ? (
        <Collapsible title={`DKIM Selectors (${dkim.selectors.length})`}>
          <div className="pt-3 space-y-2">
            {dkim.selectors.map((s) => (
              <div key={s.selector} className="p-2.5 rounded-lg border border-border bg-background/30">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-semibold text-foreground">{s.selector}</span>
                  {s.valid
                    ? <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Valid</span>
                    : <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-500/10 text-red-400 border border-red-500/20">Invalid</span>}
                </div>
                <div className="text-[11px] font-mono text-muted-foreground break-all">{s.record}</div>
              </div>
            ))}
          </div>
        </Collapsible>
      ) : null}
      {dmarc.found && (
        <Collapsible title="DMARC Record">
          <div className="pt-3 space-y-2">
            {dmarc.record && <div className="text-xs font-mono p-2.5 rounded-lg bg-background/30 border border-border text-foreground break-all">{dmarc.record}</div>}
            <KV label="Policy" value={dmarc.policy} />
            <KV label="Subdomain Policy" value={dmarc.subdomainPolicy} />
          </div>
        </Collapsible>
      )}
    </div>
  );
}
