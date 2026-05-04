"use client";

import React from "react";
import { cn } from "../../../lib/utils";
import { Collapsible, IssuesList, KV, ResultHeaderRow, type Issue } from "./_shared";

type Registration = {
  registrar?: string;
  creationDate?: string;
  expiryDate?: string;
  updatedDate?: string;
  domainAgeDays?: number;
  registrantOrg?: string;
  dnssec?: boolean | string;
  daysUntilExpiry?: number;
  nameservers?: string[];
};
type Network = {
  netName?: string;
  netRange?: string;
  cidr?: string;
  orgName?: string;
  country?: string;
};
type ASNInfo = {
  number?: string | number;
  name?: string;
  orgName?: string;
  country?: string;
};

export interface WhoisResponse {
  query?: string;
  queryType?: "domain" | "ip" | "asn";
  issues?: Issue[];
  registration?: Registration;
  network?: Network;
  asn?: ASNInfo;
  rawWhois?: string;
}

export function WhoisResult({ data }: { data: WhoisResponse }) {
  const queryType = data.queryType || "domain";

  if (queryType === "domain") {
    const reg = data.registration || {};
    return (
      <div className="space-y-4">
        <ResultHeaderRow
          label={data.query ?? ""}
          subtitle={(
            <>
              {reg.registrar ? `Registered with ${reg.registrar}` : "Registrar unknown"}
              {reg.daysUntilExpiry !== undefined && (
                <span className={cn("ml-2", reg.daysUntilExpiry <= 30 ? "text-red-400" : "text-muted-foreground")}>
                  · Expires in {reg.daysUntilExpiry} days
                </span>
              )}
            </>
          )}
          badge={{ text: "DOMAIN", color: "var(--primary, #14b8a6)" }}
        />
        <IssuesList issues={data.issues} />
        <Collapsible title="Registration Details" defaultOpen>
          <div className="pt-3 space-y-0.5">
            <KV label="Registrar" value={reg.registrar} />
            <KV label="Created" value={reg.creationDate} />
            <KV label="Expires" value={reg.expiryDate} />
            <KV label="Updated" value={reg.updatedDate} />
            <KV label="Domain Age" value={reg.domainAgeDays ? `${reg.domainAgeDays} days` : null} />
            <KV label="Registrant Org" value={reg.registrantOrg} />
            <KV label="DNSSEC" value={reg.dnssec} />
          </div>
        </Collapsible>
        {reg.nameservers?.length ? (
          <Collapsible title={`Nameservers (${reg.nameservers.length})`}>
            <div className="pt-3 space-y-1">
              {reg.nameservers.map((ns) => (
                <div key={ns} className="text-xs font-mono p-2 rounded bg-background/30 border border-border text-foreground">{ns}</div>
              ))}
            </div>
          </Collapsible>
        ) : null}
        {data.rawWhois && (
          <Collapsible title="Raw WHOIS">
            <pre className="pt-3 text-xs font-mono text-muted-foreground whitespace-pre-wrap max-h-64 overflow-y-auto">{data.rawWhois}</pre>
          </Collapsible>
        )}
      </div>
    );
  }

  if (queryType === "ip") {
    const net = data.network || {};
    return (
      <div className="space-y-4">
        <ResultHeaderRow
          label={data.query ?? ""}
          subtitle={(
            <>
              {net.orgName ? `Owned by ${net.orgName}` : "Unknown"}
              {net.country && <span className="ml-2">· {net.country}</span>}
            </>
          )}
          badge={{ text: "IP", color: "#a855f7" }}
        />
        <IssuesList issues={data.issues} />
        <Collapsible title="Network Details" defaultOpen>
          <div className="pt-3 space-y-0.5">
            <KV label="Network Name" value={net.netName} />
            <KV label="Net Range" value={net.netRange} mono />
            <KV label="CIDR" value={net.cidr} mono />
            <KV label="Organization" value={net.orgName} />
            <KV label="Country" value={net.country} />
          </div>
        </Collapsible>
        {data.rawWhois && (
          <Collapsible title="Raw WHOIS">
            <pre className="pt-3 text-xs font-mono text-muted-foreground whitespace-pre-wrap max-h-64 overflow-y-auto">{data.rawWhois}</pre>
          </Collapsible>
        )}
      </div>
    );
  }

  if (queryType === "asn") {
    const asn = data.asn || {};
    return (
      <div className="space-y-4">
        <ResultHeaderRow
          label={data.query ?? ""}
          badge={{ text: "ASN", color: "#f59e0b" }}
        />
        <Collapsible title="ASN Details" defaultOpen>
          <div className="pt-3 space-y-0.5">
            <KV label="AS Number" value={asn.number} mono />
            <KV label="AS Name" value={asn.name} />
            <KV label="Organization" value={asn.orgName} />
            <KV label="Country" value={asn.country} />
          </div>
        </Collapsible>
      </div>
    );
  }

  return <pre className="text-xs font-mono text-muted-foreground">{JSON.stringify(data, null, 2)}</pre>;
}
