"use client";

import React from "react";
import { Search } from "lucide-react";
import {
  Collapsible, IssuesList, KV, ResultHeaderRow, SendTo, type Issue,
} from "./_shared";

// Loose interface — backend response shape isn't formally specified
// anywhere we share with the frontend. Keep fields optional and
// permissive so a backend tweak doesn't crash the renderer.
export interface CertLookupResponse {
  domain?: string;
  grade?: string | null;
  issues?: Issue[];
  certificate?: {
    subjectCn?: string;
    issuer?: string;
    sans?: string[];
    notBefore?: string;
    notAfter?: string;
    daysUntilExpiry?: number;
    tlsVersion?: string;
    cipherSuite?: string;
    keySize?: number;
    isSelfSigned?: boolean;
    isWildcard?: boolean;
    chainValid?: boolean;
    hostnameMatch?: boolean;
    fingerprintSha256?: string;
  };
  ctLogCertificates?: Array<{
    commonName?: string;
    issuerName?: string;
    notBefore?: string;
    notAfter?: string;
  }>;
  ctLogCount?: number;
  // Hash-mode response shape (set when totalFound or coveredDomains
  // are present)
  totalFound?: number;
  hash?: string;
  coveredDomains?: string[];
  certificates?: Array<{
    commonName?: string;
    issuerName?: string;
    notBefore?: string;
    notAfter?: string;
    isExpired?: boolean;
  }>;
}

export function CertResult({ data }: { data: CertLookupResponse }) {
  const isHashResult = data.totalFound !== undefined || data.coveredDomains !== undefined;

  if (isHashResult) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg flex items-center justify-center bg-teal-500/10">
            <Search className="w-4 h-4 text-teal-400" />
          </div>
          <div>
            <div className="text-sm font-medium text-foreground">
              Found <span className="font-semibold text-teal-400">{data.totalFound || 0}</span> certificate(s)
            </div>
            <div className="text-xs text-muted-foreground font-mono mt-0.5">{data.hash || ""}</div>
          </div>
        </div>
        {data.coveredDomains?.length ? (
          <Collapsible title={`Covered Domains (${data.coveredDomains.length})`} defaultOpen>
            <div className="pt-3 flex flex-wrap gap-1.5">
              {data.coveredDomains.map((d) => (
                <span key={d} className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-mono bg-card/50 border border-border text-foreground">
                  {d}
                  <SendTo value={d} kind="domain" />
                </span>
              ))}
            </div>
          </Collapsible>
        ) : null}
        {data.certificates?.length ? (
          <Collapsible title={`Certificates (${data.certificates.length})`} defaultOpen>
            <div className="pt-3 space-y-2 max-h-80 overflow-y-auto">
              {data.certificates.map((ct, i) => (
                <div key={i} className="text-xs p-2 rounded border border-border bg-background/30">
                  <div className="font-mono text-foreground">{ct.commonName}</div>
                  <div className="text-muted-foreground mt-0.5">
                    {ct.issuerName} · {ct.notBefore} → {ct.notAfter}
                    {ct.isExpired && <span className="text-red-400 ml-1">(expired)</span>}
                  </div>
                </div>
              ))}
            </div>
          </Collapsible>
        ) : null}
      </div>
    );
  }

  const cert = data.certificate;
  return (
    <div className="space-y-4">
      <ResultHeaderRow
        grade={data.grade}
        label={data.domain ?? "Unknown"}
        subtitle={cert ? `Issued by ${cert.issuer}` : "No certificate found"}
      />
      <IssuesList issues={data.issues} />
      {cert && (
        <Collapsible title="Certificate Details">
          <div className="pt-3 space-y-0.5">
            <KV label="Subject CN" value={cert.subjectCn} mono />
            <KV label="Issuer" value={cert.issuer} />
            <KV label="SANs" value={cert.sans?.join(", ")} mono />
            <KV label="Not Before" value={cert.notBefore} />
            <KV label="Not After" value={cert.notAfter} />
            <KV label="Days Until Expiry" value={cert.daysUntilExpiry} />
            <KV label="TLS Version" value={cert.tlsVersion} />
            <KV label="Cipher Suite" value={cert.cipherSuite} mono />
            <KV label="Key Size" value={cert.keySize ? `${cert.keySize} bits` : null} />
            <KV label="Self-Signed" value={cert.isSelfSigned} />
            <KV label="Wildcard" value={cert.isWildcard} />
            <KV label="Chain Valid" value={cert.chainValid} />
            <KV label="Hostname Match" value={cert.hostnameMatch} />
            <KV label="SHA-256" value={cert.fingerprintSha256} mono />
          </div>
        </Collapsible>
      )}
      {data.ctLogCertificates?.length ? (
        <Collapsible title={`CT Log History (${data.ctLogCount ?? data.ctLogCertificates.length} certificates)`}>
          <div className="pt-3 space-y-2 max-h-80 overflow-y-auto">
            {data.ctLogCertificates.slice(0, 20).map((ct, i) => (
              <div key={i} className="text-xs p-2 rounded border border-border bg-background/30">
                <div className="font-mono text-foreground">{ct.commonName}</div>
                <div className="text-muted-foreground mt-0.5">
                  {ct.issuerName} · {ct.notBefore} → {ct.notAfter}
                </div>
              </div>
            ))}
          </div>
        </Collapsible>
      ) : null}
    </div>
  );
}
