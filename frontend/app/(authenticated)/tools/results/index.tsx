"use client";

import React from "react";
import { CertResult } from "./cert";
import { DNSResult } from "./dns";
import { ReverseDNSResult } from "./reverse-dns";
import { HeaderResult } from "./header";
import { WhoisResult } from "./whois";
import { ConnectivityResult } from "./connectivity";
import { EmailSecurityResult } from "./email-security";
import { SensitivePathsResult } from "./sensitive-paths";
import { GitHubLeaksResult } from "./github-leaks";
import { ResultErrorBanner } from "./_shared";

// Tool ids must match the backend tool route names — kept in sync with
// the TOOLS list in tools/page.tsx. If you add a tool, add a renderer
// here too.
export type ToolId =
  | "cert-lookup"
  | "dns-lookup"
  | "reverse-dns"
  | "header-check"
  | "whois"
  | "connectivity-check"
  | "email-security"
  | "sensitive-paths"
  | "github-leaks";

export function RichResultView({
  toolId, data,
}: {
  toolId: ToolId;
  data: any;
}) {
  // Backends sometimes return `{ error: "..." }` in the 200 body
  // (rate-limited Shodan, GitHub no-token, etc.). Surface that as
  // a user-friendly banner before dispatching to the tool renderer.
  if (data?.error) return <ResultErrorBanner error={data.error} />;

  switch (toolId) {
    case "cert-lookup":         return <CertResult data={data} />;
    case "dns-lookup":          return <DNSResult data={data} />;
    case "reverse-dns":         return <ReverseDNSResult data={data} />;
    case "header-check":        return <HeaderResult data={data} />;
    case "whois":               return <WhoisResult data={data} />;
    case "connectivity-check":  return <ConnectivityResult data={data} />;
    case "email-security":      return <EmailSecurityResult data={data} />;
    case "sensitive-paths":     return <SensitivePathsResult data={data} />;
    case "github-leaks":        return <GitHubLeaksResult data={data} />;
    default:
      return <pre className="text-xs font-mono text-muted-foreground">{JSON.stringify(data, null, 2)}</pre>;
  }
}

export type {
  CertLookupResponse,
} from "./cert";
export type { DNSLookupResponse } from "./dns";
export type { ReverseDNSResponse } from "./reverse-dns";
export type { HeaderCheckResponse } from "./header";
export type { WhoisResponse } from "./whois";
export type { ConnectivityResponse } from "./connectivity";
export type { EmailSecurityResponse } from "./email-security";
export type { SensitivePathsResponse } from "./sensitive-paths";
export type { GitHubLeaksResponse } from "./github-leaks";
