// app/(authenticated)/tools/page.tsx
// BoltEdge Security Tools — SecToolKit-style investigation workspace
// Resizable panels · flex-wrap canvas · maximize/expand · JSON/CSV export
"use client";

import React, { useState, useCallback, useRef } from "react";
import {
  Lock, Globe, Shield, FileText, Search, RefreshCcw,
  Loader2, AlertTriangle, CheckCircle2,
  Info, ChevronDown, ChevronUp, Zap, Plug, Mail,
  FolderSearch, GitBranch, ExternalLink, X, Plus,
  Play, Target, RotateCcw, Copy, Download,
  Maximize2, Minimize2, AlertCircle, LayoutGrid, Server, GripVertical,
} from "lucide-react";

import { apiFetch } from "../../lib/api";

function cn(...c: Array<string | false | null | undefined>) { return c.filter(Boolean).join(" "); }

/* ═══════════════════════════════════════════════════════════════
   TOOL DEFINITIONS
   ═══════════════════════════════════════════════════════════════ */

type ToolId = "cert-lookup" | "dns-lookup" | "reverse-dns" | "header-check" | "whois" | "connectivity-check" | "email-security" | "sensitive-paths" | "github-leaks";

interface ToolDef {
  id: ToolId;
  name: string;
  description: string;
  icon: React.ReactNode;
  inputPlaceholder: string;
  inputField: string;
  accepts: string[];
  color: string;
  iconBg: string;
  category: string;
}

const TOOLS: ToolDef[] = [
  { id: "cert-lookup", name: "Certificate Lookup", description: "SSL/TLS certs by domain or SHA-256", icon: <Lock className="w-4 h-4" />, inputPlaceholder: "example.com or AB:CD:EF:12:34...", inputField: "query", accepts: ["Domain", "SHA-256"], color: "text-emerald-400", iconBg: "bg-emerald-500/10", category: "Discovery" },
  { id: "dns-lookup", name: "DNS Lookup", description: "All DNS record types + security analysis", icon: <Globe className="w-4 h-4" />, inputPlaceholder: "example.com", inputField: "domain", accepts: ["Domain"], color: "text-cyan-400", iconBg: "bg-cyan-500/10", category: "Discovery" },
  { id: "reverse-dns", name: "Reverse DNS", description: "IP → hostname with forward verification", icon: <RefreshCcw className="w-4 h-4" />, inputPlaceholder: "8.8.8.8", inputField: "ip", accepts: ["IPv4", "IPv6"], color: "text-purple-400", iconBg: "bg-purple-500/10", category: "Discovery" },
  { id: "header-check", name: "Header Check", description: "HTTP security headers & config", icon: <Shield className="w-4 h-4" />, inputPlaceholder: "example.com", inputField: "domain", accepts: ["Domain"], color: "text-amber-400", iconBg: "bg-amber-500/10", category: "Analysis" },
  { id: "whois", name: "WHOIS Lookup", description: "Registration & ownership details", icon: <FileText className="w-4 h-4" />, inputPlaceholder: "example.com / 8.8.8.8 / AS13335", inputField: "query", accepts: ["Domain", "IPv4", "ASN"], color: "text-rose-400", iconBg: "bg-rose-500/10", category: "Discovery" },
  { id: "connectivity-check", name: "Connectivity Check", description: "TCP ports, banner grab, TLS detect", icon: <Plug className="w-4 h-4" />, inputPlaceholder: "example.com:443", inputField: "host", accepts: ["Domain", "Host:Port"], color: "text-sky-400", iconBg: "bg-sky-500/10", category: "Analysis" },
  { id: "email-security", name: "Email Security", description: "SPF, DKIM & DMARC validation", icon: <Mail className="w-4 h-4" />, inputPlaceholder: "example.com", inputField: "domain", accepts: ["Domain"], color: "text-indigo-400", iconBg: "bg-indigo-500/10", category: "Analysis" },
  { id: "sensitive-paths", name: "Exposed Paths", description: "Scan for .env, .git, SQL dumps", icon: <FolderSearch className="w-4 h-4" />, inputPlaceholder: "example.com", inputField: "domain", accepts: ["Domain"], color: "text-orange-400", iconBg: "bg-orange-500/10", category: "Recon" },
  { id: "github-leaks", name: "GitHub Leaks", description: "Leaked creds & API keys on GitHub", icon: <GitBranch className="w-4 h-4" />, inputPlaceholder: "example.com", inputField: "domain", accepts: ["Domain"], color: "text-pink-400", iconBg: "bg-pink-500/10", category: "Recon" },
];

const TOOL_MAP: Record<string, ToolDef> = Object.fromEntries(TOOLS.map((t) => [t.id, t]));
const CATEGORIES = ["Discovery", "Analysis", "Recon"] as const;
const CAT_COLORS: Record<string, string> = { Discovery: "#22d3ee", Analysis: "#f59e0b", Recon: "#f43f5e" };

function isSha256Hash(input: string): boolean {
  return /^[a-f0-9]{64}$/i.test(input.replace(/[:\s-]/g, ""));
}

/* ═══════════════════════════════════════════════════════════════
   SHARED UI
   ═══════════════════════════════════════════════════════════════ */

const SEV_BORDER: Record<string, string> = { critical: "border-l-red-500", high: "border-l-orange-500", medium: "border-l-yellow-500", low: "border-l-blue-500", info: "border-l-emerald-500" };

function SevIcon({ severity }: { severity: string }) {
  switch (severity) {
    case "critical": case "high": return <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />;
    case "medium": return <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" />;
    case "low": return <Info className="w-4 h-4 text-blue-400 shrink-0" />;
    default: return <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />;
  }
}

function GradeBadge({ grade }: { grade: string | null | undefined }) {
  if (!grade) return null;
  const g = grade.replace(/[+-]/g, "");
  const colors: Record<string, string> = { A: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30", B: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30", C: "bg-orange-500/15 text-orange-400 border-orange-500/30", D: "bg-red-500/15 text-red-400 border-red-500/30", F: "bg-red-500/20 text-red-300 border-red-500/40" };
  return <span className={cn("inline-flex items-center px-3 py-1.5 rounded-lg text-lg font-bold border", colors[g] || colors.F)}>{grade}</span>;
}

function Collapsible({ title, defaultOpen, children }: { title: string; defaultOpen?: boolean; children: React.ReactNode }) {
  const [open, setOpen] = useState(defaultOpen ?? false);
  return (
    <div className="rounded-xl border border-border bg-card/30 overflow-hidden">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium text-foreground hover:bg-card/50 transition-colors">
        {title}
        {open ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
      </button>
      {open && <div className="px-4 pb-4 border-t border-border">{children}</div>}
    </div>
  );
}

function IssuesList({ issues }: { issues: any[] }) {
  if (!issues?.length) return null;
  return (
    <div className="space-y-2">
      {issues.map((issue: any, i: number) => (
        <div key={i} className={cn("flex items-start gap-3 p-3 rounded-lg border-l-2 bg-card/30 border border-border", SEV_BORDER[issue.severity] || SEV_BORDER.info)}>
          <SevIcon severity={issue.severity} />
          <div className="min-w-0">
            <div className="text-sm font-medium text-foreground">{issue.title}</div>
            <div className="text-xs text-muted-foreground mt-0.5">{issue.description}</div>
            {issue.recommendation && <div className="text-xs text-primary mt-1">{issue.recommendation}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}

function KV({ label, value, mono }: { label: string; value: any; mono?: boolean }) {
  if (value === null || value === undefined || value === "") return null;
  const display = typeof value === "boolean" ? (value ? "Yes" : "No") : String(value);
  return (
    <div className="flex items-start gap-2 py-1.5">
      <span className="text-xs text-muted-foreground w-36 shrink-0">{label}</span>
      <span className={cn("text-xs text-foreground break-all", mono && "font-mono")}>{display}</span>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   RESULT RENDERERS (all 9 preserved exactly)
   ═══════════════════════════════════════════════════════════════ */

function CertResult({ data }: { data: any }) {
  const isHashResult = data.totalFound !== undefined || data.coveredDomains !== undefined;
  if (isHashResult) {
    return (<div className="space-y-4">
      <div className="flex items-center gap-3"><div className="h-9 w-9 rounded-lg flex items-center justify-center bg-teal-500/10"><Search className="w-4 h-4 text-teal-400" /></div><div><div className="text-sm font-medium text-foreground">Found <span className="font-semibold text-teal-400">{data.totalFound || 0}</span> certificate(s)</div><div className="text-xs text-muted-foreground font-mono mt-0.5">{data.hash || ""}</div></div></div>
      {data.coveredDomains?.length > 0 && <Collapsible title={`Covered Domains (${data.coveredDomains.length})`} defaultOpen><div className="pt-3 flex flex-wrap gap-1.5">{data.coveredDomains.map((d: string) => <span key={d} className="px-2 py-1 rounded text-xs font-mono bg-card/50 border border-border text-foreground">{d}</span>)}</div></Collapsible>}
      {data.certificates?.length > 0 && <Collapsible title={`Certificates (${data.certificates.length})`} defaultOpen><div className="pt-3 space-y-2 max-h-80 overflow-y-auto">{data.certificates.map((ct: any, i: number) => <div key={i} className="text-xs p-2 rounded border border-border bg-background/30"><div className="font-mono text-foreground">{ct.commonName}</div><div className="text-muted-foreground mt-0.5">{ct.issuerName} · {ct.notBefore} → {ct.notAfter}{ct.isExpired && <span className="text-red-400 ml-1">(expired)</span>}</div></div>)}</div></Collapsible>}
    </div>);
  }
  const cert = data.certificate;
  return (<div className="space-y-4">
    <div className="flex items-center gap-4"><GradeBadge grade={data.grade} /><div><div className="text-sm font-medium text-foreground">{data.domain}</div><div className="text-xs text-muted-foreground">{cert ? `Issued by ${cert.issuer}` : "No certificate found"}</div></div></div>
    <IssuesList issues={data.issues} />
    {cert && <Collapsible title="Certificate Details"><div className="pt-3 space-y-0.5"><KV label="Subject CN" value={cert.subjectCn} mono /><KV label="Issuer" value={cert.issuer} /><KV label="SANs" value={cert.sans?.join(", ")} mono /><KV label="Not Before" value={cert.notBefore} /><KV label="Not After" value={cert.notAfter} /><KV label="Days Until Expiry" value={cert.daysUntilExpiry} /><KV label="TLS Version" value={cert.tlsVersion} /><KV label="Cipher Suite" value={cert.cipherSuite} mono /><KV label="Key Size" value={cert.keySize ? `${cert.keySize} bits` : null} /><KV label="Self-Signed" value={cert.isSelfSigned} /><KV label="Wildcard" value={cert.isWildcard} /><KV label="Chain Valid" value={cert.chainValid} /><KV label="Hostname Match" value={cert.hostnameMatch} /><KV label="SHA-256" value={cert.fingerprintSha256} mono /></div></Collapsible>}
    {data.ctLogCertificates?.length > 0 && <Collapsible title={`CT Log History (${data.ctLogCount} certificates)`}><div className="pt-3 space-y-2 max-h-80 overflow-y-auto">{data.ctLogCertificates.slice(0, 20).map((ct: any, i: number) => <div key={i} className="text-xs p-2 rounded border border-border bg-background/30"><div className="font-mono text-foreground">{ct.commonName}</div><div className="text-muted-foreground mt-0.5">{ct.issuerName} · {ct.notBefore} → {ct.notAfter}</div></div>)}</div></Collapsible>}
  </div>);
}

function DNSResult({ data }: { data: any }) {
  const records = data.records || {};
  return (<div className="space-y-4">
    <div className="flex items-center gap-4"><GradeBadge grade={data.grade} /><div><div className="text-sm font-medium text-foreground">{data.domain}</div><div className="text-xs text-muted-foreground">{data.resolvedIps?.length ? `Resolves to ${data.resolvedIps.join(", ")}` : "No A records"}</div></div></div>
    <IssuesList issues={data.issues} />
    {Object.keys(records).length > 0 && <Collapsible title="DNS Records" defaultOpen><div className="pt-3 space-y-3">{Object.entries(records).map(([type, recs]: [string, any]) => <div key={type}><div className="text-xs font-semibold text-primary mb-1">{type} Records</div><div className="space-y-1">{(recs as any[]).map((r: any, i: number) => <div key={i} className="text-xs font-mono p-2 rounded bg-background/30 border border-border text-foreground">{r.priority !== undefined && <span className="text-muted-foreground mr-2">{r.priority}</span>}{r.value}<span className="text-muted-foreground ml-2">TTL: {r.ttl}</span></div>)}</div></div>)}</div></Collapsible>}
    {data.dkim && <Collapsible title={`DKIM (${data.dkim.found ? data.dkim.selectors?.length + " found" : "not found"})`}><div className="pt-3">{data.dkim.selectors?.map((s: any) => <div key={s.selector} className="text-xs p-2 rounded border border-border bg-background/30 mb-1"><span className="font-semibold text-foreground">{s.selector}</span><span className="text-muted-foreground ml-2">{s.record}</span></div>)}{!data.dkim.found && <div className="text-xs text-muted-foreground">No DKIM selectors found.</div>}</div></Collapsible>}
  </div>);
}

function ReverseDNSResult({ data }: { data: any }) {
  return (<div className="space-y-4">
    <div><div className="text-sm font-medium text-foreground">{data.ip}</div><div className="text-xs text-muted-foreground">{data.hostnames?.length ? `→ ${data.hostnames.join(", ")}` : "No PTR records"}</div></div>
    <IssuesList issues={data.issues} />
    {data.ptrRecords?.length > 0 && <Collapsible title="PTR Records" defaultOpen><div className="pt-3 space-y-1">{data.ptrRecords.map((r: any, i: number) => <div key={i} className="text-xs font-mono p-2 rounded bg-background/30 border border-border text-foreground">{r.hostname} {r.ttl !== null && <span className="text-muted-foreground ml-2">TTL: {r.ttl}</span>}</div>)}</div></Collapsible>}
    {data.forwardConfirmation?.length > 0 && <Collapsible title="Forward Confirmation"><div className="pt-3 space-y-1">{data.forwardConfirmation.map((fc: any, i: number) => <div key={i} className={cn("text-xs p-2 rounded border bg-background/30", fc.confirmed ? "border-emerald-500/30" : "border-red-500/30")}><span className="font-mono text-foreground">{fc.hostname}</span><span className="ml-2">→ {fc.forwardIps?.join(", ") || "no IPs"}</span><span className={cn("ml-2 font-semibold", fc.confirmed ? "text-emerald-400" : "text-red-400")}>{fc.confirmed ? "✓ Confirmed" : "✗ Mismatch"}</span></div>)}</div></Collapsible>}
    {data.infrastructure?.length > 0 && <Collapsible title="Infrastructure Indicators"><div className="pt-3 space-y-1">{data.infrastructure.map((inf: any, i: number) => <div key={i} className="text-xs p-2 rounded border border-border bg-background/30"><span className="text-foreground font-mono">{inf.hostname}</span><span className="text-primary ml-2">{inf.type}</span></div>)}</div></Collapsible>}
  </div>);
}

function HeaderResult({ data }: { data: any }) {
  const summary = data.headerSummary || {};
  return (<div className="space-y-4">
    <div className="flex items-center gap-4"><GradeBadge grade={data.grade} /><div><div className="text-sm font-medium text-foreground">{data.domain}</div><div className="text-xs text-muted-foreground">{data.https ? `HTTPS: ${data.https.statusCode}` : "HTTPS unavailable"}{data.httpRedirectsToHttps !== undefined && <span className={cn("ml-2", data.httpRedirectsToHttps ? "text-emerald-400" : "text-red-400")}>{data.httpRedirectsToHttps ? "· HTTP → HTTPS ✓" : "· No HTTP redirect"}</span>}</div></div></div>
    {Object.keys(summary).length > 0 && <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">{Object.entries(summary).map(([alias, info]: [string, any]) => <div key={alias} className={cn("flex items-center gap-2 px-3 py-2 rounded-lg border text-xs", info.present ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-400" : "border-red-500/20 bg-red-500/5 text-red-400")}>{info.present ? <CheckCircle2 className="w-3.5 h-3.5 shrink-0" /> : <AlertTriangle className="w-3.5 h-3.5 shrink-0" />}<span className="font-semibold">{alias}</span></div>)}</div>}
    <IssuesList issues={data.issues} />
    {data.https?.headers && <Collapsible title="Raw Headers"><div className="pt-3 space-y-0.5 max-h-64 overflow-y-auto">{Object.entries(data.https.headers).map(([k, v]: [string, any]) => <div key={k} className="text-xs font-mono"><span className="text-primary">{k}:</span> <span className="text-foreground break-all">{v}</span></div>)}</div></Collapsible>}
  </div>);
}

function WhoisResult({ data }: { data: any }) {
  const queryType = data.queryType || "domain";
  if (queryType === "domain") {
    const reg = data.registration || {};
    return (<div className="space-y-4">
      <div><div className="flex items-center gap-2"><span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-primary/10 text-primary border border-primary/20">DOMAIN</span><span className="text-sm font-medium text-foreground">{data.query}</span></div><div className="text-xs text-muted-foreground mt-1">{reg.registrar ? `Registered with ${reg.registrar}` : "Registrar unknown"}{reg.daysUntilExpiry !== undefined && <span className={cn("ml-2", reg.daysUntilExpiry <= 30 ? "text-red-400" : "text-muted-foreground")}>· Expires in {reg.daysUntilExpiry} days</span>}</div></div>
      <IssuesList issues={data.issues} />
      <Collapsible title="Registration Details" defaultOpen><div className="pt-3 space-y-0.5"><KV label="Registrar" value={reg.registrar} /><KV label="Created" value={reg.creationDate} /><KV label="Expires" value={reg.expiryDate} /><KV label="Updated" value={reg.updatedDate} /><KV label="Domain Age" value={reg.domainAgeDays ? `${reg.domainAgeDays} days` : null} /><KV label="Registrant Org" value={reg.registrantOrg} /><KV label="DNSSEC" value={reg.dnssec} /></div></Collapsible>
      {reg.nameservers?.length > 0 && <Collapsible title={`Nameservers (${reg.nameservers.length})`}><div className="pt-3 space-y-1">{reg.nameservers.map((ns: string) => <div key={ns} className="text-xs font-mono p-2 rounded bg-background/30 border border-border text-foreground">{ns}</div>)}</div></Collapsible>}
      {data.rawWhois && <Collapsible title="Raw WHOIS"><pre className="pt-3 text-xs font-mono text-muted-foreground whitespace-pre-wrap max-h-64 overflow-y-auto">{data.rawWhois}</pre></Collapsible>}
    </div>);
  }
  if (queryType === "ip") {
    const net = data.network || {};
    return (<div className="space-y-4"><div><div className="flex items-center gap-2"><span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-purple-500/10 text-purple-400 border border-purple-500/20">IP</span><span className="text-sm font-medium text-foreground">{data.query}</span></div><div className="text-xs text-muted-foreground mt-1">{net.orgName ? `Owned by ${net.orgName}` : "Unknown"}{net.country && <span className="ml-2">· {net.country}</span>}</div></div><IssuesList issues={data.issues} /><Collapsible title="Network Details" defaultOpen><div className="pt-3 space-y-0.5"><KV label="Network Name" value={net.netName} /><KV label="Net Range" value={net.netRange} mono /><KV label="CIDR" value={net.cidr} mono /><KV label="Organization" value={net.orgName} /><KV label="Country" value={net.country} /></div></Collapsible>{data.rawWhois && <Collapsible title="Raw WHOIS"><pre className="pt-3 text-xs font-mono text-muted-foreground whitespace-pre-wrap max-h-64 overflow-y-auto">{data.rawWhois}</pre></Collapsible>}</div>);
  }
  if (queryType === "asn") {
    const asn = data.asn || {};
    return (<div className="space-y-4"><div><div className="flex items-center gap-2"><span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">ASN</span><span className="text-sm font-medium text-foreground">{data.query}</span></div></div><Collapsible title="ASN Details" defaultOpen><div className="pt-3 space-y-0.5"><KV label="AS Number" value={asn.number} mono /><KV label="AS Name" value={asn.name} /><KV label="Organization" value={asn.orgName} /><KV label="Country" value={asn.country} /></div></Collapsible></div>);
  }
  return <pre className="text-xs font-mono text-muted-foreground">{JSON.stringify(data, null, 2)}</pre>;
}

function ConnectivityResult({ data }: { data: any }) {
  const single = data.result; const ports = data.ports;
  return (<div className="space-y-4">
    <div><div className="flex items-center gap-2"><span className="text-sm font-medium text-foreground font-mono">{data.host}</span>{data.resolvedIp && data.resolvedIp !== data.host && <span className="text-xs text-muted-foreground">→ {data.resolvedIp}</span>}</div>{data.port && <div className="text-xs text-muted-foreground mt-0.5">Port {data.port}{single?.reachable ? <span className="text-emerald-400 ml-2">· Reachable ({single.latencyMs}ms)</span> : <span className="text-red-400 ml-2">· Not reachable</span>}</div>}{!data.port && ports && <div className="text-xs text-muted-foreground mt-0.5">Scanned {data.totalChecked} ports · <span className="text-emerald-400">{data.openPorts} open</span> · {data.closedPorts} closed</div>}</div>
    <IssuesList issues={data.issues} />
    {single && <Collapsible title="Connection Details" defaultOpen><div className="pt-3 space-y-0.5"><KV label="Reachable" value={single.reachable} /><KV label="Latency" value={single.latencyMs ? `${single.latencyMs}ms` : null} /><KV label="Service" value={single.service} /><KV label="Banner" value={single.banner} mono />{single.tls && <><KV label="TLS Version" value={single.tls.version} /><KV label="Cipher" value={single.tls.cipher} mono /></>}</div></Collapsible>}
    {ports && <Collapsible title={`Port Results (${ports.length})`} defaultOpen><div className="pt-3 grid grid-cols-1 gap-1.5">{ports.map((p: any) => <div key={p.port} className={cn("flex items-center gap-3 px-3 py-2.5 rounded-lg border text-xs", p.reachable ? "border-emerald-500/20 bg-emerald-500/5" : "border-border bg-card/20")}><div className={cn("w-2 h-2 rounded-full shrink-0", p.reachable ? "bg-emerald-400" : "bg-muted-foreground/30")} /><span className="font-mono font-semibold text-foreground w-14">{p.port}</span><span className="text-muted-foreground w-20">{p.expectedService || ""}</span>{p.reachable ? <><span className="text-emerald-400 font-medium">Open</span><span className="text-muted-foreground ml-auto">{p.latencyMs}ms</span></> : <span className="text-muted-foreground">{p.error?.includes("refused") ? "Closed" : "Filtered"}</span>}</div>)}</div></Collapsible>}
  </div>);
}

function ProtocolBadge({ label, found, detail }: { label: string; found: boolean; detail?: string }) {
  return (<div className={cn("flex items-center gap-2.5 px-4 py-3 rounded-xl border", found ? "border-emerald-500/20 bg-emerald-500/5" : "border-red-500/20 bg-red-500/5")}>{found ? <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" /> : <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />}<div><div className={cn("text-sm font-semibold", found ? "text-emerald-400" : "text-red-400")}>{label}</div>{detail && <div className="text-[11px] text-muted-foreground mt-0.5">{detail}</div>}</div></div>);
}

function EmailSecurityResult({ data }: { data: any }) {
  const spf = data.spf || {}; const dkim = data.dkim || {}; const dmarc = data.dmarc || {};
  const spfDetail = spf.found ? `${spf.allQualifier === "-" ? "Hard fail" : spf.allQualifier === "~" ? "Soft fail" : "Other"} · ${spf.lookupCount} lookups` : undefined;
  const dkimDetail = dkim.found ? `${dkim.selectorCount} selector${dkim.selectorCount !== 1 ? "s" : ""}` : undefined;
  const dmarcDetail = dmarc.found ? `Policy: ${dmarc.policy || "none"}` : undefined;
  return (<div className="space-y-4">
    <div className="flex items-center gap-4"><GradeBadge grade={data.grade} /><div><div className="text-sm font-medium text-foreground">{data.domain}</div><div className="text-xs text-muted-foreground">Email authentication assessment</div></div></div>
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5"><ProtocolBadge label="SPF" found={spf.found} detail={spfDetail} /><ProtocolBadge label="DKIM" found={dkim.found} detail={dkimDetail} /><ProtocolBadge label="DMARC" found={dmarc.found} detail={dmarcDetail} /></div>
    <IssuesList issues={data.issues} />
    {spf.found && <Collapsible title="SPF Record" defaultOpen><div className="pt-3 space-y-2"><div className="text-xs font-mono p-2.5 rounded-lg bg-background/30 border border-border text-foreground break-all">{spf.record}</div><KV label="DNS Lookups" value={`${spf.lookupCount} / 10`} />{spf.mechanisms?.length > 0 && <div className="flex flex-wrap gap-1.5">{spf.mechanisms.map((m: any, i: number) => <span key={i} className="px-2 py-1 rounded text-xs font-mono bg-card/50 border border-border text-foreground">{m.qualifier !== "+" && <span className="text-muted-foreground">{m.qualifier}</span>}{m.mechanism}</span>)}</div>}</div></Collapsible>}
    {dkim.selectors?.length > 0 && <Collapsible title={`DKIM Selectors (${dkim.selectors.length})`}><div className="pt-3 space-y-2">{dkim.selectors.map((s: any) => <div key={s.selector} className="p-2.5 rounded-lg border border-border bg-background/30"><div className="flex items-center gap-2 mb-1"><span className="text-xs font-semibold text-foreground">{s.selector}</span>{s.valid ? <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Valid</span> : <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-500/10 text-red-400 border border-red-500/20">Invalid</span>}</div><div className="text-[11px] font-mono text-muted-foreground break-all">{s.record}</div></div>)}</div></Collapsible>}
    {dmarc.found && <Collapsible title="DMARC Record"><div className="pt-3 space-y-2">{dmarc.record && <div className="text-xs font-mono p-2.5 rounded-lg bg-background/30 border border-border text-foreground break-all">{dmarc.record}</div>}<KV label="Policy" value={dmarc.policy} /><KV label="Subdomain Policy" value={dmarc.subdomainPolicy} /></div></Collapsible>}
  </div>);
}

const PATH_CAT_ICONS: Record<string, { icon: string }> = { source_control: { icon: "🔓" }, secrets: { icon: "🔑" }, config: { icon: "⚙️" }, data_leak: { icon: "💾" }, info_leak: { icon: "ℹ️" }, recon: { icon: "🔍" } };

function SensitivePathsResult({ data }: { data: any }) {
  const findings = data.findings || []; const sevCounts = data.severityCounts || {};
  return (<div className="space-y-4">
    <div><div className="text-sm font-medium text-foreground">{data.domain}</div><div className="text-xs text-muted-foreground">Checked {data.pathsChecked} paths · Found {data.pathsFound} exposed</div></div>
    {data.pathsFound > 0 && <div className="flex gap-2 flex-wrap">{sevCounts.critical > 0 && <span className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/20">{sevCounts.critical} Critical</span>}{sevCounts.high > 0 && <span className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-orange-500/15 text-orange-400 border border-orange-500/20">{sevCounts.high} High</span>}{sevCounts.medium > 0 && <span className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-yellow-500/15 text-yellow-400 border border-yellow-500/20">{sevCounts.medium} Medium</span>}</div>}
    <IssuesList issues={data.issues} />
    {findings.length > 0 && <Collapsible title={`Exposed Paths (${findings.length})`} defaultOpen><div className="pt-3 space-y-2">{findings.map((f: any, i: number) => { const cat = PATH_CAT_ICONS[f.category] || PATH_CAT_ICONS.recon; return (<div key={i} className={cn("p-3 rounded-lg border-l-2 bg-card/30 border border-border", SEV_BORDER[f.severity] || SEV_BORDER.info)}><div className="flex items-center gap-2 mb-1"><span>{cat.icon}</span><span className="text-sm font-medium text-foreground">{f.title}</span><span className="ml-auto px-1.5 py-0.5 rounded text-[10px] font-semibold bg-muted/30 text-muted-foreground border border-border/50">HTTP {f.status}</span>{f.confirmed && <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Confirmed</span>}</div><div className="text-xs font-mono text-primary">{f.path}</div><div className="text-xs text-muted-foreground mt-1">{f.description}</div>{f.snippet && <div className="mt-2 p-2 rounded bg-background/30 border border-border text-xs font-mono text-muted-foreground max-h-20 overflow-y-auto whitespace-pre-wrap">{f.snippet}</div>}</div>); })}</div></Collapsible>}
    {data.pathsFound === 0 && <div className="flex items-center gap-2 p-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5"><CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" /><div className="text-sm text-emerald-400">No exposed sensitive files detected.</div></div>}
  </div>);
}

function GitHubLeaksResult({ data }: { data: any }) {
  const searches = data.searches || []; const dorks = data.dorks || []; const sevCounts = data.severityCounts || {};
  return (<div className="space-y-4">
    <div><div className="text-sm font-medium text-foreground">{data.domain}</div><div className="text-xs text-muted-foreground">{data.searchesCompleted} searches · {data.totalLeaks} leak(s){!data.hasGitHubToken && <span className="text-yellow-400 ml-2">· No GITHUB_TOKEN</span>}{data.rateLimited && <span className="text-red-400 ml-2">· Rate limited</span>}</div></div>
    {data.totalLeaks > 0 && <div className="flex gap-2 flex-wrap">{sevCounts.critical > 0 && <span className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/20">{sevCounts.critical} Critical</span>}{sevCounts.high > 0 && <span className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-orange-500/15 text-orange-400 border border-orange-500/20">{sevCounts.high} High</span>}</div>}
    <IssuesList issues={data.issues} />
    {searches.filter((s: any) => s.totalResults > 0).length > 0 && <Collapsible title={`GitHub Searches (${searches.filter((s: any) => s.totalResults > 0).length} with results)`} defaultOpen><div className="pt-3 space-y-2">{searches.filter((s: any) => s.totalResults > 0).map((s: any, i: number) => <div key={i} className={cn("p-3 rounded-lg border-l-2 bg-card/30 border border-border", SEV_BORDER[s.severity] || SEV_BORDER.info)}><div className="flex items-center gap-2 mb-1"><SevIcon severity={s.severity} /><span className="text-sm font-medium text-foreground">{s.title}</span><span className="ml-auto text-xs font-semibold text-primary">{s.totalResults} result(s)</span></div><div className="text-xs font-mono text-muted-foreground mb-1">{s.query}</div>{s.files?.length > 0 && <div className="space-y-1 mt-2">{s.files.map((f: any, j: number) => <div key={j} className="flex items-center gap-2 p-2 rounded bg-background/30 border border-border text-xs"><GitBranch className="w-3.5 h-3.5 text-muted-foreground shrink-0" /><span className="font-mono text-foreground truncate">{f.repository}</span><span className="text-muted-foreground truncate">/{f.path}</span>{f.htmlUrl && <a href={f.htmlUrl} target="_blank" rel="noopener noreferrer" className="ml-auto shrink-0 text-primary hover:underline"><ExternalLink className="w-3.5 h-3.5" /></a>}</div>)}</div>}</div>)}</div></Collapsible>}
    {dorks.length > 0 && <Collapsible title={`Google Dorks (${dorks.length})`}><div className="pt-3 space-y-2">{dorks.map((d: any, i: number) => <div key={i} className="flex items-center gap-3 p-2.5 rounded-lg border border-border bg-background/30"><Search className="w-3.5 h-3.5 text-muted-foreground shrink-0" /><div className="flex-1 min-w-0"><div className="text-xs font-semibold text-foreground">{d.title}</div><div className="text-[11px] font-mono text-muted-foreground truncate">{d.query}</div></div><a href={d.searchUrl} target="_blank" rel="noopener noreferrer" className="shrink-0 px-2.5 py-1 rounded text-xs font-medium bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20">Search →</a></div>)}</div></Collapsible>}
    {data.totalLeaks === 0 && !data.rateLimited && <div className="flex items-center gap-2 p-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5"><CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" /><div className="text-sm text-emerald-400">No leaked credentials found on GitHub.</div></div>}
  </div>);
}

function RichResultView({ toolId, data }: { toolId: ToolId; data: any }) {
  if (data?.error) return <div className="flex items-center gap-3 p-4 rounded-xl border border-red-500/20 bg-red-500/5"><AlertTriangle className="w-5 h-5 text-red-400 shrink-0" /><div className="text-sm text-red-400">{data.error}</div></div>;
  switch (toolId) {
    case "cert-lookup": return <CertResult data={data} />;
    case "dns-lookup": return <DNSResult data={data} />;
    case "reverse-dns": return <ReverseDNSResult data={data} />;
    case "header-check": return <HeaderResult data={data} />;
    case "whois": return <WhoisResult data={data} />;
    case "connectivity-check": return <ConnectivityResult data={data} />;
    case "email-security": return <EmailSecurityResult data={data} />;
    case "sensitive-paths": return <SensitivePathsResult data={data} />;
    case "github-leaks": return <GitHubLeaksResult data={data} />;
    default: return <pre className="text-xs font-mono text-muted-foreground">{JSON.stringify(data, null, 2)}</pre>;
  }
}

/* ═══════════════════════════════════════════════════════════════
   PANEL STATE & CONSTANTS
   ═══════════════════════════════════════════════════════════════ */

interface PanelState {
  uid: number;
  toolId: ToolId;
  localTarget: string;
  status: "idle" | "running" | "done" | "error";
  result: any;
  error: string | null;
  execMs: number | null;
  expanded: boolean;
  widthPct: number;
  heightPx: number;
}

const GAP = 10;
const MIN_W = 20;
const MAX_W = 100;
const MIN_H = 240;
const MAX_PANELS = 12;

const DEFAULT_TOOLS: ToolId[] = [];

/* ═══════════════════════════════════════════════════════════════
   RESIZABLE TOOL PANEL
   ═══════════════════════════════════════════════════════════════ */

function ToolPanel({
  panel, tool, globalTarget, canvasWidth,
  onRemove, onRun, onToggleExpand, onSetLocalTarget, onResize,
}: {
  panel: PanelState; tool: ToolDef; globalTarget: string; canvasWidth: number;
  onRemove: () => void; onRun: () => void;
  onToggleExpand: () => void; onSetLocalTarget: (v: string) => void;
  onResize: (w: number, h: number) => void;
}) {
  const resizeRef = useRef<{ sx: number; sy: number; ow: number; oh: number } | null>(null);
  const effectiveTarget = panel.localTarget.trim() || globalTarget.trim();
  const isLocal = panel.localTarget.trim().length > 0;
  const isRunning = panel.status === "running";
  const certMode = tool.id === "cert-lookup" && effectiveTarget ? (isSha256Hash(effectiveTarget) ? "SHA-256" : "Domain") : null;

  const handleResizeDown = (e: React.MouseEvent) => {
    e.preventDefault(); e.stopPropagation();
    resizeRef.current = { sx: e.clientX, sy: e.clientY, ow: panel.widthPct, oh: panel.heightPx };
    const onMove = (ev: MouseEvent) => {
      if (!resizeRef.current) return;
      const dxPct = ((ev.clientX - resizeRef.current.sx) / (canvasWidth || 800)) * 100;
      const dy = ev.clientY - resizeRef.current.sy;
      onResize(Math.min(MAX_W, Math.max(MIN_W, resizeRef.current.ow + dxPct)), Math.max(MIN_H, resizeRef.current.oh + dy));
    };
    const onUp = () => { resizeRef.current = null; document.body.style.cursor = ""; document.body.style.userSelect = ""; window.removeEventListener("mousemove", onMove); window.removeEventListener("mouseup", onUp); };
    document.body.style.cursor = "se-resize"; document.body.style.userSelect = "none";
    window.addEventListener("mousemove", onMove); window.addEventListener("mouseup", onUp);
  };

  const handleCopyJson = () => { if (panel.result) navigator.clipboard.writeText(JSON.stringify(panel.result, null, 2)); };
  const handleExportCsv = () => {
    if (!panel.result) return;
    const rows = Object.entries(panel.result).map(([k, v]) => `"${k}","${String(v ?? "").replace(/"/g, '""')}"`);
    const blob = new Blob(["key,value\n" + rows.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `${tool.id}-results.csv`; a.click(); URL.revokeObjectURL(url);
  };

  function renderTitleBar() {
    return (
      <div className="flex items-center gap-2 px-3 py-2 border-b border-white/[0.06] bg-white/[0.02] shrink-0">
        <div className={cn("h-6 w-6 rounded-md flex items-center justify-center shrink-0", tool.iconBg, tool.color)}>{tool.icon}</div>
        <span className="text-[12px] font-semibold text-white truncate flex-1">{tool.name}</span>
        <span className="text-[10px] text-[#475569] font-mono mr-1">{tool.category}</span>
        {panel.execMs !== null && <span className="text-[10px] text-[#475569] font-mono">{panel.execMs}ms</span>}
        <div className="flex items-center gap-0.5">
          <button onClick={onToggleExpand} className="p-1 rounded hover:bg-white/[0.06] text-[#64748b] hover:text-white transition-colors" title={panel.expanded ? "Restore" : "Maximize"}>
            {panel.expanded ? <Minimize2 size={12} /> : <Maximize2 size={12} />}
          </button>
          <button onClick={onRemove} className="p-1 rounded hover:bg-red-500/20 text-[#64748b] hover:text-red-400 transition-colors" title="Remove">
            <X size={12} />
          </button>
        </div>
      </div>
    );
  }

  function renderInputBar() {
    return (
      <>
      <div className="px-3 py-2 border-b border-white/[0.04] flex items-center gap-2 shrink-0">
        <input type="text" value={panel.localTarget}
          onChange={(e) => onSetLocalTarget(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && !isRunning && onRun()}
          placeholder={globalTarget ? `▸ ${globalTarget}` : tool.inputPlaceholder}
          className="flex-1 bg-[#080d1a] border border-white/[0.06] rounded-lg px-3 py-1.5 text-[12px] text-white placeholder-[#3b4559] outline-none focus:border-primary/30 transition-colors font-mono"
          disabled={isRunning} />
        {isLocal && <span className="text-[9px] font-mono uppercase tracking-wider text-primary shrink-0 px-1">local</span>}
        {certMode && <span className="text-[9px] font-mono uppercase tracking-wider text-teal-400 shrink-0 px-1">{certMode}</span>}
        <button onClick={onRun} disabled={isRunning || !effectiveTarget}
          className="flex items-center gap-1 rounded-lg bg-white/[0.04] border border-white/[0.06] px-2.5 py-1.5 text-[11px] font-medium text-white hover:bg-white/[0.08] hover:border-primary/20 transition-all disabled:opacity-30 disabled:cursor-not-allowed shrink-0">
          {isRunning ? <Loader2 size={12} className="animate-spin" /> : <Play size={11} className="text-primary" />}
          Run
        </button>
      </div>
      <div className="px-3 pb-1 flex items-center gap-2 shrink-0">
        <span className="text-[10px] text-muted-foreground/40 truncate">{tool.description}</span>
        <div className="flex gap-1 ml-auto shrink-0">
          {tool.accepts.map((a) => (
            <span key={a} className="px-1.5 py-0.5 rounded text-[9px] font-medium bg-muted/20 text-muted-foreground/50 border border-border/30">{a}</span>
          ))}
        </div>
      </div>
      </>
    );
  }

  function renderBody() {
    return (
      <div className="flex-1 overflow-auto min-h-0 p-3">
        {panel.status === "error" && (
          <div className="rounded-lg border border-red-500/20 bg-red-500/[0.05] px-3 py-2 flex items-start gap-2 mb-3">
            <AlertCircle size={13} className="text-red-400 mt-0.5 shrink-0" />
            <p className="text-[11px] text-red-300 leading-relaxed break-all">{panel.error}</p>
          </div>
        )}
        {panel.status === "done" && panel.result && (
          <div>
            <div className="flex items-center justify-end gap-2 mb-3">
              <button onClick={handleCopyJson} className="flex items-center gap-1 text-[10px] text-[#64748b] hover:text-white transition-colors"><Copy size={10} /> JSON</button>
              <button onClick={handleExportCsv} className="flex items-center gap-1 text-[10px] text-[#64748b] hover:text-white transition-colors"><Download size={10} /> CSV</button>
            </div>
            <RichResultView toolId={panel.toolId} data={panel.result} />
          </div>
        )}
        {panel.status === "running" && (
          <div className="flex flex-col items-center justify-center h-full">
            <Loader2 size={20} className="animate-spin mb-2 text-primary" />
            <span className="text-[11px] text-[#64748b]">Running {tool.name}…</span>
          </div>
        )}
        {panel.status === "idle" && (
          <div className="flex flex-col items-center justify-center h-full opacity-40">
            <div className={cn("h-10 w-10 rounded-xl flex items-center justify-center mb-2", tool.iconBg, tool.color)}>{tool.icon}</div>
            <span className="text-[11px] text-[#64748b]">{effectiveTarget ? "Click Run to query" : tool.inputPlaceholder}</span>
          </div>
        )}
      </div>
    );
  }

  if (panel.expanded) {
    return (<>
      <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm" onClick={onToggleExpand} />
      <div className="fixed inset-4 z-50 rounded-xl border border-white/[0.08] bg-[#0c1222]/98 backdrop-blur-xl shadow-2xl flex flex-col overflow-hidden">
        {renderTitleBar()}{renderInputBar()}{renderBody()}
      </div>
    </>);
  }

  return (
    <div className="rounded-xl border border-white/[0.08] bg-[#0c1222]/95 backdrop-blur-xl shadow-lg flex flex-col overflow-hidden relative group/panel"
      style={{ width: `calc(${panel.widthPct}% - ${GAP * (1 - panel.widthPct / 100)}px)`, height: panel.heightPx, flexShrink: 0, flexGrow: 0 }}>
      {renderTitleBar()}{renderInputBar()}{renderBody()}
      <div onMouseDown={handleResizeDown} className="absolute bottom-0 right-0 w-5 h-5 cursor-se-resize z-10 opacity-0 group-hover/panel:opacity-100 transition-opacity" title="Drag to resize">
        <svg viewBox="0 0 20 20" className="w-full h-full"><path d="M18 18L10 18" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" opacity="0.3" className="text-primary" /><path d="M18 18L18 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" opacity="0.3" className="text-primary" /><path d="M18 18L14 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.7" className="text-primary" /><path d="M18 18L18 14" stroke="currentColor" strokeWidth="2" strokeLinecap="round" opacity="0.7" className="text-primary" /></svg>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   ADD TOOL DROPDOWN
   ═══════════════════════════════════════════════════════════════ */

function AddToolDropdown({ onAdd, disabled }: { onAdd: (toolId: ToolId) => void; disabled: boolean }) {
  const [open, setOpen] = useState(false);
  const [expandedCat, setExpandedCat] = useState<string | null>(null);
  return (
    <div className="relative">
      <button onClick={() => setOpen(!open)} disabled={disabled}
        className="flex items-center gap-1.5 rounded-lg border border-white/[0.06] bg-white/[0.03] px-3 py-2 text-[12px] font-medium text-[#94a3b8] hover:bg-white/[0.06] hover:text-white transition-all disabled:opacity-30 disabled:cursor-not-allowed">
        <Plus size={13} /> Add Tool <ChevronDown size={11} className={cn("transition-transform duration-200", open && "rotate-180")} />
      </button>
      {open && (<>
        <div className="fixed inset-0 z-40" onClick={() => { setOpen(false); setExpandedCat(null); }} />
        <div className="absolute top-full left-0 mt-1 z-50 w-[260px] max-h-[420px] overflow-y-auto rounded-xl border border-white/[0.08] bg-[#0c1222]/98 backdrop-blur-xl shadow-2xl py-1.5">
          {CATEGORIES.map((cat) => {
            const catTools = TOOLS.filter((t) => t.category === cat);
            return (
              <div key={cat}>
                <button onClick={() => setExpandedCat(expandedCat === cat ? null : cat)}
                  className="w-full flex items-center gap-2 px-3 py-2 hover:bg-white/[0.04] transition-colors">
                  <span className="w-2 h-2 rounded-full shrink-0" style={{ background: CAT_COLORS[cat] }} />
                  <span className="text-[12px] font-medium text-[#94a3b8] flex-1 text-left">{cat}</span>
                  <span className="text-[10px] text-[#475569] font-mono">{catTools.length}</span>
                  <ChevronDown size={11} className={cn("text-[#475569] transition-transform duration-200", expandedCat === cat && "rotate-180")} />
                </button>
                {expandedCat === cat && (
                  <div className="pb-1">
                    {catTools.map((tool) => (
                      <button key={tool.id} onClick={() => { onAdd(tool.id); setOpen(false); setExpandedCat(null); }}
                        className="w-full flex items-center gap-2 px-5 py-1.5 text-left hover:bg-white/[0.06] transition-colors group">
                        <div className={cn("h-5 w-5 rounded flex items-center justify-center shrink-0", tool.iconBg, tool.color)}>{tool.icon}</div>
                        <span className="text-[11px] text-[#64748b] group-hover:text-white truncate transition-colors">{tool.name}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </>)}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   MAIN PAGE — INVESTIGATION WORKSPACE
   ═══════════════════════════════════════════════════════════════ */

export default function ToolsPage() {
  const nextUid = useRef(DEFAULT_TOOLS.length + 1);
  const canvasRef = useRef<HTMLDivElement>(null);

  const [panels, setPanels] = useState<PanelState[]>(() => {
    const cols = Math.min(DEFAULT_TOOLS.length, 3);
    return DEFAULT_TOOLS.map((toolId, i) => ({
      uid: i + 1, toolId, localTarget: "", status: "idle" as const,
      result: null, error: null, execMs: null, expanded: false,
      widthPct: 100 / cols, heightPx: 380,
    }));
  });
  const [globalTarget, setGlobalTarget] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [sidebarWidth, setSidebarWidth] = useState(220);
  const [collapsedCats, setCollapsedCats] = useState<Record<string, boolean>>({});
  const sidebarResizeRef = useRef<{ startX: number; startW: number } | null>(null);

  const handleSidebarResizeDown = (e: React.MouseEvent) => {
    e.preventDefault();
    sidebarResizeRef.current = { startX: e.clientX, startW: sidebarWidth };
    const onMove = (ev: MouseEvent) => {
      if (!sidebarResizeRef.current) return;
      const newW = sidebarResizeRef.current.startW + (ev.clientX - sidebarResizeRef.current.startX);
      setSidebarWidth(Math.min(400, Math.max(180, newW)));
    };
    const onUp = () => {
      sidebarResizeRef.current = null;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    document.body.style.cursor = "ew-resize";
    document.body.style.userSelect = "none";
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const addPanel = useCallback((toolId: ToolId) => {
    if (panels.length >= MAX_PANELS) return;
    const cols = Math.min(panels.length + 1, 3);
    setPanels((p) => [...p, {
      uid: nextUid.current++, toolId, localTarget: "", status: "idle",
      result: null, error: null, execMs: null, expanded: false,
      widthPct: 100 / cols, heightPx: 380,
    }]);
  }, [panels.length]);

  const removePanel = useCallback((uid: number) => setPanels((p) => p.filter((x) => x.uid !== uid)), []);
  const toggleExpand = useCallback((uid: number) => setPanels((p) => p.map((x) => x.uid === uid ? { ...x, expanded: !x.expanded } : x)), []);
  const setLocalTarget = useCallback((uid: number, val: string) => setPanels((p) => p.map((x) => x.uid === uid ? { ...x, localTarget: val } : x)), []);
  const resizePanel = useCallback((uid: number, w: number, h: number) => setPanels((p) => p.map((x) => x.uid === uid ? { ...x, widthPct: w, heightPx: h } : x)), []);
  const updatePanel = useCallback((uid: number, patch: Partial<PanelState>) => setPanels((p) => p.map((x) => x.uid === uid ? { ...x, ...patch } : x)), []);

  const runTool = useCallback(async (uid: number) => {
    const panel = panels.find((p) => p.uid === uid);
    if (!panel) return;
    const tool = TOOL_MAP[panel.toolId];
    if (!tool) return;
    const val = (panel.localTarget || globalTarget).trim();
    if (!val) return;

    updatePanel(uid, { status: "running", result: null, error: null, execMs: null });
    const startMs = performance.now();

    try {
      let endpoint = `/tools/${panel.toolId}`;
      let body: Record<string, string> = {};
      if (panel.toolId === "cert-lookup") {
        if (isSha256Hash(val)) { endpoint = "/tools/cert-hash"; body = { hash: val }; }
        else { endpoint = "/tools/cert-lookup"; body = { domain: val }; }
      } else {
        body = { [tool.inputField]: val };
      }
      const res = await apiFetch(endpoint, { method: "POST", body: JSON.stringify(body) });
      const elapsed = Math.round(performance.now() - startMs);
      updatePanel(uid, { status: "done", result: res, execMs: elapsed });
    } catch (e: any) {
      const elapsed = Math.round(performance.now() - startMs);
      updatePanel(uid, { status: "error", error: e?.message || "Request failed", execMs: elapsed });
    }
  }, [panels, globalTarget, updatePanel]);

  const runAll = useCallback(() => {
    for (const p of panels) {
      const val = (p.localTarget || globalTarget).trim();
      if (val && p.status !== "running") runTool(p.uid);
    }
  }, [panels, globalTarget, runTool]);

  const resetToDefaults = useCallback(() => {
    nextUid.current = DEFAULT_TOOLS.length + 1;
    const cols = Math.min(DEFAULT_TOOLS.length, 3);
    setPanels(DEFAULT_TOOLS.map((toolId, i) => ({
      uid: i + 1, toolId, localTarget: "", status: "idle" as const,
      result: null, error: null, execMs: null, expanded: false,
      widthPct: 100 / cols, heightPx: 380,
    })));
  }, []);

  // Sidebar drag → workspace drop
  const handleSidebarDragStart = (e: React.DragEvent, toolId: string) => {
    e.dataTransfer.setData("newToolId", toolId);
    e.dataTransfer.effectAllowed = "copy";
  };

  const handleWorkspaceDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const newToolId = e.dataTransfer.getData("newToolId");
    if (newToolId && TOOL_MAP[newToolId]) addPanel(newToolId as ToolId);
  };

  const toggleCat = (cat: string) => setCollapsedCats((prev) => ({ ...prev, [cat]: !prev[cat] }));

  const canvasWidth = canvasRef.current?.clientWidth ?? 1200;
  const runningCount = panels.filter((p) => p.status === "running").length;

  return (
    <div className="flex-1 flex overflow-hidden bg-background text-foreground">
      {/* ═══ SIDEBAR ═══ */}
      <div className={cn(
        "shrink-0 border-r border-border bg-card/40 transition-all duration-200 flex flex-col relative",
        sidebarOpen ? "" : "w-0 overflow-hidden"
      )} style={sidebarOpen ? { width: sidebarWidth } : undefined}>
        <div className="px-4 py-4 border-b border-border">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-primary" />
            <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider">Tools</span>
          </div>
          <div className="text-[10px] text-muted-foreground/50 mt-1">Drag tools into workspace or click to add</div>
        </div>

        <div className="flex-1 overflow-auto py-2">
          {CATEGORIES.map((cat) => {
            const catTools = TOOLS.filter((t) => t.category === cat);
            const collapsed = collapsedCats[cat];
            return (
              <div key={cat}>
                <button onClick={() => toggleCat(cat)}
                  className="w-full flex items-center justify-between px-4 py-2 text-left hover:bg-accent/20 transition-colors">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ background: CAT_COLORS[cat] }} />
                    <span className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">{cat}</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] text-muted-foreground/40">{catTools.length}</span>
                    {collapsed ? <ChevronDown className="w-3 h-3 text-muted-foreground/30" /> : <ChevronUp className="w-3 h-3 text-muted-foreground/30" />}
                  </div>
                </button>
                {!collapsed && (
                  <div className="px-2 pb-1 space-y-0.5">
                    {catTools.map((t) => (
                      <div key={t.id}
                        className="flex items-center gap-2.5 px-2 py-2 rounded-lg cursor-grab active:cursor-grabbing hover:bg-accent/30 transition-colors group"
                        draggable
                        onDragStart={(e) => handleSidebarDragStart(e, t.id)}
                        onClick={() => addPanel(t.id)}
                        title={`Drag or click to add ${t.name}`}>
                        <div className={cn("h-6 w-6 rounded-md flex items-center justify-center shrink-0", t.iconBg, t.color)}>
                          {t.icon}
                        </div>
                        <div className="min-w-0 flex-1">
                          <span className="text-xs text-muted-foreground group-hover:text-foreground transition-colors truncate block">{t.name}</span>
                          <span className="text-[10px] text-muted-foreground/40 truncate block">{t.description}</span>
                        </div>
                        <Plus className="w-3 h-3 text-muted-foreground/0 group-hover:text-primary/60 transition-all ml-auto shrink-0" />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <div className="px-4 py-3 border-t border-border text-[10px] text-muted-foreground/40">
          {panels.length} panel{panels.length !== 1 ? "s" : ""}
          {runningCount > 0 && <span className="text-amber-400 ml-1">· {runningCount} running</span>}
        </div>

        {/* Resize handle */}
        <div onMouseDown={handleSidebarResizeDown}
          className="absolute top-0 right-0 w-1.5 h-full cursor-ew-resize z-20 hover:bg-primary/20 transition-colors group">
          <div className="absolute top-1/2 -translate-y-1/2 right-0 w-1 h-8 rounded-full bg-muted-foreground/10 group-hover:bg-primary/40 transition-colors" />
        </div>
      </div>

      {/* ═══ MAIN AREA ═══ */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Toolbar */}
        <div className="flex items-center gap-3 px-4 py-2.5 border-b border-white/[0.06] bg-card/60 backdrop-blur-sm shrink-0">
          <button onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent/30 transition-colors"
            title={sidebarOpen ? "Hide sidebar" : "Show sidebar"}>
            <LayoutGrid className="w-4 h-4" />
          </button>
          <div className="flex items-center gap-2 shrink-0">
            <Target size={15} className="text-primary" />
            <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Target</span>
          </div>
          <input type="text" value={globalTarget}
            onChange={(e) => setGlobalTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && runAll()}
            placeholder="Shared target — e.g. example.com, 8.8.8.8, CVE-2024-1234 ..."
            className="flex-1 bg-background border border-white/[0.06] rounded-lg px-4 py-2 text-[13px] text-foreground placeholder-muted-foreground/40 outline-none focus:border-primary/30 transition-colors font-mono" />
          <button onClick={runAll} disabled={panels.length === 0}
            className="flex items-center gap-2 rounded-lg bg-primary/10 border border-primary/20 px-4 py-2 text-[12px] font-semibold text-primary hover:bg-primary/20 transition-all disabled:opacity-30 disabled:cursor-not-allowed">
            <Search size={13} /> Run All
          </button>
          <div className="w-px h-6 bg-white/[0.06]" />
          <AddToolDropdown onAdd={addPanel} disabled={panels.length >= MAX_PANELS} />
          <span className="text-[10px] text-muted-foreground font-mono">
            {panels.length}/{MAX_PANELS}
            {runningCount > 0 && <span className="text-amber-400 ml-1">· {runningCount} running</span>}
          </span>
          <button onClick={resetToDefaults} className="p-2 rounded-lg border border-white/[0.06] hover:bg-white/[0.04] text-muted-foreground hover:text-foreground transition-colors" title="Reset to defaults">
            <RotateCcw size={13} />
          </button>
        </div>

        {/* Canvas */}
        <div ref={canvasRef}
          onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; }}
          onDrop={handleWorkspaceDrop}
          className="flex-1 min-h-0 overflow-auto p-3"
          style={{ backgroundImage: "radial-gradient(circle, hsl(var(--border)) 1px, transparent 1px)", backgroundSize: "32px 32px" }}>
          {panels.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center">
              <div className="w-24 h-24 rounded-2xl border-2 border-dashed border-white/[0.08] flex items-center justify-center mb-5 relative">
                <GripVertical size={28} className="text-white/10 absolute -left-2 top-1/2 -translate-y-1/2" />
                <Plus size={32} className="text-white/10" />
              </div>
              <p className="text-[16px] font-semibold text-white/20 mb-2">Drag & Drop Tools Here</p>
              <p className="text-[13px] text-white/10 max-w-sm text-center leading-relaxed">
                Grab any tool from the sidebar and drop it into this workspace to get started.
              </p>
              <p className="text-[11px] text-white/[0.06] mt-3">or use the <span className="text-white/10 font-medium">Add Tool</span> button in the toolbar above</p>
            </div>
          ) : (
            <div className="flex flex-wrap content-start" style={{ gap: `${GAP}px` }}>
              {panels.map((panel) => {
                const tool = TOOL_MAP[panel.toolId];
                if (!tool) return null;
                return (
                  <ToolPanel key={panel.uid} panel={panel} tool={tool} globalTarget={globalTarget} canvasWidth={canvasWidth}
                    onRemove={() => removePanel(panel.uid)} onRun={() => runTool(panel.uid)}
                    onToggleExpand={() => toggleExpand(panel.uid)} onSetLocalTarget={(v) => setLocalTarget(panel.uid, v)}
                    onResize={(w, h) => resizePanel(panel.uid, w, h)} />
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}