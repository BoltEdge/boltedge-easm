// FILE: app/(authenticated)/assets/[id]/IntelligenceTabs.tsx
// F5: Asset Intelligence — tabbed view of tech stack, SSL certs, DNS, ports
// Fetches from GET /assets/<id>/intelligence and renders organized tabs
"use client";

import { useEffect, useState } from "react";
import {
  Cpu, Shield, Globe, Server, AlertTriangle, CheckCircle2,
  XCircle, Clock, Lock, Unlock, ExternalLink, ChevronDown,
  ChevronRight, Loader2, Info, Tag,
} from "lucide-react";
import { apiFetch } from "../../../lib/api";
import { SeverityBadge } from "../../../SeverityBadge";

function cn(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(" ");
}

function formatDate(d?: any) {
  if (!d) return "—";
  let dt: Date;
  if (typeof d === "string" && !d.endsWith("Z") && !d.includes("+")) dt = new Date(d + "Z");
  else dt = d instanceof Date ? d : new Date(d);
  if (isNaN(dt.getTime())) return "—";
  return dt.toLocaleDateString();
}

// ─── Types ────────────────────────────────────
type Technology = {
  name: string;
  version?: string;
  category: string;
  source: string;
  port?: number;
  confidence: string;
  severity: string;
  isOutdated: boolean;
  eolMessage?: string;
  firstSeen?: string;
  lastSeen?: string;
};

type Certificate = {
  port: number;
  ip?: string;
  commonName?: string;
  issuerName?: string;
  subject?: Record<string, string>;
  issuer?: Record<string, string>;
  notBefore?: string;
  notAfter?: string;
  isExpired?: boolean;
  daysUntilExpiry?: number;
  isSelfSigned?: boolean;
  hostnameMatch?: boolean;
  sans?: string[];
  protocolVersion?: string;
  cipher?: string;
  issues?: { title: string; severity: string; description: string }[];
  lastSeen?: string;
};

type DNSInfo = {
  spf?: { raw?: string; status?: string; allQualifier?: string; mechanisms?: string[] };
  dmarc?: { raw?: string; status?: string; policy?: string; rua?: string };
  dkim?: { found?: boolean; selectors?: string[]; status?: string };
  nameservers?: string[];
  hasIpv6?: boolean;
  zoneTransfer?: { successful?: boolean; server?: string; recordsCount?: number };
  issues?: { title: string; severity: string; description: string; findingType: string }[];
};

type PortEntry = {
  ip: string;
  port: number;
  transport: string;
  product: string;
  version: string;
  service: string;
  severity: string;
  title: string;
  banner?: string;
  lastSeen?: string;
};

type IntelligenceData = {
  technologies: Technology[];
  techCategories: Record<string, number>;
  techCount: number;
  outdatedCount: number;
  certificates: Certificate[];
  dns: DNSInfo;
  ports: PortEntry[];
  portCount: number;
};

// ─── Category config ──────────────────────────
const TECH_CATEGORY_CONFIG: Record<string, { label: string; icon: string; color: string }> = {
  web_server: { label: "Web Servers", icon: "🌐", color: "text-blue-400 bg-blue-500/10 border-blue-500/20" },
  framework: { label: "Frameworks", icon: "⚡", color: "text-purple-400 bg-purple-500/10 border-purple-500/20" },
  cms: { label: "CMS", icon: "📝", color: "text-amber-400 bg-amber-500/10 border-amber-500/20" },
  cdn_waf: { label: "CDN / WAF", icon: "🛡", color: "text-teal-400 bg-teal-500/10 border-teal-500/20" },
  database: { label: "Databases", icon: "🗄", color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" },
  os: { label: "Operating System", icon: "💻", color: "text-zinc-400 bg-zinc-500/10 border-zinc-500/20" },
  cache: { label: "Cache", icon: "⚡", color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20" },
  cloud: { label: "Cloud Platform", icon: "☁", color: "text-sky-400 bg-sky-500/10 border-sky-500/20" },
  email: { label: "Email", icon: "📧", color: "text-rose-400 bg-rose-500/10 border-rose-500/20" },
  remote_access: { label: "Remote Access", icon: "🔑", color: "text-orange-400 bg-orange-500/10 border-orange-500/20" },
  other: { label: "Other", icon: "📦", color: "text-zinc-400 bg-zinc-500/10 border-zinc-500/20" },
};

// ─── Status indicator ─────────────────────────
function StatusDot({ status }: { status: string }) {
  const cfg = {
    pass: "bg-emerald-400",
    warn: "bg-amber-400",
    fail: "bg-red-400",
    missing: "bg-red-400",
  }[status] || "bg-zinc-400";

  return <div className={cn("w-2.5 h-2.5 rounded-full shrink-0", cfg)} />;
}

function StatusLabel({ status }: { status: string }) {
  const labels: Record<string, { text: string; class: string }> = {
    pass: { text: "Configured", class: "text-emerald-400" },
    warn: { text: "Weak", class: "text-amber-400" },
    fail: { text: "Misconfigured", class: "text-red-400" },
    missing: { text: "Missing", class: "text-red-400" },
  };
  const l = labels[status] || { text: status, class: "text-zinc-400" };
  return <span className={cn("text-xs font-semibold", l.class)}>{l.text}</span>;
}

// ─── Tab definitions ──────────────────────────
type TabKey = "tech" | "ssl" | "dns" | "ports";

const TABS: { key: TabKey; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { key: "tech", label: "Technology", icon: Cpu },
  { key: "ssl", label: "SSL / TLS", icon: Lock },
  { key: "dns", label: "DNS", icon: Globe },
  { key: "ports", label: "Ports", icon: Server },
];

// ═══════════════════════════════════════════════
// Technology Tab
// ═══════════════════════════════════════════════
function TechTab({ data }: { data: IntelligenceData }) {
  const { technologies, techCategories, outdatedCount } = data;

  if (!technologies.length) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <Cpu className="w-10 h-10 mx-auto mb-3 opacity-30" />
        <p className="text-sm">No technologies detected yet. Run a Standard or Deep scan to fingerprint the tech stack.</p>
      </div>
    );
  }

  // Group by category
  const grouped: Record<string, Technology[]> = {};
  for (const t of technologies) {
    const cat = t.category || "other";
    if (!grouped[cat]) grouped[cat] = [];
    grouped[cat].push(t);
  }

  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="flex flex-wrap gap-2">
        {Object.entries(techCategories).map(([cat, count]) => {
          const cfg = TECH_CATEGORY_CONFIG[cat] || TECH_CATEGORY_CONFIG.other;
          return (
            <span key={cat} className={cn("inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium", cfg.color)}>
              <span>{cfg.icon}</span>
              {cfg.label}: {count}
            </span>
          );
        })}
        {outdatedCount > 0 && (
          <span className="inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium text-red-400 bg-red-500/10 border-red-500/20">
            <AlertTriangle className="w-3.5 h-3.5" />
            {outdatedCount} outdated
          </span>
        )}
      </div>

      {/* Tech list by category */}
      {Object.entries(grouped).map(([cat, techs]) => {
        const cfg = TECH_CATEGORY_CONFIG[cat] || TECH_CATEGORY_CONFIG.other;
        return (
          <div key={cat} className="bg-card border border-border rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-border bg-muted/20">
              <span className="text-sm font-semibold text-foreground flex items-center gap-2">
                <span>{cfg.icon}</span>{cfg.label}
                <span className="text-xs text-muted-foreground font-normal">({techs.length})</span>
              </span>
            </div>
            <div className="divide-y divide-border">
              {techs.map((t, i) => (
                <div key={`${t.name}-${i}`} className="px-4 py-3 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-foreground">{t.name}</span>
                        {t.version && (
                          <span className="text-xs font-mono text-muted-foreground bg-accent rounded px-1.5 py-0.5">{t.version}</span>
                        )}
                        {t.isOutdated && (
                          <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-red-400 bg-red-500/10 border border-red-500/20 rounded px-1.5 py-0.5">
                            <AlertTriangle className="w-3 h-3" />EOL
                          </span>
                        )}
                      </div>
                      {t.eolMessage && (
                        <p className="text-xs text-red-300/80 mt-0.5">{t.eolMessage}</p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    {t.port && (
                      <span className="text-xs text-muted-foreground font-mono">:{t.port}</span>
                    )}
                    <span className="text-[10px] text-muted-foreground bg-accent rounded px-1.5 py-0.5">{t.source}</span>
                    <SeverityBadge severity={t.severity} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ═══════════════════════════════════════════════
// SSL / TLS Tab
// ═══════════════════════════════════════════════
function SSLTab({ data }: { data: IntelligenceData }) {
  const { certificates } = data;

  if (!certificates.length) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <Lock className="w-10 h-10 mx-auto mb-3 opacity-30" />
        <p className="text-sm">No SSL/TLS data available. Run a Standard or Deep scan to analyze certificates.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {certificates.map((cert, idx) => {
        const hasIssues = cert.issues && cert.issues.length > 0;
        const expiryColor = cert.isExpired
          ? "text-red-400"
          : (cert.daysUntilExpiry ?? 999) <= 30
          ? "text-amber-400"
          : "text-emerald-400";

        return (
          <div key={`${cert.port}-${idx}`} className="bg-card border border-border rounded-xl overflow-hidden">
            {/* Header */}
            <div className="px-4 py-3 border-b border-border bg-muted/20 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center",
                  hasIssues ? "bg-amber-500/10" : "bg-emerald-500/10")}>
                  {hasIssues ? <Unlock className="w-4 h-4 text-amber-400" /> : <Lock className="w-4 h-4 text-emerald-400" />}
                </div>
                <div>
                  <span className="text-sm font-semibold text-foreground">Port {cert.port}</span>
                  <span className="text-xs text-muted-foreground ml-2">
                    {cert.commonName || "Unknown CN"}
                  </span>
                </div>
              </div>
              <div className={cn("text-xs font-semibold", expiryColor)}>
                {cert.isExpired
                  ? "EXPIRED"
                  : cert.daysUntilExpiry != null
                  ? `${cert.daysUntilExpiry}d until expiry`
                  : ""}
              </div>
            </div>

            {/* Details grid */}
            <div className="px-4 py-4 grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
              <div>
                <div className="text-xs text-muted-foreground mb-1">Subject</div>
                <div className="font-mono text-foreground text-xs">{cert.commonName || "—"}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">Issuer</div>
                <div className="text-foreground text-xs">{cert.issuerName || "—"}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">Valid Until</div>
                <div className={cn("text-xs font-semibold", expiryColor)}>{formatDate(cert.notAfter)}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">Self-Signed</div>
                <div className="text-xs text-foreground">{cert.isSelfSigned ? "Yes ⚠" : "No ✓"}</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">Hostname Match</div>
                <div className="text-xs text-foreground">{cert.hostnameMatch === false ? "No ⚠" : cert.hostnameMatch === true ? "Yes ✓" : "—"}</div>
              </div>
              {cert.cipher && (
                <div>
                  <div className="text-xs text-muted-foreground mb-1">Cipher</div>
                  <div className="font-mono text-foreground text-xs">{cert.cipher}</div>
                </div>
              )}
            </div>

            {/* SANs */}
            {cert.sans && cert.sans.length > 0 && (
              <div className="px-4 pb-3">
                <div className="text-xs text-muted-foreground mb-1.5">Subject Alternative Names ({cert.sans.length})</div>
                <div className="flex flex-wrap gap-1.5">
                  {cert.sans.slice(0, 12).map((san) => (
                    <span key={san} className="inline-flex rounded bg-accent px-2 py-0.5 text-[11px] font-mono text-muted-foreground">
                      {san}
                    </span>
                  ))}
                  {cert.sans.length > 12 && (
                    <span className="text-[11px] text-muted-foreground">+{cert.sans.length - 12} more</span>
                  )}
                </div>
              </div>
            )}

            {/* Issues */}
            {hasIssues && (
              <div className="border-t border-border">
                {cert.issues!.map((issue, i) => (
                  <div key={i} className="px-4 py-2.5 flex items-start gap-2 border-b border-border last:border-0">
                    <SeverityBadge severity={issue.severity} />
                    <div className="min-w-0">
                      <div className="text-xs font-medium text-foreground">{issue.title}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ═══════════════════════════════════════════════
// DNS Tab
// ═══════════════════════════════════════════════
function DNSTab({ data }: { data: IntelligenceData }) {
  const { dns } = data;

  if (!dns || (!dns.spf && !dns.dmarc && !dns.issues?.length && !dns.nameservers?.length)) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <Globe className="w-10 h-10 mx-auto mb-3 opacity-30" />
        <p className="text-sm">No DNS data available. Run a Standard or Deep scan to analyze DNS records.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Email Security Summary */}
      <div className="bg-card border border-border rounded-xl p-4">
        <h3 className="text-xs font-semibold text-muted-foreground uppercase mb-4">Email Security</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* SPF */}
          <div className="border border-border rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-semibold text-foreground">SPF</span>
              {dns.spf ? <StatusLabel status={dns.spf.status || "pass"} /> : <StatusLabel status="missing" />}
            </div>
            {dns.spf?.raw ? (
              <code className="text-[10px] text-muted-foreground font-mono break-all block bg-accent/50 rounded px-2 py-1">
                {dns.spf.raw}
              </code>
            ) : (
              <p className="text-xs text-muted-foreground">No SPF record found</p>
            )}
          </div>

          {/* DMARC */}
          <div className="border border-border rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-semibold text-foreground">DMARC</span>
              {dns.dmarc ? <StatusLabel status={dns.dmarc.status || "pass"} /> : <StatusLabel status="missing" />}
            </div>
            {dns.dmarc?.policy ? (
              <div className="space-y-1">
                <div className="text-xs text-muted-foreground">
                  Policy: <span className="text-foreground font-semibold">{dns.dmarc.policy}</span>
                </div>
                {dns.dmarc.rua && (
                  <div className="text-xs text-muted-foreground truncate">
                    Reports: {dns.dmarc.rua}
                  </div>
                )}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">No DMARC record found</p>
            )}
          </div>

          {/* DKIM */}
          <div className="border border-border rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-semibold text-foreground">DKIM</span>
              {dns.dkim?.found ? <StatusLabel status="pass" /> : <StatusLabel status="missing" />}
            </div>
            <p className="text-xs text-muted-foreground">
              {dns.dkim?.found ? "DKIM selectors found" : "No DKIM selectors detected"}
            </p>
          </div>
        </div>
      </div>

      {/* Zone Security */}
      {dns.zoneTransfer?.successful && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            <span className="text-sm font-semibold text-red-300">Zone Transfer Vulnerable</span>
          </div>
          <p className="text-xs text-red-200/70">
            DNS zone transfer (AXFR) succeeded from {dns.zoneTransfer.server || "nameserver"}.
            {dns.zoneTransfer.recordsCount && ` ${dns.zoneTransfer.recordsCount} records exposed.`}
            {" "}Restrict zone transfers to authorized secondary nameservers only.
          </p>
        </div>
      )}

      {/* Nameservers */}
      {dns.nameservers && dns.nameservers.length > 0 && (
        <div className="bg-card border border-border rounded-xl p-4">
          <h3 className="text-xs font-semibold text-muted-foreground uppercase mb-3">Nameservers ({dns.nameservers.length})</h3>
          <div className="flex flex-wrap gap-2">
            {dns.nameservers.map((ns) => (
              <span key={ns} className="inline-flex rounded-lg bg-accent px-2.5 py-1 text-xs font-mono text-foreground">
                {ns}
              </span>
            ))}
          </div>
          {dns.nameservers.length === 1 && (
            <p className="text-xs text-amber-400 mt-2">⚠ Only one nameserver — no redundancy</p>
          )}
        </div>
      )}

      {/* IPv6 */}
      {dns.hasIpv6 !== null && dns.hasIpv6 !== undefined && (
        <div className="bg-card border border-border rounded-xl p-4">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-foreground">IPv6 (AAAA)</span>
            {dns.hasIpv6 ? (
              <span className="text-xs text-emerald-400 font-semibold">Available ✓</span>
            ) : (
              <span className="text-xs text-amber-400 font-semibold">Not configured</span>
            )}
          </div>
        </div>
      )}

      {/* Issues list */}
      {dns.issues && dns.issues.length > 0 && (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border bg-muted/20">
            <span className="text-sm font-semibold text-foreground">DNS Issues ({dns.issues.length})</span>
          </div>
          <div className="divide-y divide-border">
            {dns.issues.map((issue, i) => (
              <div key={i} className="px-4 py-3 flex items-start gap-3">
                <SeverityBadge severity={issue.severity} />
                <div className="min-w-0">
                  <div className="text-sm font-medium text-foreground">{issue.title}</div>
                  <div className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{issue.description}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════
// Ports Tab
// ═══════════════════════════════════════════════
function PortsTab({ data }: { data: IntelligenceData }) {
  const { ports } = data;

  if (!ports.length) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <Server className="w-10 h-10 mx-auto mb-3 opacity-30" />
        <p className="text-sm">No port data available. Run a scan to discover open ports and services.</p>
      </div>
    );
  }

  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden">
      <table className="w-full">
        <thead className="bg-muted/30 border-b border-border">
          <tr>
            <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[100px]">Port</th>
            <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[80px]">Proto</th>
            <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase">Service</th>
            <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase">Product / Version</th>
            {ports.some((p) => p.ip) && (
              <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[140px]">IP</th>
            )}
            <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[80px]">Risk</th>
            <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase w-[100px]">Last Seen</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {ports.map((p, i) => (
            <tr key={`${p.ip}-${p.port}-${i}`} className="hover:bg-accent/30 transition-colors">
              <td className="px-4 py-3">
                <span className="font-mono text-sm font-semibold text-foreground">{p.port}</span>
              </td>
              <td className="px-4 py-3">
                <span className="text-xs text-muted-foreground uppercase">{p.transport}</span>
              </td>
              <td className="px-4 py-3">
                <span className="text-sm text-foreground">{p.service || "—"}</span>
              </td>
              <td className="px-4 py-3">
                <span className="text-sm text-foreground">
                  {p.product || "—"}
                  {p.version && <span className="text-muted-foreground ml-1">{p.version}</span>}
                </span>
              </td>
              {ports.some((pp) => pp.ip) && (
                <td className="px-4 py-3">
                  <span className="font-mono text-xs text-muted-foreground">{p.ip || "—"}</span>
                </td>
              )}
              <td className="px-4 py-3">
                <SeverityBadge severity={p.severity} />
              </td>
              <td className="px-4 py-3 text-xs text-muted-foreground">
                {formatDate(p.lastSeen)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ═══════════════════════════════════════════════
// Main Export: IntelligenceTabs
// ═══════════════════════════════════════════════
export default function IntelligenceTabs({ assetId }: { assetId: string }) {
  const [activeTab, setActiveTab] = useState<TabKey>("tech");
  const [data, setData] = useState<IntelligenceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    apiFetch<IntelligenceData>(`/assets/${assetId}/intelligence`)
      .then(setData)
      .catch((e: any) => setError(e?.message || "Failed to load intelligence data"))
      .finally(() => setLoading(false));
  }, [assetId]);

  // Tab badge counts
  const tabBadge = (key: TabKey): number | null => {
    if (!data) return null;
    switch (key) {
      case "tech": return data.techCount || null;
      case "ssl": return data.certificates.length || null;
      case "dns": return data.dns.issues?.length || null;
      case "ports": return data.portCount || null;
    }
  };

  if (loading) {
    return (
      <div className="bg-card border border-border rounded-xl p-8">
        <div className="flex items-center justify-center gap-2 text-muted-foreground">
          <Loader2 className="w-5 h-5 animate-spin" />Loading intelligence data…
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="bg-card border border-border rounded-xl p-6 text-center text-muted-foreground">
        <p className="text-sm">{error || "No intelligence data available. Run a scan first."}</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Tab bar */}
      <div className="flex items-center bg-card border border-border rounded-lg overflow-hidden">
        {TABS.map(({ key, label, icon: Icon }) => {
          const badge = tabBadge(key);
          return (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={cn(
                "flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium transition-colors",
                activeTab === key
                  ? "bg-primary/15 text-primary"
                  : "text-muted-foreground hover:text-foreground hover:bg-accent/30",
              )}
            >
              <Icon className="w-3.5 h-3.5" />
              {label}
              {badge != null && badge > 0 && (
                <span className="text-[10px] opacity-60">({badge})</span>
              )}
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      {activeTab === "tech" && <TechTab data={data} />}
      {activeTab === "ssl" && <SSLTab data={data} />}
      {activeTab === "dns" && <DNSTab data={data} />}
      {activeTab === "ports" && <PortsTab data={data} />}
    </div>
  );
}