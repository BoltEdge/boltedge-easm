/**
 * Human-readable summary builder for LookUp Tool results.
 *
 * Used when a user clicks "Save as Alert" — we extract the key findings from
 * the tool's structured response and produce a concise, multi-line plain-text
 * summary. That goes into MonitorAlert.summary, which is also what shows up
 * in email notifications and webhook payloads.
 *
 * Old behaviour was `JSON.stringify(result, null, 2).slice(0, 800)` which left
 * a raw JSON blob in the alert — looked terrible and gave no signal.
 */

type ToolId = string;

const MAX_SUMMARY = 950; // a touch under the 1000-char DB column

function bullet(line: string | null | undefined): string | null {
  const s = (line ?? "").toString().trim();
  return s ? `• ${s}` : null;
}

function compact(...lines: Array<string | null | undefined>): string {
  return lines
    .map((l) => (l ?? "").toString().trimEnd())
    .filter((l) => l.length > 0)
    .join("\n");
}

function truncate(s: string, max = MAX_SUMMARY): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1).trimEnd() + "…";
}

function pluralize(n: number, singular: string, plural?: string): string {
  return `${n} ${n === 1 ? singular : plural || singular + "s"}`;
}

function topIssues(issues: any[] | undefined, max = 3): string[] {
  if (!Array.isArray(issues) || issues.length === 0) return [];
  // Sort by severity desc (critical > high > medium > low > info)
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...issues].sort(
    (a, b) => (order[a.severity] ?? 99) - (order[b.severity] ?? 99),
  );
  return sorted.slice(0, max).map((i) => {
    const sev = (i.severity || "info").toUpperCase();
    return `[${sev}] ${i.title || i.message || i.code || "issue"}`;
  });
}

// ---------------------------------------------------------------------------
// Per-tool formatters
// ---------------------------------------------------------------------------

function fmtCert(data: any): string {
  if (data.totalFound !== undefined || data.coveredDomains !== undefined) {
    // crt.sh hash result
    return compact(
      `Certificate transparency match`,
      `Hash: ${data.hash || "—"}`,
      `Found: ${data.totalFound ?? 0} certificate(s)`,
      data.coveredDomains?.length
        ? `Domains covered: ${data.coveredDomains.slice(0, 5).join(", ")}${data.coveredDomains.length > 5 ? `, +${data.coveredDomains.length - 5} more` : ""}`
        : null,
    );
  }
  const cert = data.certificate || {};
  const issues = topIssues(data.issues);
  return compact(
    `Cert grade: ${data.grade || "?"}`,
    cert.subjectCn ? `CN: ${cert.subjectCn}` : null,
    cert.issuer ? `Issuer: ${cert.issuer}` : null,
    cert.notAfter ? `Expires: ${cert.notAfter}${cert.daysUntilExpiry !== undefined ? ` (${cert.daysUntilExpiry} days)` : ""}` : null,
    cert.tlsVersion ? `TLS: ${cert.tlsVersion}${cert.cipherSuite ? ` · ${cert.cipherSuite}` : ""}` : null,
    cert.isSelfSigned === true ? "⚠ Self-signed" : null,
    cert.chainValid === false ? "⚠ Chain invalid" : null,
    cert.hostnameMatch === false ? "⚠ Hostname mismatch" : null,
    issues.length ? `Issues:\n${issues.map((i) => `  • ${i}`).join("\n")}` : null,
  );
}

function fmtDns(data: any): string {
  const records = data.records || {};
  const recordSummary = Object.entries(records)
    .map(([type, recs]: [string, any]) => `${type}: ${pluralize((recs as any[]).length, "record")}`)
    .join(", ");
  const issues = topIssues(data.issues);
  return compact(
    `DNS grade: ${data.grade || "?"}`,
    data.resolvedIps?.length ? `Resolves to: ${data.resolvedIps.join(", ")}` : "No A records",
    recordSummary ? `Records: ${recordSummary}` : null,
    data.dkim?.found ? `DKIM: ${pluralize(data.dkim.selectorCount ?? data.dkim.selectors?.length ?? 0, "selector")} found` : null,
    issues.length ? `Issues:\n${issues.map((i) => `  • ${i}`).join("\n")}` : null,
  );
}

function fmtReverseDns(data: any): string {
  const issues = topIssues(data.issues);
  return compact(
    data.hostnames?.length
      ? `Hostnames: ${data.hostnames.slice(0, 5).join(", ")}${data.hostnames.length > 5 ? ", …" : ""}`
      : "No PTR records",
    data.forwardConfirmation?.length
      ? `Forward-confirmed: ${data.forwardConfirmation.filter((f: any) => f.confirmed).length} / ${data.forwardConfirmation.length}`
      : null,
    data.infrastructure?.length
      ? `Infrastructure indicators: ${data.infrastructure.map((i: any) => i.type).join(", ")}`
      : null,
    issues.length ? `Issues:\n${issues.map((i) => `  • ${i}`).join("\n")}` : null,
  );
}

function fmtHeader(data: any): string {
  const summary = data.headerSummary || {};
  const present = Object.entries(summary).filter(([, v]: [string, any]) => v?.present).map(([k]) => k);
  const missing = Object.entries(summary).filter(([, v]: [string, any]) => !v?.present).map(([k]) => k);
  const issues = topIssues(data.issues);
  return compact(
    `Headers grade: ${data.grade || "?"}`,
    data.https?.statusCode ? `HTTPS: ${data.https.statusCode}` : "HTTPS unavailable",
    data.httpRedirectsToHttps !== undefined
      ? data.httpRedirectsToHttps ? "HTTP → HTTPS: redirects ✓" : "HTTP → HTTPS: ✗ no redirect"
      : null,
    present.length ? `Present: ${present.join(", ")}` : null,
    missing.length ? `Missing: ${missing.join(", ")}` : null,
    issues.length ? `Issues:\n${issues.map((i) => `  • ${i}`).join("\n")}` : null,
  );
}

function fmtWhois(data: any): string {
  const qtype = data.queryType || "domain";
  const issues = topIssues(data.issues);
  if (qtype === "domain") {
    const reg = data.registration || {};
    return compact(
      `WHOIS · domain ${data.query}`,
      reg.registrar ? `Registrar: ${reg.registrar}` : null,
      reg.creationDate ? `Created: ${reg.creationDate}${reg.domainAgeDays ? ` (${reg.domainAgeDays} days old)` : ""}` : null,
      reg.expiryDate ? `Expires: ${reg.expiryDate}${reg.daysUntilExpiry !== undefined ? ` (${reg.daysUntilExpiry} days)` : ""}` : null,
      reg.registrantOrg ? `Registrant: ${reg.registrantOrg}` : null,
      reg.dnssec ? `DNSSEC: ${reg.dnssec}` : null,
      reg.nameservers?.length ? `Nameservers: ${reg.nameservers.slice(0, 4).join(", ")}` : null,
      issues.length ? `Issues:\n${issues.map((i) => `  • ${i}`).join("\n")}` : null,
    );
  }
  if (qtype === "ip") {
    const net = data.network || {};
    return compact(
      `WHOIS · IP ${data.query}`,
      net.orgName ? `Org: ${net.orgName}` : null,
      net.country ? `Country: ${net.country}` : null,
      net.netRange ? `Range: ${net.netRange}` : null,
      net.cidr ? `CIDR: ${net.cidr}` : null,
      issues.length ? `Issues:\n${issues.map((i) => `  • ${i}`).join("\n")}` : null,
    );
  }
  if (qtype === "asn") {
    const asn = data.asn || {};
    return compact(
      `WHOIS · ASN ${data.query}`,
      asn.number ? `AS${asn.number}${asn.name ? ` (${asn.name})` : ""}` : null,
      asn.orgName ? `Org: ${asn.orgName}` : null,
      asn.country ? `Country: ${asn.country}` : null,
    );
  }
  return `WHOIS · ${data.query || "?"}`;
}

function fmtConnectivity(data: any): string {
  const single = data.result;
  const ports: any[] | undefined = data.ports;
  const issues = topIssues(data.issues);
  if (single) {
    return compact(
      `Connectivity · ${data.host}${data.port ? `:${data.port}` : ""}`,
      data.resolvedIp && data.resolvedIp !== data.host ? `Resolved: ${data.resolvedIp}` : null,
      single.reachable ? `✓ Reachable (${single.latencyMs}ms)` : "✗ Not reachable",
      single.service ? `Service: ${single.service}` : null,
      single.banner ? `Banner: ${String(single.banner).slice(0, 120)}` : null,
      single.tls ? `TLS: ${single.tls.version}${single.tls.cipher ? ` · ${single.tls.cipher}` : ""}` : null,
      issues.length ? `Issues:\n${issues.map((i) => `  • ${i}`).join("\n")}` : null,
    );
  }
  if (ports) {
    const open = ports.filter((p) => p.reachable).map((p) => `${p.port}${p.expectedService ? ` (${p.expectedService})` : ""}`);
    return compact(
      `Connectivity · ${data.host} · scanned ${data.totalChecked} ports`,
      `Open: ${data.openPorts}${open.length ? ` — ${open.slice(0, 8).join(", ")}${open.length > 8 ? ", …" : ""}` : ""}`,
      `Closed/filtered: ${data.closedPorts}`,
      issues.length ? `Issues:\n${issues.map((i) => `  • ${i}`).join("\n")}` : null,
    );
  }
  return `Connectivity · ${data.host}`;
}

function fmtEmailSecurity(data: any): string {
  const spf = data.spf || {};
  const dkim = data.dkim || {};
  const dmarc = data.dmarc || {};
  const issues = topIssues(data.issues);
  return compact(
    `Email auth grade: ${data.grade || "?"}`,
    `SPF:   ${spf.found ? `found (${spf.allQualifier === "-" ? "hard fail" : spf.allQualifier === "~" ? "soft fail" : "other"} · ${spf.lookupCount} lookups)` : "✗ not found"}`,
    `DKIM:  ${dkim.found ? `${pluralize(dkim.selectorCount ?? 0, "selector")} found` : "✗ not found"}`,
    `DMARC: ${dmarc.found ? `policy=${dmarc.policy || "none"}${dmarc.subdomainPolicy ? ` · sp=${dmarc.subdomainPolicy}` : ""}` : "✗ not found"}`,
    issues.length ? `Issues:\n${issues.map((i) => `  • ${i}`).join("\n")}` : null,
  );
}

function fmtSensitivePaths(data: any): string {
  const findings = data.findings || [];
  const sev = data.severityCounts || {};
  const top = findings.slice(0, 3).map((f: any) => `[${(f.severity || "info").toUpperCase()}] ${f.path} — ${f.title}`);
  return compact(
    `Sensitive paths · ${data.domain}`,
    `Checked ${data.pathsChecked} paths · Found ${data.pathsFound} exposed`,
    sev.critical || sev.high || sev.medium
      ? `By severity: ${[
          sev.critical ? `${sev.critical} critical` : null,
          sev.high ? `${sev.high} high` : null,
          sev.medium ? `${sev.medium} medium` : null,
        ].filter(Boolean).join(", ")}`
      : null,
    top.length ? `Top hits:\n${top.map((t: string) => `  • ${t}`).join("\n")}` : null,
  );
}

function fmtGitHubLeaks(data: any): string {
  const sev = data.severityCounts || {};
  const searches = (data.searches || []).filter((s: any) => s.totalResults > 0);
  const top = searches.slice(0, 3).map(
    (s: any) => `[${(s.severity || "info").toUpperCase()}] ${s.title} — ${s.totalResults} hit(s)`,
  );
  return compact(
    `GitHub leak scan · ${data.domain}`,
    `${data.searchesCompleted} searches · ${data.totalLeaks} leak(s)`,
    !data.hasGitHubToken ? "⚠ No GITHUB_TOKEN — limited results" : null,
    data.rateLimited ? "⚠ Rate-limited by GitHub" : null,
    sev.critical || sev.high
      ? `By severity: ${[sev.critical ? `${sev.critical} critical` : null, sev.high ? `${sev.high} high` : null].filter(Boolean).join(", ")}`
      : null,
    top.length ? `Top searches:\n${top.map((t: string) => `  • ${t}`).join("\n")}` : null,
  );
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function formatToolResultSummary(toolId: ToolId, data: any, target: string): string {
  if (!data) return `${toolId} on ${target}: no data`;
  if (data.error) return `${toolId} on ${target}: ${data.error}`;

  let body: string;
  switch (toolId) {
    case "cert-lookup":        body = fmtCert(data); break;
    case "dns-lookup":         body = fmtDns(data); break;
    case "reverse-dns":        body = fmtReverseDns(data); break;
    case "header-check":       body = fmtHeader(data); break;
    case "whois":              body = fmtWhois(data); break;
    case "connectivity-check": body = fmtConnectivity(data); break;
    case "email-security":     body = fmtEmailSecurity(data); break;
    case "sensitive-paths":    body = fmtSensitivePaths(data); break;
    case "github-leaks":       body = fmtGitHubLeaks(data); break;
    default:
      // Unknown tool — fall back to a short JSON preview rather than the
      // full dump. Better than silence, less ugly than 800 chars of JSON.
      body = `Result preview:\n${JSON.stringify(data).slice(0, 400)}`;
  }

  return truncate(body);
}

/**
 * Suggest a sensible alert title for a tool result. Used to seed the
 * "Save as Alert" dialog so the user starts with something descriptive
 * rather than `"<tool>: <target>"`.
 */
export function suggestAlertTitle(toolId: ToolId, toolName: string, data: any, target: string): string {
  if (!data || data.error) return `${toolName}: ${target}`;
  switch (toolId) {
    case "cert-lookup": {
      const cert = data.certificate;
      if (cert?.daysUntilExpiry !== undefined && cert.daysUntilExpiry <= 30) {
        return `Cert expiring in ${cert.daysUntilExpiry} days — ${target}`;
      }
      return `Cert grade ${data.grade || "?"} — ${target}`;
    }
    case "dns-lookup":     return `DNS grade ${data.grade || "?"} — ${target}`;
    case "header-check":   return `Headers grade ${data.grade || "?"} — ${target}`;
    case "email-security": return `Email auth grade ${data.grade || "?"} — ${target}`;
    case "sensitive-paths":
      return data.pathsFound > 0
        ? `${data.pathsFound} exposed path(s) on ${target}`
        : `Sensitive-path scan — ${target}`;
    case "github-leaks":
      return data.totalLeaks > 0
        ? `${data.totalLeaks} GitHub leak(s) for ${target}`
        : `GitHub leak scan — ${target}`;
    case "connectivity-check":
      return data.openPorts !== undefined
        ? `${data.openPorts} open port(s) on ${target}`
        : `Connectivity — ${target}`;
    default:
      return `${toolName}: ${target}`;
  }
}

/**
 * Suggested severity from tool output. Returns `null` if we can't infer one
 * (caller falls back to whatever the user picked in the dialog).
 */
export function suggestSeverity(toolId: ToolId, data: any): "critical" | "high" | "medium" | "low" | "info" | null {
  if (!data || data.error) return null;

  // Issues array — take the highest severity present
  if (Array.isArray(data.issues) && data.issues.length > 0) {
    const sevs = new Set(data.issues.map((i: any) => (i.severity || "").toLowerCase()));
    if (sevs.has("critical")) return "critical";
    if (sevs.has("high"))     return "high";
    if (sevs.has("medium"))   return "medium";
    if (sevs.has("low"))      return "low";
  }

  // Tool-specific overrides
  if (toolId === "cert-lookup") {
    const days = data.certificate?.daysUntilExpiry;
    if (days !== undefined && days <= 7)  return "critical";
    if (days !== undefined && days <= 30) return "high";
  }
  if (toolId === "sensitive-paths" && data.severityCounts?.critical > 0) return "critical";
  if (toolId === "github-leaks"    && data.severityCounts?.critical > 0) return "critical";

  // Grade fallback
  if (data.grade === "F") return "high";
  if (data.grade === "D") return "medium";
  if (data.grade === "C") return "low";

  return null;
}
