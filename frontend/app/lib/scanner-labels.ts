// Scanner / engine / source name mapping.
//
// The backend records the actual tool name on findings, intelligence
// rows, and discovery sources (e.g. "shodan", "nmap", "nuclei",
// "ct_logs"). We deliberately don't surface those names to customers
// — they're implementation detail and naming a third-party scanner
// in the UI suggests Nano EASM is just a wrapper, which under-sells
// the platform.
//
// Use `friendlyScannerName(raw)` everywhere a backend-provided
// engine / source / module name would otherwise be rendered.

const FRIENDLY: Record<string, string> = {
  // External intelligence + asset enrichment
  shodan:        "Host intelligence",
  virustotal:    "Threat intelligence",
  abuseipdb:     "Abuse intelligence",
  censys:        "Host intelligence",

  // Active scanners
  nmap:          "Port scan",
  nuclei:        "Vulnerability check",
  sslyze:        "TLS analysis",
  ssl_analyzer:  "TLS analysis",
  ssl:           "TLS analysis",
  cert:          "Certificate check",

  // Discovery sources / sub-modules
  ct_logs:       "Certificate transparency",
  ct:            "Certificate transparency",
  crtsh:         "Certificate transparency",
  brute:         "Subdomain brute force",
  brute_force:   "Subdomain brute force",
  dns:           "DNS lookup",
  dnsdumpster:   "DNS lookup",
  passive_dns:   "DNS lookup",
  whois:         "WHOIS",
  rdap:          "WHOIS",
  asn:           "Network mapping",
  bgp:           "Network mapping",
  permutations:  "Subdomain permutations",
  archive:       "Web archive",
  wayback:       "Web archive",

  // Finding categories / engines
  http:          "Web",
  web:           "Web",
  headers:       "HTTP headers",
  tech:          "Tech detection",
  fingerprint:   "Tech detection",
  ports:         "Ports",
  port_risk:     "Ports",
  cve:           "CVE",
  exposure:      "Exposure check",

  // Generic fallbacks
  engine:        "Auto-detected",
  manual:        "Manual",
  user:          "Manual",
};

/**
 * Translate a raw backend-provided scanner / engine / source name
 * into a customer-friendly label. Unknown values fall through with
 * underscores → spaces and Title Case so we never leak something raw.
 */
export function friendlyScannerName(raw: string | null | undefined): string {
  if (!raw) return "Auto-detected";
  const key = String(raw).trim().toLowerCase();
  if (!key) return "Auto-detected";
  if (FRIENDLY[key]) return FRIENDLY[key];

  // Fallback: titlecase the unknown value with underscores → spaces.
  // Avoids any scanner brand we forgot leaking through verbatim.
  const cleaned = key.replace(/[_\-]+/g, " ");
  // If the cleaned label still contains a known brand substring,
  // suppress it entirely — better to label generically than to expose
  // the third-party tool.
  const SUPPRESSED = ["shodan", "nmap", "nuclei", "sslyze", "censys", "virustotal", "abuseipdb"];
  if (SUPPRESSED.some((s) => cleaned.includes(s))) return "Auto-detected";
  return cleaned.replace(/\b\w/g, (c) => c.toUpperCase());
}
