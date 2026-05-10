// app/(unauthenticated)/tools/tools-config.ts
// Authoritative list of public lookup tools surfaced on /tools.
// 9 entries; cert-hash is intentionally not in the displayed accordion
// (niche, hash input is awkward for SEO). Endpoint stays callable.

import type { ComponentType, SVGProps } from "react";
import {
  FileText, Globe, Mail, Shield, Lock, RefreshCcw, FileSearch, Github,
} from "lucide-react";

export type ToolInputKind = "domain" | "ip" | "url-or-domain" | "hash";

export type ToolConfig = {
  id: string;
  /** Endpoint suffix — full URL is `${API_BASE}/tools/public/${endpoint}`. */
  endpoint: string;
  name: string;
  shortName: string;
  description: string;
  inputKind: ToolInputKind;
  /** Body field name expected by the backend. */
  inputField: string;
  placeholder: string;
  icon: ComponentType<SVGProps<SVGSVGElement>>;
  iconColor: string;
  /** Hidden from the visible accordion when true. Endpoint still callable. */
  hidden?: boolean;
};

export const TOOLS: ToolConfig[] = [
  {
    id: "whois",
    endpoint: "whois",
    name: "WHOIS Lookup",
    shortName: "WHOIS",
    description: "Registrar, expiry date, contacts, and nameservers for any domain or IP.",
    inputKind: "domain",
    inputField: "query",
    placeholder: "example.com / 8.8.8.8 / AS13335",
    icon: FileText,
    iconColor: "text-rose-400",
  },
  {
    id: "dns-lookup",
    endpoint: "dns-lookup",
    name: "DNS Lookup",
    shortName: "DNS",
    description: "A, AAAA, MX, NS, TXT, and CNAME records — what every resolver sees.",
    inputKind: "domain",
    inputField: "domain",
    placeholder: "example.com",
    icon: Globe,
    iconColor: "text-cyan-400",
  },
  {
    id: "email-security",
    endpoint: "email-security",
    name: "Email Security Check",
    shortName: "Email",
    description: "SPF, DKIM, and DMARC presence — graded so you know what's missing.",
    inputKind: "domain",
    inputField: "domain",
    placeholder: "example.com",
    icon: Mail,
    iconColor: "text-amber-400",
  },
  {
    id: "header-check",
    endpoint: "header-check",
    name: "HTTP Header Check",
    shortName: "Headers",
    description: "Security headers, cookie flags, and a letter-grade verdict.",
    inputKind: "url-or-domain",
    inputField: "domain",
    placeholder: "https://example.com or example.com",
    icon: Shield,
    iconColor: "text-amber-400",
  },
  {
    id: "cert-lookup",
    endpoint: "cert-lookup",
    name: "Certificate Lookup",
    shortName: "Cert",
    description: "Active certs from CT logs — issuer, expiry, SAN list, all certs covering the domain.",
    inputKind: "domain",
    inputField: "domain",
    placeholder: "example.com",
    icon: Lock,
    iconColor: "text-emerald-400",
  },
  {
    id: "reverse-dns",
    endpoint: "reverse-dns",
    name: "Reverse DNS Lookup",
    shortName: "Reverse DNS",
    description: "Hostnames pointing at a given IP — useful for asset attribution.",
    inputKind: "ip",
    inputField: "ip",
    placeholder: "8.8.8.8",
    icon: RefreshCcw,
    iconColor: "text-purple-400",
  },
  {
    id: "sensitive-paths",
    endpoint: "sensitive-paths",
    name: "Sensitive Paths Probe",
    shortName: "Paths",
    description: "Looks for exposed admin panels, env files, and other commonly-leaked paths.",
    inputKind: "domain",
    inputField: "domain",
    placeholder: "example.com",
    icon: FileSearch,
    iconColor: "text-orange-400",
  },
  {
    id: "github-leaks",
    endpoint: "github-leaks",
    name: "GitHub Leak Search",
    shortName: "GitHub",
    description: "Search GitHub code for secrets and config referencing a domain — surface what's already public.",
    inputKind: "domain",
    inputField: "domain",
    placeholder: "example.com",
    icon: Github,
    iconColor: "text-pink-400",
  },
  // Hidden — kept so the smart cert-lookup hash detection still has an
  // endpoint to hit. Not surfaced on the accordion.
  {
    id: "cert-hash",
    endpoint: "cert-hash",
    name: "Certificate Hash Lookup",
    shortName: "Hash",
    description: "Look up a cert by SHA-256 fingerprint.",
    inputKind: "hash",
    inputField: "hash",
    placeholder: "sha256 hex",
    icon: Lock,
    iconColor: "text-emerald-400",
    hidden: true,
  },
];

export const VISIBLE_TOOLS = TOOLS.filter((t) => !t.hidden);
