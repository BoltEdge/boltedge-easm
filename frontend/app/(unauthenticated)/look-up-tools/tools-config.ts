// app/(unauthenticated)/look-up-tools/tools-config.ts
// Authoritative list of public lookup tools surfaced on /look-up-tools.
// 9 entries; cert-hash is intentionally not in the displayed grid (niche,
// hash input is awkward for SEO). Endpoint stays callable.
//
// Visual fields (`iconColor`, `tint`, `ring`) are full Tailwind class
// strings rather than computed — Tailwind's compiler scans source files
// for literal class names, so anything templated would be stripped.

import type { ComponentType, SVGProps } from "react";
import {
  FileText, Globe, Mail, Shield, Lock, RefreshCcw, FileSearch, Github, Plug,
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
  /** Tailwind text-* class for the icon + accent text. */
  iconColor: string;
  /** Tailwind bg-* class for the tinted card background + icon square. */
  tint: string;
  /** Tailwind border-* class for the card outline. */
  ring: string;
  /** Hidden from the visible grid when true. Endpoint still callable. */
  hidden?: boolean;
  /** Surface the card on /look-up-tools as a sign-in teaser instead of an
   *  input form. Use for tools that should be account-only on the public
   *  surface (e.g. connectivity probes, leak search). */
  authOnly?: boolean;
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
    iconColor: "text-rose-300",
    tint: "bg-rose-500/[0.04]",
    ring: "border-rose-500/20",
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
    iconColor: "text-cyan-300",
    tint: "bg-cyan-500/[0.04]",
    ring: "border-cyan-500/20",
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
    iconColor: "text-amber-300",
    tint: "bg-amber-500/[0.04]",
    ring: "border-amber-500/20",
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
    iconColor: "text-sky-300",
    tint: "bg-sky-500/[0.04]",
    ring: "border-sky-500/20",
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
    iconColor: "text-emerald-300",
    tint: "bg-emerald-500/[0.04]",
    ring: "border-emerald-500/20",
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
    iconColor: "text-purple-300",
    tint: "bg-purple-500/[0.04]",
    ring: "border-purple-500/20",
  },
  {
    id: "connectivity-check",
    endpoint: "connectivity-check",
    name: "Connectivity Check",
    shortName: "Connectivity",
    description: "TCP port reachability, latency, banner grabs, and TLS detection.",
    inputKind: "domain",
    inputField: "host",
    placeholder: "example.com:443",
    icon: Plug,
    iconColor: "text-violet-300",
    tint: "bg-violet-500/[0.04]",
    ring: "border-violet-500/20",
    authOnly: true,
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
    iconColor: "text-orange-300",
    tint: "bg-orange-500/[0.04]",
    ring: "border-orange-500/20",
    authOnly: true,
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
    iconColor: "text-pink-300",
    tint: "bg-pink-500/[0.04]",
    ring: "border-pink-500/20",
    authOnly: true,
  },
  // Hidden — kept so the smart cert-lookup hash detection still has an
  // endpoint to hit. Not surfaced on the grid.
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
    iconColor: "text-emerald-300",
    tint: "bg-emerald-500/[0.04]",
    ring: "border-emerald-500/20",
    hidden: true,
  },
];

export const VISIBLE_TOOLS = TOOLS.filter((t) => !t.hidden);
