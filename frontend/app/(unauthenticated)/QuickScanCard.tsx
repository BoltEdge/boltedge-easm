"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Search, Sparkles, Lock, ArrowRight } from "lucide-react";

import {
  quickScanAsset,
  publicExplainFinding,
  type FindingExplanation,
  type PublicFindingType,
} from "../lib/api";
import TurnstileWidget from "./TurnstileWidget";

const TURNSTILE_ENABLED = !!process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY;

type Severity = "critical" | "high" | "medium" | "low" | "info";

type QuickScanFinding = {
  title?: string;
  description?: string;
  severity?: Severity | string;
  finding_type?: string;
  source?: string;
  details_json?: {
    ip?: string;
    port?: number;
    transport?: string;
    product?: string;
    version?: string;
    cve?: string;
    cvss?: number;
    service_label?: string;
    [k: string]: any;
  };
  [k: string]: any;
};

type QuickScanRawResponse = {
  status?: string;
  assetType?: string;
  assetValue?: string;
  summary?: { ips_scanned?: string[]; resolved_ips?: string[]; errors?: Array<{ ip: string; error: string }>; [k: string]: any };
  risk?: { maxSeverity?: string; totalFindings?: number; counts?: Record<string, number> };
  findings?: QuickScanFinding[];
  maxSeverity?: string;
  totalFindings?: number;
  ipsScanned?: string[];
  errors?: Array<{ ip: string; error: string }>;
  counts?: Record<string, number>;
  [k: string]: any;
};

type QuickScanNormalized = {
  assetType: "domain" | "ip";
  assetValue: string;
  maxSeverity: Severity;
  totalFindings: number;
  counts: Record<Severity, number>;
  ipsScanned: string[];
  errors: Array<{ ip: string; error: string }>;
  findings: QuickScanFinding[];
};

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const ALLOWED_PUBLIC_TYPES = new Set<string>(["service_exposure", "risky_port", "cve"]);

function toSeverity(x: any): Severity {
  const s = String(x ?? "info").toLowerCase();
  if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info") return s;
  return "info";
}

function MaxSeverityBadge({ severity }: { severity: Severity | string }) {
  const cls = useMemo(() => {
    const s = String(severity || "info").toLowerCase();
    if (s === "critical") return "bg-red-500/15 text-red-300 border-red-500/30";
    if (s === "high") return "bg-orange-500/15 text-orange-300 border-orange-500/30";
    if (s === "medium") return "bg-yellow-500/15 text-yellow-200 border-yellow-500/30";
    if (s === "low") return "bg-green-500/15 text-green-300 border-green-500/30";
    return "bg-cyan-500/15 text-cyan-300 border-cyan-500/30";
  }, [severity]);
  return (
    <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium ${cls}`}>
      <span className="inline-block h-2 w-2 rounded-full bg-current opacity-80" />
      Max: {String(severity || "info").toUpperCase()}
    </span>
  );
}

function SeverityPill({ label, value }: { label: Severity; value: number }) {
  const cls = useMemo(() => {
    const s = label.toLowerCase();
    if (s === "critical") return "border-purple-500/35 text-purple-200 bg-purple-500/10";
    if (s === "high") return "border-red-500/30 text-red-200 bg-red-500/10";
    if (s === "medium") return "border-amber-500/30 text-amber-100 bg-amber-500/10";
    if (s === "low") return "border-yellow-400/20 text-yellow-100 bg-yellow-400/5";
    return "border-slate-400/20 text-slate-200 bg-slate-400/5";
  }, [label]);
  return (
    <span className={`inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-xs ${cls}`}>
      <span className="font-semibold uppercase">{label}</span>
      <span className="font-mono">{value}</span>
    </span>
  );
}

function SeverityBadge({ severity }: { severity: Severity | string }) {
  const s = toSeverity(severity);
  const base = "inline-flex items-center rounded-md border px-2.5 py-1 text-[11px] font-semibold uppercase min-w-[72px] justify-center";
  const styles: Record<Severity, string> = {
    critical: "bg-purple-500/20 border-purple-500/35 text-purple-100",
    high: "bg-red-500/15 border-red-500/30 text-red-200",
    medium: "bg-amber-500/15 border-amber-500/30 text-amber-100",
    low: "bg-yellow-400/10 border-yellow-400/20 text-yellow-100",
    info: "bg-slate-400/10 border-slate-400/20 text-slate-200",
  };
  return <span className={`${base} ${styles[s]}`}>{s}</span>;
}

function getEvidenceChips(f: QuickScanFinding): string[] {
  const d = f.details_json || {};
  const chips: string[] = [];
  if (d.ip && d.port) {
    chips.push(`${d.ip}:${d.port}/${(d.transport ?? "tcp").toLowerCase()}`);
  } else if (d.port) {
    chips.push(`port ${d.port}/${(d.transport ?? "tcp").toLowerCase()}`);
  }
  const pv = [d.product, d.version].filter(Boolean).join(" ");
  if (pv) chips.push(pv);
  if (d.cve) chips.push(String(d.cve) + (d.cvss ? ` (CVSS ${d.cvss})` : ""));
  return chips;
}

// Pick the highest-severity finding for the featured Nano AI panel.
// Severity rank wins; on tie, the first finding in the returned order wins.
function pickTopFinding(findings: QuickScanFinding[]): QuickScanFinding | null {
  if (!findings.length) return null;
  const sevIdx = (s: any) => SEV_ORDER.indexOf(toSeverity(s));
  let best = findings[0];
  let bestSev = sevIdx(best.severity);
  for (let i = 1; i < findings.length; i++) {
    const sev = sevIdx(findings[i].severity);
    if (sev < bestSev) {
      best = findings[i];
      bestSev = sev;
    }
  }
  return best;
}

// Trim a paragraph to the first N sentences for the compact card layout.
// Falls back to the full string if it's already short.
function shortenParagraph(text: string | undefined, sentenceCap = 2): string {
  if (!text) return "";
  const trimmed = text.trim();
  if (trimmed.length < 220) return trimmed;
  const parts = trimmed.split(/(?<=[.!?])\s+/);
  return parts.slice(0, sentenceCap).join(" ").trim();
}

type QuickScanCardProps = {
  /** Notifies the parent when the card has results to show, so the page can
   *  expand the card to full width and tuck away the sibling tool cards. */
  onActiveChange?: (active: boolean) => void;
  /** When provided alongside `onTokenConsumed`, the parent owns the
   *  Turnstile widget — the card uses the parent's token, calls back
   *  on consumption, and does not render its own widget. Used by
   *  QuickToolsSection so all three landing-page cards share a single
   *  widget. Standalone pages omit these and the card falls back to
   *  managing Turnstile locally. */
  turnstileToken?: string | null;
  onTokenConsumed?: () => void;
};

export default function QuickScanCard({
  onActiveChange,
  turnstileToken: externalToken,
  onTokenConsumed: externalConsume,
}: QuickScanCardProps = {}) {
  const [type, setType] = useState<"domain" | "ip">("domain");
  const [value, setValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<{ message: string; code?: string } | null>(null);
  const [result, setResult] = useState<QuickScanNormalized | null>(null);

  // Nano EASM Assistant explanation for the top finding (user-initiated — fetched only on click)
  const [explanation, setExplanation] = useState<FindingExplanation | null>(null);
  const [explanationLoading, setExplanationLoading] = useState(false);
  const [explanationError, setExplanationError] = useState<string | null>(null);

  // Cloudflare Turnstile — when the parent manages it (externalConsume is
  // defined), use parent props. Otherwise fall back to local state and
  // render our own widget below.
  const externalManaged = externalConsume != null;
  const [localToken, setLocalToken] = useState<string | null>(null);
  const [widgetKey, setWidgetKey] = useState(0);
  const turnstileToken = externalManaged ? externalToken ?? null : localToken;
  const consumeToken = externalManaged
    ? externalConsume
    : () => {
        setLocalToken(null);
        setWidgetKey((k) => k + 1);
      };

  const canScan = value.trim().length > 0 && !loading && (!TURNSTILE_ENABLED || !!turnstileToken);

  const onScan = async () => {
    if (!canScan) return;
    try {
      setLoading(true);
      setError(null);
      setResult(null);
      setExplanation(null);
      setExplanationError(null);
      const res = (await quickScanAsset({
        type,
        value: value.trim(),
        turnstileToken: turnstileToken ?? undefined,
      })) as QuickScanRawResponse;
      const rawCounts =
        (res?.risk?.counts as Record<string, number> | undefined) ??
        (res?.counts as Record<string, number> | undefined) ??
        { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      const normalized: QuickScanNormalized = {
        assetType: ((res?.assetType as any) ?? type) === "ip" ? "ip" : "domain",
        assetValue: String(res?.assetValue ?? value.trim()),
        maxSeverity: toSeverity(res?.risk?.maxSeverity ?? res?.maxSeverity ?? "info"),
        totalFindings:
          typeof res?.risk?.totalFindings === "number"
            ? res.risk.totalFindings
            : typeof res?.totalFindings === "number"
              ? res.totalFindings
              : 0,
        counts: {
          critical: Number(rawCounts.critical ?? 0),
          high: Number(rawCounts.high ?? 0),
          medium: Number(rawCounts.medium ?? 0),
          low: Number(rawCounts.low ?? 0),
          info: Number(rawCounts.info ?? 0),
        },
        ipsScanned: Array.isArray(res?.summary?.ips_scanned)
          ? (res.summary!.ips_scanned as string[])
          : Array.isArray(res?.summary?.resolved_ips)
            ? (res.summary!.resolved_ips as string[])
            : Array.isArray(res?.ipsScanned)
              ? (res.ipsScanned as string[])
              : [],
        errors: Array.isArray(res?.summary?.errors)
          ? (res.summary!.errors as Array<{ ip: string; error: string }>)
          : Array.isArray(res?.errors)
            ? (res.errors as Array<{ ip: string; error: string }>)
            : [],
        findings: Array.isArray(res?.findings) ? (res.findings as QuickScanFinding[]) : [],
      };
      if (normalized.totalFindings === 0 && normalized.findings.length > 0) {
        normalized.totalFindings = normalized.findings.length;
      }
      setResult(normalized);
    } catch (e: any) {
      setError({
        message: e?.message || "Quick scan failed",
        code: e?.payload?.code,
      });
    } finally {
      setLoading(false);
      // The token is consumed by the verify call regardless of scan
      // outcome — remount the widget for a fresh challenge.
      consumeToken();
    }
  };

  const topFinding = useMemo(() => (result ? pickTopFinding(result.findings) : null), [result]);
  const otherFindings = useMemo(() => {
    if (!result) return [];
    if (!topFinding) return result.findings;
    return result.findings.filter((f) => f !== topFinding);
  }, [result, topFinding]);

  // Reset the explanation state whenever the scan result changes, so a stale
  // explanation from a previous target doesn't linger when a new scan lands.
  useEffect(() => {
    setExplanation(null);
    setExplanationError(null);
    setExplanationLoading(false);
  }, [result]);

  // Tell the parent (QuickToolsSection) whether this card has results to
  // render, so it can expand to full width and tuck away the sibling cards.
  useEffect(() => {
    onActiveChange?.(result !== null);
  }, [result, onActiveChange]);

  // User-initiated: visitor clicks the "Explain with Nano EASM Assistant"
  // button to fetch the explanation. We deliberately don't auto-fetch — it
  // saves a backend call when the visitor isn't interested, and putting
  // the visitor in control of depth is better UX in a narrow card.
  const fetchExplanation = async () => {
    if (!result || !topFinding) return;
    const ft = String(topFinding.finding_type || "").toLowerCase();
    if (!ALLOWED_PUBLIC_TYPES.has(ft)) {
      setExplanationError("This finding type isn't supported by the public assistant yet.");
      return;
    }
    try {
      setExplanationLoading(true);
      setExplanationError(null);
      const res = await publicExplainFinding({
        findingType: ft as PublicFindingType,
        assetValue: result.assetValue,
        detailsJson: topFinding.details_json || {},
        turnstileToken: turnstileToken ?? undefined,
      });
      setExplanation(res?.explanation ?? null);
    } catch (e: any) {
      setExplanationError(e?.message || "Could not load the explanation.");
    } finally {
      setExplanationLoading(false);
      consumeToken();
    }
  };

  const ipsText = useMemo(() => {
    if (!result?.ipsScanned?.length) return "—";
    return result.ipsScanned.join(", ");
  }, [result]);

  return (
    <div className="rounded-2xl border border-border bg-card/40 backdrop-blur overflow-hidden h-full flex flex-col shadow-[0_0_80px_rgba(139,92,246,0.08)]">
      {/* Header */}
      <div className="px-6 pt-6 pb-4">
        <div className="flex items-center gap-2 mb-1">
          <Search className="w-5 h-5 text-primary" />
          <h3 className="text-sm font-semibold text-foreground">Quick Asset Scan</h3>
        </div>
        <p className="text-xs text-muted-foreground">Scan any domain or IP — no account needed</p>
      </div>

      {/* Inputs */}
      <div className="px-6 pb-4">
        <div className="grid grid-cols-[100px_1fr] gap-2">
          <select
            value={type}
            onChange={(e) => setType(e.target.value as any)}
            className="h-10 w-full rounded-lg border border-border bg-background px-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/40"
          >
            <option value="domain">Domain</option>
            <option value="ip">IP</option>
          </select>
          <input
            type="text"
            placeholder={type === "ip" ? "e.g., 8.8.8.8" : "e.g., example.com"}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onScan();
            }}
            className="h-10 w-full rounded-lg border border-border bg-background px-3 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/40"
          />
        </div>
        {!externalManaged && TURNSTILE_ENABLED && (
          <div className="mt-3">
            <TurnstileWidget
              key={widgetKey}
              onVerify={setLocalToken}
              onExpire={() => setLocalToken(null)}
              onError={() => setLocalToken(null)}
            />
          </div>
        )}
        <button
          onClick={onScan}
          disabled={!canScan}
          className={`w-full mt-3 rounded-lg px-4 py-2.5 text-sm font-medium transition-all ${
            !canScan
              ? "bg-muted text-muted-foreground cursor-not-allowed"
              : "bg-primary text-primary-foreground hover:bg-primary/90"
          }`}
        >
          {loading ? "Scanning…" : "Scan now"}
        </button>
        <p className="mt-2 text-[11px] text-muted-foreground/60 text-center">
          <Link href="/register" className="underline hover:text-muted-foreground">Sign in</Link> for deeper scans and richer findings
        </p>
      </div>

      {error && (
        <div className="mx-6 mb-4 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">
          {error.code === "RATE_LIMITED" ? (
            <div>
              <p>{error.message.replace(/\s*Sign up for free.*$/i, "").trim()}</p>
              <Link
                href="/register"
                className="mt-1.5 inline-flex items-center gap-1 text-xs font-semibold text-teal-300 hover:text-teal-200 transition-colors"
              >
                Sign up free for more scans <ArrowRight className="w-3 h-3" />
              </Link>
            </div>
          ) : (
            error.message
          )}
        </div>
      )}

      {/* Results panel */}
      <div className="px-6 pb-6 flex-1">
        <div className="rounded-xl border border-border bg-background/30 p-4 h-full flex flex-col">
          {/* Header row */}
          <div className="flex items-center justify-between gap-3 mb-3">
            <div className="text-xs font-semibold text-foreground">Scan results</div>
            {result ? (
              <MaxSeverityBadge severity={result.maxSeverity} />
            ) : (
              <div className="text-[11px] text-muted-foreground">Run a scan to see results</div>
            )}
          </div>

          {/* Counts */}
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg border border-border bg-card/30 p-3">
              <div className="text-[11px] text-muted-foreground">Total findings</div>
              <div className="mt-1 text-lg font-semibold text-foreground">{result ? result.totalFindings : "—"}</div>
            </div>
            <div className="rounded-lg border border-border bg-card/30 p-3">
              <div className="text-[11px] text-muted-foreground">IPs scanned</div>
              <div className="mt-1 text-sm font-mono text-foreground break-words">{ipsText}</div>
            </div>
          </div>

          {/* Severity pills */}
          {result && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => (
                <SeverityPill key={s} label={s} value={result.counts[s] ?? 0} />
              ))}
            </div>
          )}

          {/* Featured top-finding panel.
              The Nano EASM Assistant explanation is opt-in — the visitor
              clicks the button below to fetch it. Avoids spending a backend
              call on visitors who only skim the title, and gives them
              control over how deep they want to go in this narrow card. */}
          {result && topFinding && (
            <div className="mt-4 rounded-xl border border-teal-500/25 bg-gradient-to-br from-teal-500/[0.06] via-transparent to-transparent p-3 relative overflow-hidden">
              <div className="absolute top-0 right-0 w-32 h-32 bg-teal-500/[0.06] rounded-full blur-2xl pointer-events-none" />
              <div className="relative">
                <div className="text-[10px] font-bold uppercase tracking-wider text-teal-400 mb-2">Top finding</div>

                <div className="flex items-start gap-2 mb-3">
                  <SeverityBadge severity={String(topFinding.severity ?? "info")} />
                  <div className="min-w-0 flex-1">
                    <div className="text-xs font-semibold text-foreground leading-snug">{topFinding.title || "Finding"}</div>
                    {getEvidenceChips(topFinding).length > 0 && (
                      <div className="mt-1 flex flex-wrap gap-1">
                        {getEvidenceChips(topFinding).map((chip, idx) => (
                          <span
                            key={idx}
                            className="inline-flex rounded border border-border bg-card/40 px-1.5 py-0.5 text-[10px] text-muted-foreground font-mono"
                          >
                            {chip}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Assistant CTA / explanation slot */}
                {!explanation && !explanationLoading && (
                  <button
                    type="button"
                    onClick={fetchExplanation}
                    disabled={TURNSTILE_ENABLED && !turnstileToken}
                    className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg border border-teal-500/40 bg-teal-500/[0.08] px-3 py-2 text-[11px] font-semibold text-teal-300 hover:bg-teal-500/[0.14] hover:text-teal-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    Explain with Nano EASM Assistant
                  </button>
                )}
                {explanationLoading && (
                  <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground italic">
                    <Sparkles className="w-3.5 h-3.5 text-teal-400 animate-pulse" />
                    Nano EASM Assistant is generating an explanation…
                  </div>
                )}
                {explanationError && !explanationLoading && (
                  <div className="text-[11px] text-amber-300/90">{explanationError}</div>
                )}
                {explanation && (
                  <div className="space-y-2 text-[11px] leading-relaxed">
                    <div className="flex items-center gap-1.5 -mt-1 mb-1">
                      <Sparkles className="w-3.5 h-3.5 text-teal-400" />
                      <span className="text-[10px] font-bold uppercase tracking-wider text-teal-400">Nano EASM Assistant</span>
                    </div>
                    {(explanation.summary || explanation.clientSummary) && (
                      <p className="text-foreground/90">{explanation.summary || explanation.clientSummary}</p>
                    )}
                    {explanation.technicalExplanation && (
                      <div>
                        <div className="text-[10px] font-semibold uppercase tracking-wider text-teal-400/80 mb-0.5">Why it matters</div>
                        <p className="text-muted-foreground">{shortenParagraph(explanation.technicalExplanation, 2)}</p>
                      </div>
                    )}
                    {explanation.remediation && (
                      <div>
                        <div className="text-[10px] font-semibold uppercase tracking-wider text-teal-400/80 mb-0.5">How to fix</div>
                        <p className="text-muted-foreground">{shortenParagraph(explanation.remediation, 2)}</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Other findings — compact rows, no expand */}
          {result && otherFindings.length > 0 && (
            <div className="mt-4 flex-1 overflow-auto">
              <div className="text-xs font-semibold text-foreground mb-2">Other findings ({otherFindings.length})</div>
              <div className="space-y-1.5">
                {otherFindings.map((f, idx) => {
                  const chips = getEvidenceChips(f);
                  return (
                    <div key={idx} className="flex items-start gap-2 rounded-md border border-border bg-card/20 px-2.5 py-2">
                      <SeverityBadge severity={String(f.severity ?? "info")} />
                      <div className="min-w-0 flex-1">
                        <div className="text-[11px] font-medium text-foreground truncate">{f.title || "Finding"}</div>
                        {chips.length > 0 && (
                          <div className="mt-0.5 text-[10px] text-muted-foreground font-mono truncate">{chips.join(" · ")}</div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* CTA — copy adapts to findings count */}
          {result && (
            <div className="mt-4 rounded-xl border border-teal-500/25 bg-teal-500/[0.04] p-3">
              <div className="flex items-start gap-2">
                <Lock className="w-4 h-4 text-teal-400 mt-0.5 shrink-0" />
                <div className="flex-1 min-w-0">
                  {result.findings.length === 0 ? (
                    <p className="text-[11px] text-foreground/80 leading-relaxed">
                      Nothing publicly exposed worth flagging from this snapshot. Sign up free to map your full external surface and get alerted when new exposures appear.
                    </p>
                  ) : result.findings.length === 1 ? (
                    <p className="text-[11px] text-foreground/80 leading-relaxed">
                      You&apos;ve seen this finding explained in detail. Sign up free to monitor for new exposures and changes over time.
                    </p>
                  ) : (
                    <p className="text-[11px] text-foreground/80 leading-relaxed">
                      You&apos;ve seen the top finding explained in detail. Sign up free to get the same depth on the other{" "}
                      <strong>{otherFindings.length}</strong> finding{otherFindings.length === 1 ? "" : "s"}, plus continuous
                      monitoring and alerts when things change.
                    </p>
                  )}
                  <Link
                    href="/register"
                    className="mt-2 inline-flex items-center gap-1 text-[11px] font-semibold text-teal-400 hover:text-teal-300 transition-colors"
                  >
                    Create free account <ArrowRight className="w-3 h-3" />
                  </Link>
                </div>
              </div>
            </div>
          )}

          {/* Scan errors (best-effort surface) */}
          {result && result.errors.length > 0 && (
            <div className="mt-3 rounded-lg border border-border bg-card/30 p-3">
              <div className="text-[10px] font-semibold text-foreground mb-1">Scan errors</div>
              <ul className="space-y-0.5 text-[10px] text-muted-foreground">
                {result.errors.map((e, idx) => (
                  <li key={`${e.ip}-${idx}`} className="font-mono break-words">{e.ip}: {e.error}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
