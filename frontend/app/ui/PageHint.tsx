"use client";

// =============================================================================
// PageHint — small, dismissible "what is this page for?" card.
//
// Goals:
//   - Quiet by default. One sentence, one optional inline action, an X.
//   - Permanent dismiss per browser via localStorage. No DB, no schema, no
//     "you've seen this on Chrome, why is it back on Firefox?" plumbing.
//   - User can bring it back from a single small "?" button in the page
//     header (rendered separately via <PageHintToggle>).
//   - Never re-prompts. If a user dismisses, the card stays gone unless they
//     re-open it explicitly.
//
// Usage:
//   <PageHint
//     pageKey="findings"
//     title="Findings"
//     body="Vulnerabilities discovered across your assets. Triage by severity, mark as resolved, or export."
//     action={{ label: "Filter by critical", href: "/findings?severity=critical" }}
//   />
//
// To render a re-show button in the header:
//   <PageHintToggle pageKey="findings" />
// =============================================================================

import React, { useEffect, useState, useCallback } from "react";
import { HelpCircle, X, ArrowRight } from "lucide-react";
import Link from "next/link";

const STORAGE_PREFIX = "asm_hint_dismissed_";

function storageKey(pageKey: string) {
  return `${STORAGE_PREFIX}${pageKey}`;
}

function readDismissed(pageKey: string): boolean {
  if (typeof window === "undefined") return true; // SSR: render nothing initially
  try {
    return window.localStorage.getItem(storageKey(pageKey)) === "1";
  } catch {
    return false;
  }
}

function writeDismissed(pageKey: string, dismissed: boolean) {
  if (typeof window === "undefined") return;
  try {
    if (dismissed) {
      window.localStorage.setItem(storageKey(pageKey), "1");
    } else {
      window.localStorage.removeItem(storageKey(pageKey));
    }
    // Notify same-tab listeners so PageHintToggle can rerender.
    window.dispatchEvent(new CustomEvent("asm-hint-changed", { detail: { pageKey } }));
  } catch {
    /* noop — private browsing, etc. */
  }
}

type PageHintProps = {
  pageKey: string;
  title: string;
  body: string;
  action?: { label: string; href: string };
};

export function PageHint({ pageKey, title, body, action }: PageHintProps) {
  // Start hidden so SSR + first paint don't flash a hint that's already
  // dismissed. Effect resolves the actual state from localStorage.
  const [visible, setVisible] = useState(false);

  const sync = useCallback(() => {
    setVisible(!readDismissed(pageKey));
  }, [pageKey]);

  useEffect(() => {
    sync();
    function onChange(e: Event) {
      const detail = (e as CustomEvent).detail;
      if (detail?.pageKey === pageKey) sync();
    }
    window.addEventListener("asm-hint-changed", onChange);
    return () => window.removeEventListener("asm-hint-changed", onChange);
  }, [pageKey, sync]);

  if (!visible) return null;

  return (
    <div className="mb-5 rounded-lg border border-primary/20 bg-primary/5 px-4 py-3 flex items-start gap-3">
      <HelpCircle className="w-4 h-4 text-primary mt-0.5 shrink-0" />
      <div className="flex-1 min-w-0 text-sm">
        <p className="text-foreground">
          <span className="font-medium">{title}.</span>{" "}
          <span className="text-muted-foreground">{body}</span>
        </p>
        {action && (
          <Link
            href={action.href}
            className="inline-flex items-center gap-1 mt-1.5 text-xs text-primary hover:underline"
          >
            {action.label}
            <ArrowRight className="w-3 h-3" />
          </Link>
        )}
      </div>
      <button
        type="button"
        aria-label="Dismiss"
        onClick={() => writeDismissed(pageKey, true)}
        className="text-muted-foreground hover:text-foreground transition-colors shrink-0"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  );
}

// Small "?" button next to the page title. Always visible — clicking
// toggles the hint card open / closed. We always show it (rather than
// only when dismissed) so users discover it exists in the first place,
// and so it remains a stable affordance once they're used to it.
export function PageHintToggle({ pageKey }: { pageKey: string }) {
  const [dismissed, setDismissed] = useState(false);

  const sync = useCallback(() => {
    setDismissed(readDismissed(pageKey));
  }, [pageKey]);

  useEffect(() => {
    sync();
    function onChange(e: Event) {
      const detail = (e as CustomEvent).detail;
      if (detail?.pageKey === pageKey) sync();
    }
    window.addEventListener("asm-hint-changed", onChange);
    return () => window.removeEventListener("asm-hint-changed", onChange);
  }, [pageKey, sync]);

  return (
    <button
      type="button"
      aria-label={dismissed ? "Show hint" : "Hide hint"}
      title={dismissed ? "Show hint" : "Hide hint"}
      onClick={() => writeDismissed(pageKey, !dismissed)}
      className={`inline-flex items-center justify-center w-7 h-7 rounded-full transition-colors ${
        dismissed
          ? "text-muted-foreground hover:text-foreground hover:bg-card/60"
          : "text-primary hover:bg-primary/10"
      }`}
    >
      <HelpCircle className="w-4 h-4" />
    </button>
  );
}
