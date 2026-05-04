"use client";

// =============================================================================
// OnboardingTour — opt-in guided walkthrough for first-time users.
//
// Flow:
//   1. On the user's first authenticated render, a small "Want a quick
//      tour?" card slides in from the bottom-right.
//   2. If they click "Sure", a floating card appears next to the first
//      sidebar item and a pulsing teal ring highlights it. Each
//      "Next →" click slides the card to the next target.
//   3. "Skip" / "Got it!" / closing the prompt all set the same
//      localStorage flag — the tour is shown at most once. Never
//      reprompts on subsequent sessions.
//
// Targets are <li data-tour-target="..."> elements in Sidebar.tsx.
// We intentionally keep the steps short (4) and tied to the actual
// happy path (Assets → Discovery → Scan → Monitoring) instead of
// touring every feature — a long tour is a tour nobody finishes.
// =============================================================================

import React, { useEffect, useState, useCallback } from "react";
import { ArrowRight, X, Sparkles } from "lucide-react";

const STORAGE_KEY = "asm_tour_seen_v1";

// Window event other components dispatch to relaunch the tour
// without clearing localStorage manually. Used by the "Replay tour"
// item in the TopBar user menu.
export const REPLAY_TOUR_EVENT = "asm-replay-tour";

export function replayOnboardingTour(): void {
  if (typeof window === "undefined") return;
  try { window.localStorage.removeItem(STORAGE_KEY); } catch { /* noop */ }
  window.dispatchEvent(new CustomEvent(REPLAY_TOUR_EVENT));
}

type TourStep = {
  /** Matches the `data-tour-target` attribute on a sidebar <li>. */
  target: string;
  title: string;
  body: string;
};

const STEPS: TourStep[] = [
  {
    target: "assets",
    title: "Start with an asset",
    body: "Add a domain or IP you own. Everything else hangs off this — discovery, scans, monitoring.",
  },
  {
    target: "discovery",
    title: "See what's exposed",
    body: "Find subdomains, IPs, and services for your root domain. Newly found assets can be added straight to your inventory.",
  },
  {
    target: "scanning",
    title: "Run a scan",
    body: "Pick a profile (Quick / Standard / Deep / Full) and target an asset or group. Findings come with severity, CWE, and remediation.",
  },
  {
    target: "monitoring",
    title: "Watch for changes",
    body: "Re-scan on a schedule and get alerted on new ports, expired certs, or fresh findings.",
  },
];

type Phase = "checking" | "prompt" | "tour" | "done";

export function OnboardingTour() {
  const [phase, setPhase] = useState<Phase>("checking");
  const [stepIndex, setStepIndex] = useState(0);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);

  const dismissForever = useCallback(() => {
    try { window.localStorage.setItem(STORAGE_KEY, "1"); } catch { /* noop */ }
    setPhase("done");
  }, []);

  // First-render gate. We deliberately check localStorage in an
  // effect (not lazily during state init) so the SSR / hydration
  // path can't render the prompt for a returning user before
  // localStorage is consulted.
  useEffect(() => {
    if (typeof window === "undefined") return;
    let seen = false;
    try { seen = window.localStorage.getItem(STORAGE_KEY) === "1"; } catch { /* private mode */ }
    if (seen) {
      setPhase("done");
      return;
    }
    // Tiny delay so the layout (sidebar, top bar) settles before we
    // pop the prompt — otherwise it can flash in the wrong spot
    // during initial hydration.
    const t = window.setTimeout(() => setPhase("prompt"), 700);
    return () => window.clearTimeout(t);
  }, []);

  // Replay handler — listens for the "asm-replay-tour" event from
  // the TopBar user menu. We skip the opt-in prompt because the
  // user just explicitly clicked "Replay tour"; asking them again
  // would be silly. Resets to step 0.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const handler = () => {
      setStepIndex(0);
      setPhase("tour");
    };
    window.addEventListener(REPLAY_TOUR_EVENT, handler);
    return () => window.removeEventListener(REPLAY_TOUR_EVENT, handler);
  }, []);

  // Position the floating card next to the active step's target.
  // Recomputed on step change AND on window resize so a sidebar
  // collapse / window drag keeps the card glued to the right spot.
  useEffect(() => {
    if (phase !== "tour") return;
    if (typeof window === "undefined") return;
    const step = STEPS[stepIndex];

    const reposition = () => {
      const target = document.querySelector<HTMLElement>(
        `[data-tour-target="${step.target}"]`,
      );
      if (!target) {
        // Sidebar might be hidden (mobile collapse, tiny viewport) —
        // bail out cleanly instead of rendering the card in some
        // arbitrary corner.
        setPos(null);
        return;
      }
      const rect = target.getBoundingClientRect();
      // Place the card to the right of the sidebar item, vertically
      // centered. The card is ~320px wide; if it would clip the
      // viewport we fall back to placing it below the target.
      const cardWidth = 320;
      const margin = 14;
      const fitsRight = rect.right + margin + cardWidth < window.innerWidth;
      if (fitsRight) {
        setPos({
          top: rect.top + rect.height / 2,
          left: rect.right + margin,
        });
      } else {
        setPos({
          top: rect.bottom + margin,
          left: Math.max(margin, Math.min(rect.left, window.innerWidth - cardWidth - margin)),
        });
      }

      // Highlight the target. Removed in cleanup so the previous
      // step's spotlight doesn't linger when we move on.
      target.classList.add("asm-tour-spotlight");
      return () => target.classList.remove("asm-tour-spotlight");
    };

    const cleanup = reposition();
    window.addEventListener("resize", reposition);
    return () => {
      window.removeEventListener("resize", reposition);
      if (typeof cleanup === "function") cleanup();
      // Defensive: if the cleanup closure didn't fire (target became
      // null mid-step), make sure no spotlight survives.
      document.querySelectorAll(".asm-tour-spotlight").forEach((el) => {
        el.classList.remove("asm-tour-spotlight");
      });
    };
  }, [phase, stepIndex]);

  if (phase === "checking" || phase === "done") return null;

  // ── Phase 1: the opt-in prompt (bottom-right) ────────────────────
  if (phase === "prompt") {
    return (
      <>
        <SpotlightStyles />
        <div
          role="dialog"
          aria-label="Take a quick tour"
          className="fixed bottom-6 right-6 z-[60] w-[320px] rounded-2xl border border-primary/30 bg-card shadow-2xl p-4 animate-tour-in"
        >
          <div className="flex items-start gap-3">
            <div className="w-9 h-9 rounded-xl bg-primary/15 flex items-center justify-center shrink-0">
              <Sparkles className="w-4 h-4 text-primary" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-semibold text-foreground">
                Want a quick tour?
              </div>
              <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">
                4 steps · ~30 seconds. Shows the main flow: add an asset, discover, scan, monitor.
              </p>
              <div className="flex items-center gap-2 mt-3">
                <button
                  onClick={() => { setStepIndex(0); setPhase("tour"); }}
                  className="px-3 py-1.5 rounded-lg bg-primary text-primary-foreground text-xs font-semibold hover:bg-primary/90 transition-colors"
                >
                  Sure, show me
                </button>
                <button
                  onClick={dismissForever}
                  className="px-3 py-1.5 rounded-lg text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  No thanks
                </button>
              </div>
            </div>
            <button
              onClick={dismissForever}
              aria-label="Dismiss"
              className="text-muted-foreground hover:text-foreground transition-colors -mr-1 -mt-1"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      </>
    );
  }

  // ── Phase 2: the tour itself ─────────────────────────────────────
  // If we couldn't position the card (target hidden / off-screen),
  // bail out gracefully rather than rendering it in an arbitrary
  // corner. The user can always replay later if we add a re-trigger.
  if (!pos) return <SpotlightStyles />;

  const step = STEPS[stepIndex];
  const isLast = stepIndex === STEPS.length - 1;

  return (
    <>
      <SpotlightStyles />
      <div
        role="dialog"
        aria-label={`Tour step ${stepIndex + 1} of ${STEPS.length}: ${step.title}`}
        // The slide-between-targets animation lives here: changing
        // top/left triggers a smooth transform-driven move because
        // we transition the inset properties below.
        className="fixed z-[60] w-[320px] rounded-2xl border border-primary/30 bg-card shadow-2xl p-4 transition-all duration-300 ease-out -translate-y-1/2"
        style={{ top: pos.top, left: pos.left }}
      >
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-primary">
            Step {stepIndex + 1} of {STEPS.length}
          </span>
          <button
            onClick={dismissForever}
            aria-label="Skip tour"
            className="text-muted-foreground hover:text-foreground transition-colors"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
        <h3 className="text-sm font-semibold text-foreground">{step.title}</h3>
        <p className="text-xs text-muted-foreground mt-1.5 leading-relaxed">{step.body}</p>
        <div className="flex items-center justify-between gap-2 mt-4">
          <button
            onClick={dismissForever}
            className="text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            Skip tour
          </button>
          <button
            onClick={() => {
              if (isLast) dismissForever();
              else setStepIndex((i) => i + 1);
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary text-primary-foreground text-xs font-semibold hover:bg-primary/90 transition-colors"
          >
            {isLast ? "Got it!" : (
              <>
                Next
                <ArrowRight className="w-3 h-3" />
              </>
            )}
          </button>
        </div>

        {/* Step dots */}
        <div className="flex items-center justify-center gap-1 mt-3">
          {STEPS.map((_, i) => (
            <span
              key={i}
              className={`w-1.5 h-1.5 rounded-full transition-colors ${
                i === stepIndex ? "bg-primary" : "bg-muted-foreground/20"
              }`}
            />
          ))}
        </div>
      </div>
    </>
  );
}

// Co-located global styles. Keeping them here means deleting the
// component cleans up after itself with no orphan CSS in
// globals.css to remember.
function SpotlightStyles() {
  return (
    <style jsx global>{`
      .asm-tour-spotlight {
        position: relative;
        z-index: 55;
        border-radius: 0.625rem;
        outline: 2px solid hsl(var(--primary));
        outline-offset: 4px;
        animation: asm-tour-pulse 1.8s ease-in-out infinite;
      }
      @keyframes asm-tour-pulse {
        0%, 100% {
          box-shadow: 0 0 0 0 hsl(var(--primary) / 0.45);
        }
        50% {
          box-shadow: 0 0 0 10px hsl(var(--primary) / 0);
        }
      }
      @keyframes asm-tour-in {
        from {
          opacity: 0;
          transform: translateY(8px) scale(0.97);
        }
        to {
          opacity: 1;
          transform: translateY(0) scale(1);
        }
      }
      .animate-tour-in {
        animation: asm-tour-in 240ms ease-out both;
      }
    `}</style>
  );
}
