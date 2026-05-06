"use client";

import { useCallback, useState } from "react";

import FadeInOnScroll from "./Fadeinonscroll";
import QuickScanCard from "./QuickScanCard";
import QuickDiscoveryCard from "./QuickDiscoveryCard";
import QuickToolsCard from "./QuickToolsCard";

type ActiveCard = "scan" | "discovery" | "tools" | null;

/**
 * QuickToolsSection — owns the layout for the three landing-page tool cards.
 *
 * Default state: a 3-column grid (QuickScan / QuickDiscovery / QuickTools).
 *
 * When any card reports it has results, that card spans the full row and the
 * other two are unmounted. This keeps the visitor focused on the result they
 * just generated (especially the Nano EASM Assistant explanation, which is
 * text-heavy and needs the room) and removes competing CTAs at the moment of
 * highest engagement. A small reset link below brings the 3-column layout
 * back; clicking it bumps a `nonce` that remounts cards with cleared state.
 *
 * Mutual exclusion is automatic by construction: while one card is active,
 * the other two aren't mounted, so they can't fire onActiveChange. The
 * single ActiveCard slot can only be set by whichever card is rendered.
 */
export default function QuickToolsSection() {
  const [activeCard, setActiveCard] = useState<ActiveCard>(null);
  const [nonce, setNonce] = useState(0);

  // Memoised handlers — passing inline arrows would make each child's
  // onActiveChange effect re-run every render and notify falsely.
  const handleScanActive = useCallback((active: boolean) => {
    setActiveCard(active ? "scan" : null);
  }, []);
  const handleDiscoveryActive = useCallback((active: boolean) => {
    setActiveCard(active ? "discovery" : null);
  }, []);
  const handleToolsActive = useCallback((active: boolean) => {
    setActiveCard(active ? "tools" : null);
  }, []);

  const handleReset = () => {
    setNonce((n) => n + 1);
    setActiveCard(null);
  };

  if (activeCard !== null) {
    return (
      <div className="max-w-5xl mx-auto">
        <FadeInOnScroll delay={100}>
          {activeCard === "scan" && (
            <QuickScanCard key={`scan-${nonce}`} onActiveChange={handleScanActive} />
          )}
          {activeCard === "discovery" && (
            <QuickDiscoveryCard key={`discovery-${nonce}`} onActiveChange={handleDiscoveryActive} />
          )}
          {activeCard === "tools" && (
            <QuickToolsCard key={`tools-${nonce}`} onActiveChange={handleToolsActive} />
          )}
        </FadeInOnScroll>
        <div className="mt-4 text-center text-[11px] text-white/40">
          Looking for something else?{" "}
          <button
            type="button"
            onClick={handleReset}
            className="text-teal-400 hover:text-teal-300 underline underline-offset-2 transition-colors"
          >
            See all quick tools
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-6 sm:grid-cols-3 items-stretch max-w-5xl mx-auto">
      <FadeInOnScroll delay={100} className="h-full">
        <QuickScanCard key={`scan-${nonce}`} onActiveChange={handleScanActive} />
      </FadeInOnScroll>
      <FadeInOnScroll delay={200} className="h-full">
        <QuickDiscoveryCard key={`discovery-${nonce}`} onActiveChange={handleDiscoveryActive} />
      </FadeInOnScroll>
      <FadeInOnScroll delay={300} className="h-full">
        <QuickToolsCard key={`tools-${nonce}`} onActiveChange={handleToolsActive} />
      </FadeInOnScroll>
    </div>
  );
}
