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
 * When any card reports it has results, that card spans the full row (via
 * grid-column tricks below) and the other two are hidden via `display:none`.
 * This keeps the visitor focused on the result they just generated and the
 * Nano EASM Assistant explanation, which is text-heavy and needs the room.
 *
 * IMPORTANT: all three cards stay mounted in the same JSX positions across
 * layout transitions. We toggle Tailwind classes — never restructure the
 * tree. If the tree shape changed, React would unmount the active card,
 * lose its `result` state, and the just-fetched results would vanish before
 * paint. We learned that the hard way.
 *
 * Reset bumps a `nonce` that re-keys all three cards, clearing their state
 * cleanly when the visitor wants to return to the 3-col view.
 */
export default function QuickToolsSection() {
  const [activeCard, setActiveCard] = useState<ActiveCard>(null);
  const [nonce, setNonce] = useState(0);

  // Memoised handlers — passing inline arrows would make each child's
  // onActiveChange effect re-run every render and notify falsely.
  const handleScanActive = useCallback((active: boolean) => {
    setActiveCard((prev) => (active ? "scan" : prev === "scan" ? null : prev));
  }, []);
  const handleDiscoveryActive = useCallback((active: boolean) => {
    setActiveCard((prev) => (active ? "discovery" : prev === "discovery" ? null : prev));
  }, []);
  const handleToolsActive = useCallback((active: boolean) => {
    setActiveCard((prev) => (active ? "tools" : prev === "tools" ? null : prev));
  }, []);

  const handleReset = () => {
    setNonce((n) => n + 1);
    setActiveCard(null);
  };

  const isActive = activeCard !== null;

  // Slot class:
  //   - inactive: take normal 1/3 grid column, full-height
  //   - active + this is the active card: span all 3 columns
  //   - active + this is NOT the active card: hidden
  const slotClass = (slot: ActiveCard) =>
    !isActive
      ? "h-full"
      : activeCard === slot
        ? "sm:col-span-3"
        : "hidden";

  return (
    <div className="max-w-5xl mx-auto">
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-3 items-stretch">
        <div className={slotClass("scan")}>
          <FadeInOnScroll delay={100} className="h-full">
            <QuickScanCard key={`scan-${nonce}`} onActiveChange={handleScanActive} />
          </FadeInOnScroll>
        </div>
        <div className={slotClass("discovery")}>
          <FadeInOnScroll delay={200} className="h-full">
            <QuickDiscoveryCard key={`discovery-${nonce}`} onActiveChange={handleDiscoveryActive} />
          </FadeInOnScroll>
        </div>
        <div className={slotClass("tools")}>
          <FadeInOnScroll delay={300} className="h-full">
            <QuickToolsCard key={`tools-${nonce}`} onActiveChange={handleToolsActive} />
          </FadeInOnScroll>
        </div>
      </div>
      {isActive && (
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
      )}
    </div>
  );
}
