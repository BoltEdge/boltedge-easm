// FILE: app/(unauthenticated)/faq/FAQContent.tsx
// Categorised, accordion-style FAQ with live keyword search.
//
// Uses native <details>/<summary> so:
//   - Browser find-in-page (Cmd/Ctrl-F) finds answer text AND
//     auto-expands the matching item (Chrome 102+, Edge, Firefox 124+,
//     Safari 17+) — works alongside our own search box.
//   - Free accessibility: keyboard toggle, screen-reader semantics.
//
// Live search filters by question text + extracted answer text and
// auto-opens matching items so the user sees the answer immediately.

"use client";

import { useState, useMemo } from "react";
import Link from "next/link";
import { ChevronDown, Search, X } from "lucide-react";
import type { ReactNode } from "react";
import { FAQS, nodeToText, type FAQItem } from "./faq-data";


function matchesQuery(item: FAQItem, query: string): boolean {
  if (!query) return true;
  const q = query.toLowerCase();
  return (
    item.q.toLowerCase().includes(q) ||
    nodeToText(item.a).toLowerCase().includes(q)
  );
}

function AccordionItem({ q, a, forceOpen }: FAQItem & { forceOpen: boolean }) {
  // When `forceOpen` is true we want the item rendered open, but we
  // also want to leave the user free to toggle it. Spreading the
  // `open` attribute conditionally means: while searching, every
  // matched item starts open; clear the search and items return to
  // normal click-to-toggle behaviour.
  const openProps = forceOpen ? { open: true } : {};
  return (
    <details
      {...openProps}
      className="group border-b border-white/[0.06] last:border-0 [&_summary::-webkit-details-marker]:hidden"
    >
      <summary className="cursor-pointer list-none flex items-center justify-between py-4 px-5 hover:bg-white/[0.02] transition-colors gap-4 select-none">
        <span className="text-sm font-medium text-white">{q}</span>
        <ChevronDown className="w-4 h-4 text-white/40 shrink-0 transition-transform duration-200 group-open:rotate-180" />
      </summary>
      <div className="px-5 pb-5 pt-1 text-sm text-white/65 leading-relaxed">
        {a}
      </div>
    </details>
  );
}

export default function FAQContent() {
  const [query, setQuery] = useState("");
  const trimmed = query.trim();
  const isSearching = trimmed.length > 0;

  const filtered = useMemo(() => {
    if (!isSearching) return FAQS;
    return FAQS
      .map((cat) => ({ ...cat, items: cat.items.filter((i) => matchesQuery(i, trimmed)) }))
      .filter((cat) => cat.items.length > 0);
  }, [trimmed, isSearching]);

  const totalAll = FAQS.reduce((sum, cat) => sum + cat.items.length, 0);
  const totalMatches = filtered.reduce((sum, cat) => sum + cat.items.length, 0);

  return (
    <div className="mt-10">
      {/* ── Search box ── */}
      <div className="relative">
        <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-white/30 pointer-events-none" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search the FAQ — e.g. trial, API, refund, MSSP…"
          className="w-full pl-10 pr-10 py-3 rounded-xl bg-white/[0.03] border border-white/[0.08] text-white text-sm placeholder:text-white/30 focus:outline-none focus:border-teal-500/40 focus:bg-white/[0.05] transition-colors"
          aria-label="Search the FAQ"
        />
        {query && (
          <button
            type="button"
            onClick={() => setQuery("")}
            className="absolute right-2.5 top-1/2 -translate-y-1/2 w-7 h-7 rounded-md flex items-center justify-center text-white/40 hover:text-white hover:bg-white/[0.06] transition-colors"
            aria-label="Clear search"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      {isSearching && (
        <p className="mt-3 text-xs text-white/40">
          {totalMatches === 0
            ? "No questions match your search."
            : `${totalMatches} of ${totalAll} ${totalMatches === 1 ? "question matches" : "questions match"}.`}
        </p>
      )}

      {/* ── Results ── */}
      {totalMatches === 0 ? (
        <div className="mt-12 text-center py-12 rounded-xl border border-white/[0.06] bg-white/[0.02]">
          <p className="text-sm text-white/60">Nothing matches &ldquo;{trimmed}&rdquo;.</p>
          <p className="mt-2 text-sm text-white/55">
            Try a different keyword, or{" "}
            <Link href="/#contact" className="text-teal-400 hover:text-teal-300">ask us directly</Link>.
          </p>
        </div>
      ) : (
        <div className="mt-8 space-y-10">
          {filtered.map((category) => {
            const Icon = category.icon;
            return (
              <section key={category.title}>
                <h2 className="flex items-center gap-2.5 text-lg font-semibold text-white mb-3">
                  <span className="w-7 h-7 rounded-lg bg-teal-500/10 flex items-center justify-center">
                    <Icon className="w-3.5 h-3.5 text-teal-400" />
                  </span>
                  {category.title}
                </h2>
                <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] overflow-hidden">
                  {category.items.map((item) => (
                    <AccordionItem key={item.q} {...item} forceOpen={isSearching} />
                  ))}
                </div>
              </section>
            );
          })}
        </div>
      )}
    </div>
  );
}
