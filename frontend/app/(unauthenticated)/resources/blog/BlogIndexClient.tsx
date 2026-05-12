// FILE: app/(unauthenticated)/resources/blog/BlogIndexClient.tsx
//
// Client island for the blog index — handles category filter chips,
// search input, and the card grid. The list itself is built server-side
// and passed in as a prop; this component only re-filters on keystroke
// or chip click.

"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { Search, Tag, ArrowRight } from "lucide-react";

import type { Article, ArticleCategory } from "./_types";
import { CATEGORY_BADGE, categoryLabel, formatPublishDate } from "./_types";

type Category = { id: ArticleCategory; label: string; description: string };

export default function BlogIndexClient({
  articles,
  categories,
}: {
  articles: Article[];
  categories: Category[];
}) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<"all" | ArticleCategory>("all");

  // Show a count next to each chip — readers like knowing where the
  // content actually lives. Hide chips with zero articles so the row
  // doesn't fill with empty filters.
  const counts = useMemo(() => {
    const map: Record<string, number> = { all: articles.length };
    for (const a of articles) {
      map[a.category] = (map[a.category] ?? 0) + 1;
    }
    return map;
  }, [articles]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return articles.filter((a) => {
      if (category !== "all" && a.category !== category) return false;
      if (!q) return true;
      const haystack = `${a.title} ${a.description} ${(a.tags ?? []).join(" ")}`.toLowerCase();
      return haystack.includes(q);
    });
  }, [articles, query, category]);

  return (
    <div>
      {/* Filters */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-6">
        <div className="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            onClick={() => setCategory("all")}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs font-medium transition-colors ${
              category === "all"
                ? "bg-teal-500/15 text-teal-300 border-teal-500/30"
                : "bg-white/[0.02] text-white/55 border-white/[0.08] hover:bg-white/[0.05]"
            }`}
          >
            All <span className="text-white/40">({counts.all ?? 0})</span>
          </button>
          {categories.map((cat) => {
            const n = counts[cat.id] ?? 0;
            if (n === 0 && category !== cat.id) return null;
            const active = category === cat.id;
            return (
              <button
                key={cat.id}
                type="button"
                onClick={() => setCategory(cat.id)}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs font-medium transition-colors ${
                  active
                    ? CATEGORY_BADGE[cat.id]
                    : "bg-white/[0.02] text-white/55 border-white/[0.08] hover:bg-white/[0.05]"
                }`}
                title={cat.description}
              >
                {cat.label} <span className={active ? "text-white/55" : "text-white/40"}>({n})</span>
              </button>
            );
          })}
        </div>
        <div className="relative w-full sm:w-72">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/30 pointer-events-none" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search articles…"
            className="w-full h-9 pl-8 pr-3 rounded-lg border border-white/[0.08] bg-white/[0.02] text-sm text-white placeholder:text-white/30 outline-none focus:border-teal-500/30 focus:bg-white/[0.04] transition-colors"
          />
        </div>
      </div>

      {/* Card grid */}
      {filtered.length === 0 ? (
        <div className="text-center py-16 border border-dashed border-white/10 rounded-xl">
          <Tag className="w-10 h-10 text-white/15 mx-auto mb-3" />
          <p className="text-sm text-white/50">
            {query.trim() ? `No articles match "${query.trim()}".` : "No articles in this category yet."}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filtered.map((a) => (
            <Link
              key={a.slug}
              href={`/resources/blog/${a.slug}`}
              className="group flex flex-col rounded-2xl border border-white/[0.08] bg-white/[0.02] p-5 hover:border-white/[0.16] hover:bg-white/[0.04] transition-colors"
            >
              <div className="flex items-center gap-2 flex-wrap mb-3">
                <span className={`inline-flex items-center px-2 py-0.5 rounded-md border text-[10px] font-semibold ${CATEGORY_BADGE[a.category]}`}>
                  {categoryLabel(a.category)}
                </span>
                <span className="text-[10px] text-white/40">{formatPublishDate(a.publishDate)}</span>
                <span className="text-white/20">·</span>
                <span className="text-[10px] text-white/40">{a.computedReadTime} min</span>
              </div>
              <h3 className="text-base font-semibold text-foreground leading-snug group-hover:text-teal-300 transition-colors">
                {a.title}
              </h3>
              <p className="text-sm text-white/55 mt-2 leading-relaxed line-clamp-3">{a.description}</p>
              <div className="mt-4 inline-flex items-center gap-1 text-xs text-teal-400/80 group-hover:text-teal-300">
                Read <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
