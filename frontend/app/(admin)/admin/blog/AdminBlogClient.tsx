// FILE: app/(admin)/admin/blog/AdminBlogClient.tsx
//
// Client island for the admin blog view. Two stacked panels:
//
//   1. Articles — one row per published article with a per-article
//      "Send to subscribers" button. The button shows how many active
//      subscribers haven't yet received the article (from the
//      /api/admin/blog/article-sent/<slug> endpoint), and on click
//      confirms before posting /api/admin/blog/send.
//
//   2. Subscribers — paginated list with email, status, source, dates.
//      Read-only — no admin-side unsubscribe to keep the audit trail
//      coming exclusively from the public unsubscribe link.

"use client";

import { useEffect, useMemo, useState, useCallback } from "react";
import { Loader2, Send, Users, Calendar, Mail, RefreshCw, AlertTriangle, Check } from "lucide-react";

import { apiFetch } from "../../../lib/api";

type AdminArticle = {
  slug: string;
  title: string;
  description: string;
  publishDate: string;
  category: string;
  readTime: number;
};

type ArticleSentCounts = {
  slug: string;
  sent: number;
  failed: number;
  activeSubscribers: number;
  notYetSent: number;
};

type Subscriber = {
  id: number;
  email: string;
  isActive: boolean;
  subscribedAt: string | null;
  unsubscribedAt: string | null;
  lastSentAt: string | null;
  source: string | null;
};

type SubscribersResponse = {
  total: number;
  active: number;
  page: number;
  perPage: number;
  items: Subscriber[];
};

type SendResponse = {
  slug: string;
  attempted: number;
  sent: number;
  skipped: number;
  failed: number;
  message: string;
};

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString("en-AU", {
      year: "numeric", month: "short", day: "numeric",
    });
  } catch {
    return iso;
  }
}

export default function AdminBlogClient({ articles }: { articles: AdminArticle[] }) {
  const [subscribers, setSubscribers] = useState<SubscribersResponse | null>(null);
  const [counts, setCounts] = useState<Record<string, ArticleSentCounts>>({});
  const [loading, setLoading] = useState(true);
  const [includeInactive, setIncludeInactive] = useState(false);
  const [sendingSlug, setSendingSlug] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [confirmSlug, setConfirmSlug] = useState<string | null>(null);

  const loadCounts = useCallback(async () => {
    const results = await Promise.all(
      articles.map(async (a) => {
        try {
          const c = await apiFetch<ArticleSentCounts>(`/admin/blog/article-sent/${a.slug}`);
          return [a.slug, c] as const;
        } catch {
          return [a.slug, null] as const;
        }
      }),
    );
    const next: Record<string, ArticleSentCounts> = {};
    for (const [slug, c] of results) {
      if (c) next[slug] = c;
    }
    setCounts(next);
  }, [articles]);

  const loadSubscribers = useCallback(async () => {
    try {
      const res = await apiFetch<SubscribersResponse>(
        `/admin/blog/subscribers?includeInactive=${includeInactive ? 1 : 0}&perPage=100`,
      );
      setSubscribers(res);
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to load subscribers" });
    }
  }, [includeInactive]);

  const reload = useCallback(async () => {
    setLoading(true);
    await Promise.all([loadSubscribers(), loadCounts()]);
    setLoading(false);
  }, [loadSubscribers, loadCounts]);

  useEffect(() => { reload(); }, [reload]);
  useEffect(() => {
    if (!banner) return;
    const t = setTimeout(() => setBanner(null), 6000);
    return () => clearTimeout(t);
  }, [banner]);

  const sortedArticles = useMemo(
    () => [...articles].sort((a, b) => (a.publishDate < b.publishDate ? 1 : -1)),
    [articles],
  );

  async function handleSend(slug: string) {
    const article = articles.find((a) => a.slug === slug);
    if (!article) return;
    setConfirmSlug(null);
    setSendingSlug(slug);
    setBanner(null);
    try {
      const res = await apiFetch<SendResponse>("/admin/blog/send", {
        method: "POST",
        body: JSON.stringify({
          slug: article.slug,
          title: article.title,
          description: article.description,
          readTime: article.readTime,
        }),
      });
      setBanner({ kind: "ok", text: res.message });
      await loadCounts();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Send failed" });
    } finally {
      setSendingSlug(null);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <Mail className="w-5 h-5 text-primary" />Blog Subscribers
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage the blog mailing list and send new articles to subscribers.
            Single opt-in; one-click unsubscribe from every email.
          </p>
        </div>
        <button
          type="button"
          onClick={reload}
          disabled={loading}
          className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border border-border text-foreground hover:bg-accent transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {banner && (
        <div className={`rounded-xl border px-4 py-3 text-sm ${
          banner.kind === "ok"
            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
            : "border-red-500/30 bg-red-500/10 text-red-300"
        }`}>
          {banner.text}
        </div>
      )}

      {/* Stats strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-xl border border-border bg-card/40 p-4">
          <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-2">Active subscribers</div>
          <div className="text-2xl font-bold text-foreground tabular-nums">{subscribers?.active ?? "—"}</div>
        </div>
        <div className="rounded-xl border border-border bg-card/40 p-4">
          <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-2">Total (incl. unsubscribed)</div>
          <div className="text-2xl font-bold text-foreground tabular-nums">{subscribers?.total ?? "—"}</div>
        </div>
        <div className="rounded-xl border border-border bg-card/40 p-4">
          <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-2">Articles published</div>
          <div className="text-2xl font-bold text-foreground tabular-nums">{articles.length}</div>
        </div>
        <div className="rounded-xl border border-border bg-card/40 p-4">
          <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-2">Last article sent</div>
          <div className="text-sm font-medium text-foreground">
            {(() => {
              const sentSlugs = Object.entries(counts).filter(([, c]) => c.sent > 0);
              if (sentSlugs.length === 0) return "Never";
              return `${sentSlugs.length} article${sentSlugs.length === 1 ? "" : "s"}`;
            })()}
          </div>
        </div>
      </div>

      {/* Articles panel */}
      <section className="rounded-xl border border-border bg-card/40 overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <h2 className="text-base font-semibold text-foreground">Articles</h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Click "Send" to notify all active subscribers about an article.
            Already-sent rows are skipped per subscriber — safe to re-click.
          </p>
        </div>

        {articles.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted-foreground">
            No articles published yet.
          </div>
        ) : (
          <div className="divide-y divide-border">
            {sortedArticles.map((a) => {
              const c = counts[a.slug];
              const notYet = c?.notYetSent ?? 0;
              const sent = c?.sent ?? 0;
              const failed = c?.failed ?? 0;
              const total = subscribers?.active ?? 0;
              const isSending = sendingSlug === a.slug;
              return (
                <div key={a.slug} className="p-4 sm:p-5 flex items-start justify-between gap-4 flex-wrap">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold bg-muted/40 text-muted-foreground border border-border capitalize">
                        {a.category}
                      </span>
                      <span className="text-[11px] text-muted-foreground inline-flex items-center gap-1">
                        <Calendar className="w-3 h-3" />{fmtDate(a.publishDate)}
                      </span>
                      <span className="text-[11px] text-muted-foreground">· {a.readTime} min</span>
                    </div>
                    <div className="text-sm font-semibold text-foreground">{a.title}</div>
                    <div className="text-xs text-muted-foreground mt-0.5 line-clamp-2 max-w-2xl">{a.description}</div>
                    <div className="mt-2 flex items-center gap-3 text-[11px] text-muted-foreground flex-wrap">
                      <span className="inline-flex items-center gap-1">
                        <Users className="w-3 h-3" />
                        <span className="tabular-nums">{sent}</span> / <span className="tabular-nums">{total}</span> sent
                      </span>
                      {failed > 0 && (
                        <span className="inline-flex items-center gap-1 text-red-300">
                          <AlertTriangle className="w-3 h-3" /><span className="tabular-nums">{failed}</span> failed
                        </span>
                      )}
                      {notYet > 0 && total > 0 && (
                        <span className="inline-flex items-center gap-1 text-amber-300">
                          <span className="tabular-nums">{notYet}</span> not yet sent
                        </span>
                      )}
                      {notYet === 0 && sent > 0 && (
                        <span className="inline-flex items-center gap-1 text-emerald-300">
                          <Check className="w-3 h-3" />All sent
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <button
                      type="button"
                      onClick={() => setConfirmSlug(a.slug)}
                      disabled={isSending || total === 0 || notYet === 0}
                      title={
                        total === 0
                          ? "No active subscribers"
                          : notYet === 0
                            ? "All active subscribers already received this article"
                            : `Send to ${notYet} subscriber${notYet === 1 ? "" : "s"}`
                      }
                      className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-primary text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      {isSending ? (
                        <><Loader2 className="w-3.5 h-3.5 animate-spin" />Sending…</>
                      ) : (
                        <><Send className="w-3.5 h-3.5" />Send to {notYet || 0}</>
                      )}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Subscribers panel */}
      <section className="rounded-xl border border-border bg-card/40 overflow-hidden">
        <div className="px-5 py-4 border-b border-border flex items-center justify-between gap-3 flex-wrap">
          <h2 className="text-base font-semibold text-foreground">Subscribers</h2>
          <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer select-none">
            <input
              type="checkbox"
              checked={includeInactive}
              onChange={(e) => setIncludeInactive(e.target.checked)}
              className="accent-primary"
            />
            Include unsubscribed
          </label>
        </div>

        {subscribers && subscribers.items.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted-foreground">
            No subscribers yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-muted/20">
                <tr>
                  <th className="text-left px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Email</th>
                  <th className="text-left px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Status</th>
                  <th className="text-left px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Source</th>
                  <th className="text-left px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Subscribed</th>
                  <th className="text-left px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Last sent</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {subscribers?.items.map((s) => (
                  <tr key={s.id} className={s.isActive ? "" : "opacity-50"}>
                    <td className="px-4 py-3 text-sm text-foreground font-mono">{s.email}</td>
                    <td className="px-4 py-3">
                      {s.isActive ? (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold bg-zinc-500/15 text-zinc-300 border border-zinc-500/30">
                          <span className="w-1.5 h-1.5 rounded-full bg-zinc-400" />Unsubscribed
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{s.source || "—"}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{fmtDate(s.subscribedAt)}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{fmtDate(s.lastSentAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Confirmation dialog — minimal, no library needed */}
      {confirmSlug && (() => {
        const a = articles.find((x) => x.slug === confirmSlug);
        const c = counts[confirmSlug];
        if (!a) return null;
        return (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => setConfirmSlug(null)}>
            <div
              className="bg-card border border-border rounded-xl p-6 max-w-md w-full"
              onClick={(e) => e.stopPropagation()}
            >
              <h3 className="text-lg font-semibold text-foreground">Send "{a.title}"?</h3>
              <p className="mt-2 text-sm text-muted-foreground">
                This emails the article to <span className="text-foreground font-semibold">{c?.notYetSent ?? 0}</span> subscriber
                {(c?.notYetSent ?? 0) === 1 ? "" : "s"} who haven't received it yet.
                Subscribers who already got it will be skipped.
              </p>
              <div className="mt-5 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setConfirmSlug(null)}
                  className="px-4 py-2 rounded-lg text-sm font-medium border border-border text-foreground hover:bg-accent transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={() => handleSend(confirmSlug)}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
                >
                  <Send className="w-3.5 h-3.5" />Send now
                </button>
              </div>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
