// FILE: app/(admin)/admin/billing/page.tsx
// Platform Admin — Billing overview.
//
// Surfaces subscription state across all orgs:
//   - Stat tiles: active / trialing / past-due / cancelling / MRR / monthly revenue
//   - Subscriptions table with status filter + search
//   - Recent BillingEvent feed
//   - Webhook log (with errorOnly filter for debugging)
//
// All write actions (refunds, manual subscription edits) live in the
// Stripe dashboard — this page is read-only on purpose.
"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  CreditCard, AlertOctagon, Clock, RefreshCcw, Search,
  CheckCircle2, XCircle, Loader2, AlertTriangle,
} from "lucide-react";
import {
  getAdminBillingOverview,
  getAdminBillingSubscriptions,
  getAdminBillingEvents,
  getAdminWebhookLog,
  type AdminBillingOverview,
  type AdminBillingSubscription,
  type AdminBillingEvent,
  type AdminWebhookLogEntry,
  type Paginated,
} from "../../../lib/api";

type Tab = "subscriptions" | "events" | "webhooks";

const PLAN_LABELS: Record<string, string> = {
  free: "Free",
  starter: "Starter",
  professional: "Professional",
  enterprise_silver: "Enterprise Silver",
  enterprise_gold: "Enterprise Gold",
};

function formatMoney(cents: number | null | undefined): string {
  if (!cents) return "$0";
  return `$${(cents / 100).toLocaleString(undefined, {
    minimumFractionDigits: 0,
    maximumFractionDigits: 2,
  })}`;
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function formatDateTime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

const STATUS_STYLES: Record<string, string> = {
  active:     "bg-[#10b981]/10 text-[#10b981] border-[#10b981]/30",
  trialing:   "bg-[#ff8800]/10 text-[#ff8800] border-[#ff8800]/30",
  past_due:   "bg-red-500/10 text-red-300 border-red-500/30",
  canceled:   "bg-white/[0.04] text-white/40 border-white/10",
  incomplete: "bg-white/[0.04] text-white/40 border-white/10",
  cancelling: "bg-amber-500/10 text-amber-300 border-amber-500/30",
};

const EVENT_KIND_STYLES: Record<string, string> = {
  subscription_created:  "bg-[#10b981]/10 text-[#10b981]",
  subscription_canceled: "bg-white/[0.04] text-white/50",
  subscription_updated:  "bg-[#00b8d4]/10 text-[#00b8d4]",
  payment_succeeded:     "bg-[#10b981]/10 text-[#10b981]",
  payment_failed:        "bg-red-500/10 text-red-300",
  refund_issued:         "bg-amber-500/10 text-amber-300",
  plan_changed:          "bg-[#7c5cfc]/10 text-[#7c5cfc]",
};

function StatusBadge({ status }: { status: string | null }) {
  if (!status) return <span className="text-white/30 text-xs">—</span>;
  const style = STATUS_STYLES[status] || "bg-white/[0.04] text-white/40 border-white/10";
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-medium ${style}`}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

export default function AdminBillingPage() {
  const [overview, setOverview] = useState<AdminBillingOverview | null>(null);
  const [tab, setTab] = useState<Tab>("subscriptions");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadOverview(isRefresh = false) {
    if (isRefresh) setRefreshing(true); else setLoading(true);
    setError(null);
    try {
      setOverview(await getAdminBillingOverview());
    } catch (e: any) {
      setError(e?.message || "Failed to load billing overview");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => { loadOverview(); }, []);

  if (loading) return <div className="text-white/40 text-sm">Loading…</div>;
  if (error) return <div className="text-red-400 text-sm">{error}</div>;
  if (!overview) return null;

  const tiles = [
    { label: "Active",     value: overview.counts.active,     icon: CheckCircle2, color: "#10b981" },
    { label: "Trialing",   value: overview.counts.trialing,   icon: Clock,        color: "#ff8800" },
    { label: "Past due",   value: overview.counts.past_due,   icon: AlertOctagon, color: "#ef4444" },
    { label: "Cancelling", value: overview.counts.cancelling, icon: XCircle,      color: "#f59e0b" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white flex items-center gap-2">
            <CreditCard className="w-5 h-5 text-teal-400" />Billing
          </h1>
          <p className="text-xs text-white/30 mt-0.5">
            Subscription state across all tenants. Read-only — write actions live in the Stripe dashboard.
          </p>
        </div>
        <button
          onClick={() => loadOverview(true)}
          disabled={refreshing}
          className="flex items-center gap-1.5 text-xs text-white/40 hover:text-white transition-colors disabled:opacity-50"
        >
          <RefreshCcw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin" : ""}`} />
          {refreshing ? "Refreshing…" : "Refresh"}
        </button>
      </div>

      {!overview.billingEnabled && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 px-4 py-3 text-sm text-amber-200">
          <span className="font-semibold">Billing is currently disabled.</span>
          <span className="ml-2 text-amber-200/70">
            ENABLE_BILLING is false on the backend. New subscriptions can&apos;t be created and webhooks will be rejected.
          </span>
        </div>
      )}

      {/* Top-line counts */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {tiles.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ backgroundColor: `${color}15` }}>
                <Icon className="w-3.5 h-3.5" style={{ color }} />
              </div>
              <span className="text-[11px] text-white/40">{label}</span>
            </div>
            <div className="text-2xl font-bold text-white">{value.toLocaleString()}</div>
          </div>
        ))}
      </div>

      {/* Revenue tiles */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
          <div className="text-[11px] text-white/40 uppercase tracking-wide">Estimated MRR</div>
          <div className="mt-2 text-3xl font-bold text-white">{formatMoney(overview.mrrCents)}</div>
          <div className="mt-1 text-[11px] text-white/30">
            Sum of monthly equivalents for active + past-due subscriptions
          </div>
        </div>
        <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
          <div className="text-[11px] text-white/40 uppercase tracking-wide">Revenue this month</div>
          <div className="mt-2 text-3xl font-bold text-white">{formatMoney(overview.monthlyRevenueCents)}</div>
          <div className="mt-1 text-[11px] text-white/30">
            Recognised payments collected since the 1st
          </div>
        </div>
        <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5">
          <div className="text-[11px] text-white/40 uppercase tracking-wide">Webhook health (24h)</div>
          <div className="mt-2 flex items-baseline gap-4">
            <div>
              <div className="text-xl font-bold text-red-300">
                {overview.webhookHealth.errorsLast24h}
              </div>
              <div className="text-[10px] text-white/40">errors</div>
            </div>
            <div>
              <div className="text-xl font-bold text-amber-300">
                {overview.webhookHealth.unprocessedLast24h}
              </div>
              <div className="text-[10px] text-white/40">unprocessed</div>
            </div>
            <div className="ml-auto">
              <button
                onClick={() => setTab("webhooks")}
                className="text-[11px] text-teal-400 hover:text-teal-300"
              >
                View log →
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-white/[0.06] flex gap-1">
        {[
          { id: "subscriptions" as const, label: "Subscriptions" },
          { id: "events"        as const, label: "Recent events" },
          { id: "webhooks"      as const, label: "Webhook log" },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2 text-sm border-b-2 -mb-px transition-colors ${
              tab === t.id
                ? "border-teal-400 text-white"
                : "border-transparent text-white/40 hover:text-white/70"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "subscriptions" && <SubscriptionsTab />}
      {tab === "events" && <EventsTab />}
      {tab === "webhooks" && <WebhooksTab />}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Subscriptions tab
// ─────────────────────────────────────────────────────────────────

function SubscriptionsTab() {
  const [data, setData] = useState<Paginated<AdminBillingSubscription> | null>(null);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);

  async function load() {
    setLoading(true);
    try {
      const res = await getAdminBillingSubscriptions({ status, search: search || undefined, page });
      setData(res);
    } catch {
      setData({ items: [], page: 1, perPage: 50, total: 0 });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [status, page]);

  function onSearchSubmit(e: React.FormEvent) {
    e.preventDefault();
    setPage(1);
    load();
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <form onSubmit={onSearchSubmit} className="flex-1 relative max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/30" />
          <input
            type="text"
            placeholder="Search by org name…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-white/[0.03] border border-white/[0.06] text-white text-sm placeholder:text-white/30 focus:outline-none focus:border-teal-500/40"
          />
        </form>
        <select
          value={status}
          onChange={(e) => { setStatus(e.target.value); setPage(1); }}
          className="px-3 py-2 rounded-lg bg-white/[0.03] border border-white/[0.06] text-white text-sm focus:outline-none focus:border-teal-500/40"
        >
          <option value="all">All</option>
          <option value="active">Active</option>
          <option value="trialing">Trialing</option>
          <option value="past_due">Past due</option>
          <option value="cancelling">Cancelling</option>
          <option value="canceled">Canceled</option>
        </select>
      </div>

      <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-[11px] text-white/40 uppercase tracking-wide border-b border-white/[0.06]">
              <th className="px-4 py-2.5 font-medium">Organisation</th>
              <th className="px-4 py-2.5 font-medium">Plan</th>
              <th className="px-4 py-2.5 font-medium">Cycle</th>
              <th className="px-4 py-2.5 font-medium">Status</th>
              <th className="px-4 py-2.5 font-medium">Next renewal</th>
              <th className="px-4 py-2.5 font-medium text-right">MRR</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} className="px-4 py-6 text-center text-white/40">Loading…</td></tr>
            ) : !data || data.items.length === 0 ? (
              <tr><td colSpan={6} className="px-4 py-12 text-center text-white/30">
                No subscriptions match this filter.
              </td></tr>
            ) : data.items.map((s) => (
              <tr key={s.id} className="border-b border-white/[0.04] last:border-0 hover:bg-white/[0.02]">
                <td className="px-4 py-3">
                  <Link href={`/admin/organizations/${s.id}`} className="text-white hover:text-teal-300 font-medium">
                    {s.name}
                  </Link>
                  <div className="text-[10px] text-white/30 font-mono mt-0.5">{s.displayId}</div>
                </td>
                <td className="px-4 py-3 text-white/70">{PLAN_LABELS[s.plan] || s.plan}</td>
                <td className="px-4 py-3 text-white/50 capitalize">{s.billingCycle || "—"}</td>
                <td className="px-4 py-3">
                  <StatusBadge status={s.cancelAtPeriodEnd ? "cancelling" : s.subscriptionStatus} />
                </td>
                <td className="px-4 py-3 text-white/50">{formatDate(s.currentPeriodEnd)}</td>
                <td className="px-4 py-3 text-right font-mono text-white">{formatMoney(s.mrrCents)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {data && data.total > data.perPage && (
        <Pagination page={page} total={data.total} perPage={data.perPage} onPage={setPage} />
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Events tab — recent BillingEvent rows
// ─────────────────────────────────────────────────────────────────

function EventsTab() {
  const [data, setData] = useState<Paginated<AdminBillingEvent> | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [kind, setKind] = useState("");

  useEffect(() => {
    setLoading(true);
    getAdminBillingEvents({ page, kind: kind || undefined })
      .then(setData)
      .catch(() => setData({ items: [], page: 1, perPage: 50, total: 0 }))
      .finally(() => setLoading(false));
  }, [page, kind]);

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <select
          value={kind}
          onChange={(e) => { setKind(e.target.value); setPage(1); }}
          className="px-3 py-2 rounded-lg bg-white/[0.03] border border-white/[0.06] text-white text-sm focus:outline-none focus:border-teal-500/40"
        >
          <option value="">All event types</option>
          <option value="subscription_created">subscription_created</option>
          <option value="subscription_updated">subscription_updated</option>
          <option value="subscription_canceled">subscription_canceled</option>
          <option value="payment_succeeded">payment_succeeded</option>
          <option value="payment_failed">payment_failed</option>
          <option value="plan_changed">plan_changed</option>
          <option value="refund_issued">refund_issued</option>
        </select>
      </div>

      <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-[11px] text-white/40 uppercase tracking-wide border-b border-white/[0.06]">
              <th className="px-4 py-2.5 font-medium">When</th>
              <th className="px-4 py-2.5 font-medium">Organisation</th>
              <th className="px-4 py-2.5 font-medium">Event</th>
              <th className="px-4 py-2.5 font-medium">Description</th>
              <th className="px-4 py-2.5 font-medium text-right">Amount</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} className="px-4 py-6 text-center text-white/40">Loading…</td></tr>
            ) : !data || data.items.length === 0 ? (
              <tr><td colSpan={5} className="px-4 py-12 text-center text-white/30">
                No billing events yet — they show up here as subscriptions are created and payments processed.
              </td></tr>
            ) : data.items.map((e) => {
              const style = EVENT_KIND_STYLES[e.kind] || "bg-white/[0.04] text-white/50";
              return (
                <tr key={e.id} className="border-b border-white/[0.04] last:border-0 hover:bg-white/[0.02]">
                  <td className="px-4 py-3 text-white/50 text-xs">{formatDateTime(e.createdAt)}</td>
                  <td className="px-4 py-3">
                    {e.organizationId ? (
                      <Link href={`/admin/organizations/${e.organizationId}`} className="text-white hover:text-teal-300">
                        {e.organizationName || "(deleted)"}
                      </Link>
                    ) : (
                      <span className="text-white/40">—</span>
                    )}
                    {e.organizationDisplayId && (
                      <div className="text-[10px] text-white/30 font-mono mt-0.5">{e.organizationDisplayId}</div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex rounded-md px-1.5 py-0.5 text-[10px] font-mono ${style}`}>
                      {e.kind}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-white/60 text-xs max-w-md truncate">
                    {e.description || "—"}
                  </td>
                  <td className="px-4 py-3 text-right font-mono text-white text-xs">
                    {e.amountCents != null ? formatMoney(e.amountCents) : "—"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {data && data.total > data.perPage && (
        <Pagination page={page} total={data.total} perPage={data.perPage} onPage={setPage} />
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Webhook log tab — recent StripeEvent rows
// ─────────────────────────────────────────────────────────────────

function WebhooksTab() {
  const [data, setData] = useState<Paginated<AdminWebhookLogEntry> | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [errorOnly, setErrorOnly] = useState(false);
  const [type, setType] = useState("");

  useEffect(() => {
    setLoading(true);
    getAdminWebhookLog({ page, errorOnly, type: type || undefined })
      .then(setData)
      .catch(() => setData({ items: [], page: 1, perPage: 50, total: 0 }))
      .finally(() => setLoading(false));
  }, [page, errorOnly, type]);

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <label className="flex items-center gap-2 text-xs text-white/60 cursor-pointer">
          <input
            type="checkbox"
            checked={errorOnly}
            onChange={(e) => { setErrorOnly(e.target.checked); setPage(1); }}
            className="rounded"
          />
          Errors only
        </label>
        <input
          type="text"
          placeholder="Filter by event type (e.g. invoice.payment_failed)…"
          value={type}
          onChange={(e) => { setType(e.target.value); setPage(1); }}
          className="flex-1 max-w-md px-3 py-2 rounded-lg bg-white/[0.03] border border-white/[0.06] text-white text-sm placeholder:text-white/30 focus:outline-none focus:border-teal-500/40"
        />
      </div>

      <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-[11px] text-white/40 uppercase tracking-wide border-b border-white/[0.06]">
              <th className="px-4 py-2.5 font-medium">Received</th>
              <th className="px-4 py-2.5 font-medium">Event ID</th>
              <th className="px-4 py-2.5 font-medium">Type</th>
              <th className="px-4 py-2.5 font-medium">Status</th>
              <th className="px-4 py-2.5 font-medium">Error</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} className="px-4 py-6 text-center text-white/40">Loading…</td></tr>
            ) : !data || data.items.length === 0 ? (
              <tr><td colSpan={5} className="px-4 py-12 text-center text-white/30">
                No webhook deliveries match this filter.
              </td></tr>
            ) : data.items.map((w) => {
              const StatusIcon = w.status === "processed" ? CheckCircle2
                : w.status === "failed" ? AlertTriangle
                : Loader2;
              const statusColor = w.status === "processed" ? "text-[#10b981]"
                : w.status === "failed" ? "text-red-300"
                : "text-amber-300";
              return (
                <tr key={w.id} className="border-b border-white/[0.04] last:border-0 hover:bg-white/[0.02]">
                  <td className="px-4 py-3 text-white/50 text-xs">{formatDateTime(w.receivedAt)}</td>
                  <td className="px-4 py-3 font-mono text-[11px] text-white/70">{w.stripeId}</td>
                  <td className="px-4 py-3 font-mono text-[11px] text-white/70">{w.type}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1 text-xs ${statusColor}`}>
                      <StatusIcon className={`w-3 h-3 ${w.status === "pending" ? "animate-spin" : ""}`} />
                      {w.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-red-300/80 text-xs max-w-md truncate" title={w.error || undefined}>
                    {w.error || ""}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {data && data.total > data.perPage && (
        <Pagination page={page} total={data.total} perPage={data.perPage} onPage={setPage} />
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// Pagination
// ─────────────────────────────────────────────────────────────────

function Pagination({ page, total, perPage, onPage }: {
  page: number; total: number; perPage: number; onPage: (p: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / perPage));
  return (
    <div className="flex items-center justify-between text-xs text-white/40">
      <span>
        {Math.min((page - 1) * perPage + 1, total)}–{Math.min(page * perPage, total)} of {total}
      </span>
      <div className="flex gap-1">
        <button
          onClick={() => onPage(Math.max(1, page - 1))}
          disabled={page <= 1}
          className="px-2 py-1 rounded border border-white/[0.06] hover:bg-white/[0.04] disabled:opacity-30 disabled:cursor-not-allowed"
        >
          Prev
        </button>
        <span className="px-2 py-1 text-white/60">
          {page} / {pages}
        </span>
        <button
          onClick={() => onPage(Math.min(pages, page + 1))}
          disabled={page >= pages}
          className="px-2 py-1 rounded border border-white/[0.06] hover:bg-white/[0.04] disabled:opacity-30 disabled:cursor-not-allowed"
        >
          Next
        </button>
      </div>
    </div>
  );
}
