"use client";

import { useEffect, useState, useCallback } from "react";
import {
  MessageSquare, Search, RefreshCw, Trash2, Send, Loader2, X,
  Check, ExternalLink, ChevronLeft, ChevronRight, Clock, AlertOctagon, Inbox,
} from "lucide-react";

import {
  getAdminContactRequests,
  getAdminContactRequest,
  setAdminContactRequestStatus,
  replyAdminContactRequest,
  deleteAdminContactRequest,
} from "../../../lib/api";

const STATUS_OPTIONS = ["open", "in_progress", "replied", "closed", "spam"] as const;
type Status = (typeof STATUS_OPTIONS)[number];

const STATUS_STYLES: Record<Status, string> = {
  open:         "bg-teal-500/10 text-teal-300 border-teal-500/20",
  in_progress:  "bg-amber-500/10 text-amber-300 border-amber-500/20",
  replied:      "bg-emerald-500/10 text-emerald-300 border-emerald-500/20",
  closed:       "bg-white/[0.04] text-white/40 border-white/[0.08]",
  spam:         "bg-red-500/10 text-red-300 border-red-500/20",
};

const STATUS_LABELS: Record<Status, string> = {
  open: "Open",
  in_progress: "In Progress",
  replied: "Replied",
  closed: "Closed",
  spam: "Spam",
};

function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  const diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  if (diffSec < 7 * 86400) return `${Math.floor(diffSec / 86400)}d ago`;
  return d.toLocaleDateString();
}

function fmtAbsolute(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

export default function AdminContactRequests() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<"" | Status>("");

  const [selected, setSelected] = useState<any | null>(null);
  const [busy, setBusy] = useState(false);
  const [replying, setReplying] = useState(false);
  const [replyOpen, setReplyOpen] = useState(false);
  const [replySubject, setReplySubject] = useState("");
  const [replyMessage, setReplyMessage] = useState("");
  const [adminNotes, setAdminNotes] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const res = await getAdminContactRequests({
        page,
        search: search || undefined,
        status: statusFilter || undefined,
      });
      setData(res);
    } catch (e: any) {
      setError(e?.message || "Failed to load");
    } finally {
      setLoading(false);
    }
  }, [page, search, statusFilter]);

  useEffect(() => { setLoading(true); load(); }, [load]);
  useEffect(() => { setPage(1); }, [search, statusFilter]);
  useEffect(() => {
    if (!banner) return;
    const t = setTimeout(() => setBanner(null), 4000);
    return () => clearTimeout(t);
  }, [banner]);

  async function openDetail(row: any) {
    try {
      const full = await getAdminContactRequest(row.id);
      setSelected(full);
      setAdminNotes(full.adminNotes || "");
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to load request" });
    }
  }

  function closeDetail() {
    setSelected(null);
    setReplyOpen(false);
    setConfirmDelete(false);
    setReplySubject("");
    setReplyMessage("");
    setAdminNotes("");
  }

  async function handleStatusChange(status: Status) {
    if (!selected) return;
    setBusy(true);
    try {
      const updated = await setAdminContactRequestStatus(selected.id, {
        status,
        adminNotes: adminNotes || undefined,
      });
      setSelected(updated);
      setBanner({ kind: "ok", text: `Marked as ${STATUS_LABELS[status]}.` });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to update status" });
    } finally { setBusy(false); }
  }

  async function handleSendReply() {
    if (!selected || !replyMessage.trim()) return;
    setReplying(true);
    try {
      const res = await replyAdminContactRequest(selected.id, {
        subject: replySubject.trim() || undefined,
        message: replyMessage.trim(),
        adminNotes: adminNotes || undefined,
      });
      setSelected(res.request);
      setReplyOpen(false);
      setReplySubject("");
      setReplyMessage("");
      setBanner({
        kind: res.emailSent ? "ok" : "err",
        text: res.message,
      });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to send reply" });
    } finally { setReplying(false); }
  }

  async function handleDelete() {
    if (!selected) return;
    setBusy(true);
    try {
      await deleteAdminContactRequest(selected.id);
      setBanner({ kind: "ok", text: "Request deleted." });
      closeDetail();
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to delete" });
    } finally { setBusy(false); }
  }

  const statusCounts = data?.statusCounts ?? { open: 0, in_progress: 0, replied: 0, closed: 0, spam: 0 };
  const requests: any[] = data?.requests ?? [];

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white flex items-center gap-2">
            <MessageSquare className="w-5 h-5 text-teal-400" />Contact Requests
          </h1>
          <p className="text-xs text-white/30 mt-0.5">{data ? `${data.total} total` : "…"}</p>
        </div>
        <button
          onClick={() => { setLoading(true); load(); }}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-white/50 hover:text-white bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.06] transition-colors disabled:opacity-40"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />Refresh
        </button>
      </div>

      {banner && (
        <div className={`rounded-lg px-4 py-2.5 text-sm ${banner.kind === "ok" ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20" : "bg-red-500/10 text-red-300 border border-red-500/20"}`}>
          {banner.text}
        </div>
      )}

      {/* Status totals */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {(["open", "in_progress", "replied", "closed", "spam"] as Status[]).map((s) => (
          <button
            key={s}
            onClick={() => setStatusFilter(statusFilter === s ? "" : s)}
            className={`rounded-xl border p-4 text-left transition-all ${statusFilter === s ? "border-teal-500/40 bg-teal-500/[0.06]" : "border-white/[0.06] bg-white/[0.02] hover:border-white/[0.12]"}`}
          >
            <div className="text-xl font-semibold text-white">{statusCounts[s] ?? 0}</div>
            <div className="text-[11px] text-white/40 mt-0.5">{STATUS_LABELS[s]}</div>
          </button>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative max-w-sm flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/30" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search name, email, subject, message…"
            className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg pl-8 pr-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40"
          />
        </div>
        {statusFilter && (
          <button
            onClick={() => setStatusFilter("")}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm text-white/40 hover:text-white hover:bg-white/[0.04] transition-colors"
          >
            <X className="w-3.5 h-3.5" />Clear filter
          </button>
        )}
      </div>

      {error && (
        <div className="rounded-lg px-4 py-2.5 text-sm bg-red-500/10 text-red-300 border border-red-500/20">{error}</div>
      )}

      {/* List */}
      {loading && !data ? (
        <div className="text-center text-white/30 text-sm py-12">Loading…</div>
      ) : !requests.length ? (
        <div className="rounded-xl border border-white/[0.06] px-4 py-12 text-center">
          <Inbox className="w-10 h-10 text-white/20 mx-auto mb-3" />
          <p className="text-sm text-white/40">{statusFilter || search ? "No matching requests." : "No contact requests yet."}</p>
        </div>
      ) : (
        <div className="rounded-xl border border-white/[0.06] overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/[0.06] bg-white/[0.02]">
                <th className="text-left px-4 py-3 text-xs font-medium text-white/40">ID</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-white/40">From</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Subject</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Status</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-white/40">Received</th>
              </tr>
            </thead>
            <tbody>
              {requests.map((r) => (
                <tr
                  key={r.id}
                  onClick={() => openDetail(r)}
                  className="border-b border-white/[0.04] hover:bg-white/[0.03] transition-colors cursor-pointer"
                >
                  <td className="px-4 py-3 font-mono text-xs text-white/50">{r.displayId}</td>
                  <td className="px-4 py-3">
                    <div className="text-white/80">{r.name}</div>
                    <div className="text-[11px] text-white/40">{r.email}</div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="text-white/70 text-xs max-w-md truncate">{r.subject || <span className="text-white/30 italic">(no subject)</span>}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${STATUS_STYLES[r.status as Status] || STATUS_STYLES.open}`}>
                      {STATUS_LABELS[r.status as Status] || r.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-white/40" title={fmtAbsolute(r.createdAt)}>{fmtTime(r.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {data && data.pages > 1 && (
        <div className="flex items-center justify-between text-xs text-white/40">
          <span>Page {data.page} of {data.pages}</span>
          <div className="flex items-center gap-2">
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} className="p-1.5 rounded hover:bg-white/[0.04] disabled:opacity-30 transition-colors">
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button onClick={() => setPage((p) => Math.min(data.pages, p + 1))} disabled={page === data.pages} className="p-1.5 rounded hover:bg-white/[0.04] disabled:opacity-30 transition-colors">
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Detail drawer */}
      {selected && (
        <div className="fixed inset-0 z-50 flex">
          <div className="flex-1 bg-black/60 backdrop-blur-sm" onClick={closeDetail} />
          <div className="w-full max-w-2xl bg-[#0d1424] border-l border-white/[0.08] overflow-y-auto p-6 space-y-5">
            {/* Header */}
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-xs text-white/40">{selected.displayId}</span>
                  <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${STATUS_STYLES[selected.status as Status] || STATUS_STYLES.open}`}>
                    {STATUS_LABELS[selected.status as Status] || selected.status}
                  </span>
                </div>
                <h2 className="text-lg font-semibold text-white">{selected.subject || <span className="text-white/40 italic">(no subject)</span>}</h2>
                <div className="text-sm text-white/60 mt-1">
                  From <span className="text-white">{selected.name}</span> &lt;<a href={`mailto:${selected.email}`} className="text-teal-400 hover:text-teal-300">{selected.email}</a>&gt;
                </div>
                <div className="text-xs text-white/30 mt-1">{fmtAbsolute(selected.createdAt)}</div>
              </div>
              <button onClick={closeDetail} className="p-1.5 rounded text-white/40 hover:text-white hover:bg-white/[0.06] transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Message */}
            <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-4">
              <div className="text-[11px] uppercase tracking-wider text-white/40 mb-2">Message</div>
              <div className="text-sm text-white/80 whitespace-pre-wrap break-words">{selected.message}</div>
            </div>

            {/* Origin */}
            <details className="rounded-lg border border-white/[0.04] bg-white/[0.01] px-4 py-2">
              <summary className="text-[11px] uppercase tracking-wider text-white/30 cursor-pointer">Origin metadata</summary>
              <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                <div>
                  <div className="text-white/30">IP</div>
                  <div className="text-white/60 font-mono">{selected.ipAddress || "—"}</div>
                </div>
                <div>
                  <div className="text-white/30">User Agent</div>
                  <div className="text-white/60 break-words">{selected.userAgent || "—"}</div>
                </div>
                {selected.referer && (
                  <div className="sm:col-span-2">
                    <div className="text-white/30">Referer</div>
                    <div className="text-white/60 break-all">{selected.referer}</div>
                  </div>
                )}
              </div>
            </details>

            {/* Reply (existing) */}
            {selected.replyMessage && (
              <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.04] p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="text-[11px] uppercase tracking-wider text-emerald-300">Reply sent</div>
                  <div className="text-[11px] text-white/40">
                    {selected.repliedBy ? `by ${selected.repliedBy} · ` : ""}{fmtAbsolute(selected.repliedAt)}
                  </div>
                </div>
                {selected.replySubject && <div className="text-sm font-semibold text-white mb-1">{selected.replySubject}</div>}
                <div className="text-sm text-white/70 whitespace-pre-wrap break-words">{selected.replyMessage}</div>
              </div>
            )}

            {/* Reply composer */}
            {replyOpen ? (
              <div className="rounded-lg border border-teal-500/30 bg-teal-500/[0.04] p-4 space-y-3">
                <div className="text-[11px] uppercase tracking-wider text-teal-300">Compose reply</div>
                <input
                  type="text"
                  placeholder={selected.subject ? `Re: ${selected.subject}` : "Subject"}
                  value={replySubject}
                  onChange={(e) => setReplySubject(e.target.value)}
                  className="w-full h-10 rounded-md border border-white/[0.08] bg-white/[0.04] px-3 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40"
                />
                <textarea
                  rows={8}
                  placeholder={`Hi ${selected.name},\n\nThanks for reaching out…`}
                  value={replyMessage}
                  onChange={(e) => setReplyMessage(e.target.value)}
                  maxLength={10000}
                  className="w-full rounded-md border border-white/[0.08] bg-white/[0.04] px-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40 resize-y"
                />
                <div className="flex items-center justify-between text-[11px] text-white/30">
                  <span>Sent from {process.env.NEXT_PUBLIC_EMAIL_FROM || "EMAIL_FROM env"} via Resend.</span>
                  <span>{replyMessage.length} / 10000</span>
                </div>
                <div className="flex justify-end gap-2">
                  <button
                    onClick={() => { setReplyOpen(false); setReplyMessage(""); setReplySubject(""); }}
                    disabled={replying}
                    className="px-3 py-1.5 text-xs text-white/50 hover:text-white transition-colors disabled:opacity-40"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSendReply}
                    disabled={replying || !replyMessage.trim()}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-teal-500/15 text-teal-300 border border-teal-500/30 hover:bg-teal-500/25 transition-colors disabled:opacity-40"
                  >
                    {replying ? <Loader2 className="w-3 h-3 animate-spin" /> : <Send className="w-3 h-3" />}
                    {replying ? "Sending…" : "Send reply"}
                  </button>
                </div>
              </div>
            ) : (
              <button
                onClick={() => setReplyOpen(true)}
                className="w-full inline-flex items-center justify-center gap-2 h-10 rounded-lg bg-teal-500/10 text-teal-300 border border-teal-500/30 hover:bg-teal-500/20 transition-colors text-sm font-semibold"
              >
                <Send className="w-4 h-4" />Compose reply
              </button>
            )}

            {/* Admin notes */}
            <div className="space-y-1.5">
              <label className="text-[11px] uppercase tracking-wider text-white/40">Admin notes (internal)</label>
              <textarea
                rows={3}
                value={adminNotes}
                onChange={(e) => setAdminNotes(e.target.value)}
                placeholder="Notes for the team — never sent to the requester."
                className="w-full rounded-md border border-white/[0.08] bg-white/[0.04] px-3 py-2 text-xs text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40 resize-y"
              />
            </div>

            {/* Status actions */}
            <div className="flex flex-wrap gap-2">
              {STATUS_OPTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => handleStatusChange(s)}
                  disabled={busy || selected.status === s}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${selected.status === s ? STATUS_STYLES[s] : "border-white/[0.08] text-white/50 hover:bg-white/[0.04]"}`}
                >
                  {selected.status === s && <Check className="w-3 h-3" />}
                  {STATUS_LABELS[s]}
                </button>
              ))}
            </div>

            {/* Delete */}
            <div className="pt-3 border-t border-white/[0.04]">
              {confirmDelete ? (
                <div className="flex items-center justify-between gap-3">
                  <div className="text-xs text-red-300 flex items-center gap-2">
                    <AlertOctagon className="w-3.5 h-3.5" />
                    Delete permanently? Cannot be undone.
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => setConfirmDelete(false)} disabled={busy} className="px-3 py-1.5 text-xs text-white/50 hover:text-white transition-colors disabled:opacity-40">Cancel</button>
                    <button onClick={handleDelete} disabled={busy} className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-500/15 text-red-300 border border-red-500/30 hover:bg-red-500/25 transition-colors disabled:opacity-40">
                      <Trash2 className="w-3 h-3" />{busy ? "Deleting…" : "Delete"}
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  onClick={() => setConfirmDelete(true)}
                  className="inline-flex items-center gap-1.5 text-xs text-white/40 hover:text-red-400 transition-colors"
                >
                  <Trash2 className="w-3 h-3" />Delete request
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
