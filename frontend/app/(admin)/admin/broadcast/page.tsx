"use client";
import { useEffect, useState, useCallback } from "react";
import { getAdminAnnouncements, createAdminAnnouncement, deleteAdminAnnouncement, getAdminOrganizations } from "../../../lib/api";
import { Megaphone, Trash2, Info, AlertTriangle, AlertOctagon, X } from "lucide-react";

const KIND_CONFIG = {
  info: {
    label: "Info",
    icon: Info,
    colors: "text-teal-300 bg-teal-500/10 border-teal-500/20",
    badge: "text-teal-300 bg-teal-500/10",
  },
  warning: {
    label: "Warning",
    icon: AlertTriangle,
    colors: "text-amber-300 bg-amber-500/10 border-amber-500/20",
    badge: "text-amber-300 bg-amber-500/10",
  },
  critical: {
    label: "Critical",
    icon: AlertOctagon,
    colors: "text-red-300 bg-red-500/10 border-red-500/20",
    badge: "text-red-300 bg-red-500/10",
  },
};

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

export default function AdminBroadcast() {
  const [announcements, setAnnouncements] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [deleting, setDeleting] = useState<number | null>(null);
  const [orgs, setOrgs] = useState<{ id: number; name: string }[]>([]);

  // Form state
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [kind, setKind] = useState<"info" | "warning" | "critical">("info");
  const [targetOrgId, setTargetOrgId] = useState<number | null>(null);
  const [expiresAt, setExpiresAt] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getAdminAnnouncements();
      setAnnouncements(res.announcements || []);
    } catch (e: any) {
      setError(e?.message || "Failed to load");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    getAdminOrganizations({ limit: 200 }).then((res) => {
      setOrgs((res.organizations || []).map((o: any) => ({ id: o.id, name: o.name })));
    }).catch(() => {});
  }, []);
  useEffect(() => {
    if (banner) {
      const t = setTimeout(() => setBanner(null), 4000);
      return () => clearTimeout(t);
    }
  }, [banner]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!title.trim()) return;
    setSubmitting(true);
    try {
      await createAdminAnnouncement({
        title: title.trim(),
        body: body.trim() || undefined,
        kind,
        targetOrgId: targetOrgId ?? null,
        expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
      });
      setBanner({ kind: "ok", text: "Announcement sent." });
      setTitle(""); setBody(""); setKind("info"); setTargetOrgId(null); setExpiresAt("");
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to send" });
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(id: number) {
    setDeleting(id);
    try {
      await deleteAdminAnnouncement(id);
      setBanner({ kind: "ok", text: "Announcement deleted." });
      load();
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to delete" });
    } finally {
      setDeleting(null);
    }
  }

  const KindIcon = KIND_CONFIG[kind].icon;

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-xl font-semibold text-white">Broadcast</h1>
        <p className="text-xs text-white/30 mt-0.5">Send announcements to all users or a specific organisation</p>
      </div>

      {banner && (
        <div className={`rounded-lg px-4 py-2.5 text-sm ${banner.kind === "ok" ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20" : "bg-red-500/10 text-red-300 border border-red-500/20"}`}>
          {banner.text}
        </div>
      )}

      {/* Compose */}
      <form onSubmit={handleSubmit} className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-5 space-y-4">
        <h2 className="text-sm font-semibold text-white flex items-center gap-2">
          <Megaphone className="w-4 h-4 text-teal-400" />
          New announcement
        </h2>

        <div className="space-y-1">
          <label className="text-xs text-white/40">Title *</label>
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="e.g. Scheduled maintenance on May 3rd"
            required
            className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40"
          />
        </div>

        <div className="space-y-1">
          <label className="text-xs text-white/40">Message (optional)</label>
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder="Additional details shown below the title…"
            rows={3}
            className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/25 focus:outline-none focus:border-teal-500/40 resize-none"
          />
        </div>

        <div className="grid grid-cols-3 gap-3">
          <div className="space-y-1">
            <label className="text-xs text-white/40">Kind</label>
            <select
              value={kind}
              onChange={(e) => setKind(e.target.value as any)}
              className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500/40"
            >
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          <div className="space-y-1">
            <label className="text-xs text-white/40">Target organisation (blank = all)</label>
            <select
              value={targetOrgId ?? ""}
              onChange={(e) => setTargetOrgId(e.target.value ? Number(e.target.value) : null)}
              className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500/40"
            >
              <option value="">All organisations</option>
              {orgs.map((o) => (
                <option key={o.id} value={o.id}>#{o.id} — {o.name}</option>
              ))}
            </select>
          </div>

          <div className="space-y-1">
            <label className="text-xs text-white/40">Expires (blank = never)</label>
            <input
              type="datetime-local"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
              className="w-full bg-white/[0.04] border border-white/[0.08] rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500/40"
            />
          </div>
        </div>

        {/* Preview */}
        {title && (
          <div className={`rounded-lg border px-4 py-3 ${KIND_CONFIG[kind].colors}`}>
            <div className="flex items-start gap-2.5">
              <KindIcon className="w-4 h-4 mt-0.5 shrink-0" />
              <div>
                <div className="text-sm font-semibold">{title}</div>
                {body && <div className="text-xs mt-1 opacity-80">{body}</div>}
              </div>
            </div>
          </div>
        )}

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={submitting || !title.trim()}
            className="px-4 py-2 text-sm bg-teal-500/10 text-teal-300 border border-teal-500/20 rounded-lg hover:bg-teal-500/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {submitting ? "Sending…" : "Send announcement"}
          </button>
        </div>
      </form>

      {/* Existing announcements */}
      <div>
        <h2 className="text-xs font-semibold text-white/40 uppercase tracking-wider mb-3">
          Active announcements ({announcements.filter((a) => a.isActive).length})
        </h2>

        {error && (
          <div className="rounded-lg px-4 py-2.5 text-sm bg-red-500/10 text-red-300 border border-red-500/20 mb-3">{error}</div>
        )}

        {loading ? (
          <div className="text-xs text-white/30 py-4 text-center">Loading…</div>
        ) : !announcements.length ? (
          <div className="rounded-xl border border-white/[0.06] px-4 py-8 text-center text-white/20 text-xs">
            No announcements yet.
          </div>
        ) : (
          <div className="space-y-2">
            {announcements.map((a) => {
              const cfg = KIND_CONFIG[a.kind as keyof typeof KIND_CONFIG] || KIND_CONFIG.info;
              const Icon = cfg.icon;
              const expired = a.expiresAt && new Date(a.expiresAt) < new Date();
              return (
                <div key={a.id} className={`rounded-xl border px-4 py-3 flex items-start gap-3 ${expired ? "opacity-40" : ""} ${cfg.colors}`}>
                  <Icon className="w-4 h-4 mt-0.5 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-semibold">{a.title}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded font-semibold ${cfg.badge}`}>{a.kind}</span>
                      {a.targetOrgName && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.08] text-white/50">
                          → {a.targetOrgName}
                        </span>
                      )}
                      {!a.targetOrgName && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/[0.08] text-white/50">all orgs</span>
                      )}
                      {expired && <span className="text-[10px] text-white/30">expired</span>}
                    </div>
                    {a.body && <div className="text-xs mt-1 opacity-80">{a.body}</div>}
                    <div className="text-[11px] mt-1.5 opacity-50">
                      Sent {fmtDate(a.createdAt)}{a.createdBy ? ` by ${a.createdBy}` : ""}
                      {a.expiresAt ? ` · Expires ${fmtDate(a.expiresAt)}` : ""}
                    </div>
                  </div>
                  <button
                    onClick={() => handleDelete(a.id)}
                    disabled={deleting === a.id}
                    title="Delete announcement"
                    className="p-1.5 rounded hover:bg-white/[0.08] text-current opacity-40 hover:opacity-80 transition-opacity disabled:opacity-20"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
