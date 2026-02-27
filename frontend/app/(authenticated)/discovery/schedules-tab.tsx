// FILE: app/(authenticated)/discovery/schedules-tab.tsx
"use client";

import React, { useEffect, useState, useCallback } from "react";
import {
  Plus, Clock, Trash2, Play, Loader2, Calendar, CheckCircle2,
  XCircle, MoreVertical, Pencil, Power, PowerOff,
} from "lucide-react";
import { Button } from "../../ui/button";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../ui/dialog";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from "../../ui/dropdown-menu";
import { useOrg } from "../contexts/OrgContext";
import {
  getDiscoverySchedules, createDiscoverySchedule, updateDiscoverySchedule,
  deleteDiscoverySchedule, runScheduleNow,
  type DiscoverySchedule,
} from "../../lib/discovery-api";

function cn(...p: Array<string | false | null | undefined>) { return p.filter(Boolean).join(" "); }

function timeAgo(d?: string | null) {
  if (!d) return "Never";
  const dt = new Date(d);
  if (isNaN(dt.getTime())) return "—";
  const sec = Math.floor((Date.now() - dt.getTime()) / 1000);
  if (sec < 60) return "just now";
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

function timeUntil(d?: string | null) {
  if (!d) return "—";
  const dt = new Date(d);
  if (isNaN(dt.getTime())) return "—";
  const sec = Math.floor((dt.getTime() - Date.now()) / 1000);
  if (sec < 0) return "Overdue";
  if (sec < 3600) return `in ${Math.floor(sec / 60)}m`;
  if (sec < 86400) return `in ${Math.floor(sec / 3600)}h`;
  return `in ${Math.floor(sec / 86400)}d`;
}

const DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

export default function DiscoverySchedulesTab() {
  const { canDo } = useOrg();
  const canManage = canDo("run_discovery");

  const [schedules, setSchedules] = useState<DiscoverySchedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  const [runningIds, setRunningIds] = useState<Set<number>>(new Set());

  // Form
  const [formName, setFormName] = useState("");
  const [formTarget, setFormTarget] = useState("");
  const [formTargetType, setFormTargetType] = useState("domain");
  const [formDepth, setFormDepth] = useState("standard");
  const [formFreq, setFormFreq] = useState("weekly");
  const [formDow, setFormDow] = useState(0);
  const [formDom, setFormDom] = useState(1);
  const [formHour, setFormHour] = useState(2);

  useEffect(() => { if (banner) { const t = setTimeout(() => setBanner(null), 5000); return () => clearTimeout(t); } }, [banner]);

  const load = useCallback(async () => {
    try {
      setLoading(true);
      setSchedules(await getDiscoverySchedules());
    }
    catch { setBanner({ kind: "err", text: "Failed to load schedules" }); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  function resetForm() {
    setFormName(""); setFormTarget(""); setFormTargetType("domain");
    setFormDepth("standard"); setFormFreq("weekly"); setFormDow(0); setFormDom(1); setFormHour(2);
  }

  async function handleCreate() {
    if (!formName.trim() || !formTarget.trim()) return;
    try {
      setSaving(true);
      await createDiscoverySchedule({
        name: formName.trim(), target: formTarget.trim(), targetType: formTargetType,
        scanDepth: formDepth, frequency: formFreq,
        dayOfWeek: formFreq === "weekly" ? formDow : undefined,
        dayOfMonth: formFreq === "monthly" ? formDom : undefined,
        hour: formHour,
      });
      setBanner({ kind: "ok", text: "Schedule created!" });
      setCreateOpen(false); resetForm(); load();
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed" }); }
    finally { setSaving(false); }
  }

  async function handleEdit() {
    if (!editingId || !formName.trim() || !formTarget.trim()) return;
    try {
      setSaving(true);
      await updateDiscoverySchedule(editingId, {
        name: formName.trim(), target: formTarget.trim(), targetType: formTargetType,
        scanDepth: formDepth, frequency: formFreq,
        dayOfWeek: formFreq === "weekly" ? formDow : undefined,
        dayOfMonth: formFreq === "monthly" ? formDom : undefined,
        hour: formHour,
      });
      setBanner({ kind: "ok", text: "Schedule updated" });
      setEditOpen(false); resetForm(); load();
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed" }); }
    finally { setSaving(false); }
  }

  function openEdit(s: DiscoverySchedule) {
    setEditingId(s.id); setFormName(s.name); setFormTarget(s.target);
    setFormTargetType(s.targetType); setFormDepth(s.scanDepth);
    setFormFreq(s.frequency); setFormDow(s.dayOfWeek ?? 0);
    setFormDom(s.dayOfMonth ?? 1); setFormHour(s.hour); setEditOpen(true);
  }

  async function handleToggle(s: DiscoverySchedule) {
    try {
      await updateDiscoverySchedule(s.id, { enabled: !s.enabled });
      setBanner({ kind: "ok", text: `Schedule ${s.enabled ? "paused" : "enabled"}` }); load();
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed" }); }
  }

  async function handleDelete(id: number) {
    try { await deleteDiscoverySchedule(id); setBanner({ kind: "ok", text: "Schedule deleted" }); load(); }
    catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed" }); }
  }

  async function handleRunNow(id: number) {
    try {
      setRunningIds((p) => new Set([...p, id]));
      const r = await runScheduleNow(id);
      setBanner({ kind: "ok", text: `Discovery started! Job #${r.jobId}` }); load();
    } catch (e: any) { setBanner({ kind: "err", text: e?.message || "Failed" }); }
    finally { setRunningIds((p) => { const n = new Set(p); n.delete(id); return n; }); }
  }

  const isDialogOpen = createOpen || editOpen;
  const placeholder = formTargetType === "ip" ? "e.g., 8.8.8.8" : formTargetType === "asn" ? "e.g., AS13335" : formTargetType === "cidr" ? "e.g., 192.168.1.0/24" : "e.g., example.com";
  const isFormValid = !!(formName.trim() && formTarget.trim());

  if (loading) return <div className="flex items-center justify-center py-12 text-muted-foreground gap-2"><Loader2 className="w-5 h-5 animate-spin" />Loading schedules…</div>;

  return (
    <div className="space-y-6">
      {banner && (
        <div className={cn("rounded-xl border px-4 py-3 text-sm",
          banner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>
          {banner.text}
        </div>
      )}

      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground">Scheduled Discoveries</h2>
          <p className="text-sm text-muted-foreground">Automatically run recurring discovery jobs on your targets.</p>
        </div>
        {canManage && (
          <Button onClick={() => { resetForm(); setCreateOpen(true); }} className="bg-[#00b8d4] hover:bg-[#00b8d4]/90">
            <Plus className="w-4 h-4 mr-2" />New Schedule
          </Button>
        )}
      </div>

      {schedules.length === 0 ? (
        <div className="bg-card border border-border rounded-xl p-12 text-center">
          <Calendar className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" />
          <h3 className="text-foreground font-semibold mb-1">No schedules yet</h3>
          <p className="text-sm text-muted-foreground mb-4">Create a schedule to automatically discover new assets on a recurring basis.</p>
          {canManage && (
            <Button onClick={() => { resetForm(); setCreateOpen(true); }} className="bg-[#00b8d4] hover:bg-[#00b8d4]/90">
              <Plus className="w-4 h-4 mr-2" />Create First Schedule
            </Button>
          )}
        </div>
      ) : (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <table className="w-full">
            <thead className="bg-muted/30 border-b border-border">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase">Name</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase">Target</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase">Frequency</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase">Status</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase">Next Run</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase">Last Run</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-muted-foreground uppercase">Runs</th>
                <th className="px-4 py-3 text-right text-xs font-semibold text-muted-foreground uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {schedules.map((s) => (
                <tr key={s.id} className="hover:bg-accent/30 transition-colors">
                  <td className="px-4 py-3">
                    <div className="text-foreground font-medium text-sm">{s.name}</div>
                    <div className="text-xs text-muted-foreground">{s.scanDepth} depth</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-mono text-sm text-foreground">{s.target}</span>
                    <span className="ml-2 text-xs text-muted-foreground uppercase">{s.targetType}</span>
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    <span className="capitalize">{s.frequency}</span>
                    {s.frequency === "weekly" && s.dayOfWeek != null && <span className="text-xs ml-1">({DAYS[s.dayOfWeek]?.slice(0, 3)})</span>}
                    {s.frequency === "monthly" && s.dayOfMonth != null && <span className="text-xs ml-1">(day {s.dayOfMonth})</span>}
                    <div className="text-xs">{String(s.hour).padStart(2, "0")}:00 UTC</div>
                  </td>
                  <td className="px-4 py-3">
                    {s.enabled
                      ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-[#10b981]/10 text-[#10b981]"><CheckCircle2 className="w-3 h-3" />Active</span>
                      : <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-zinc-500/10 text-zinc-400"><XCircle className="w-3 h-3" />Paused</span>}
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">{s.enabled ? timeUntil(s.nextRunAt) : "—"}</td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">{timeAgo(s.lastRunAt)}</td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">{s.runCount}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2">
                      <Button size="sm" variant="outline" onClick={() => handleRunNow(s.id)} disabled={runningIds.has(s.id)}
                        className="gap-1.5 border-[#00b8d4]/50 text-[#00b8d4] hover:bg-[#00b8d4]/10">
                        {runningIds.has(s.id) ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}Run Now
                      </Button>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm" className="h-8 w-8 p-0"><MoreVertical className="w-4 h-4" /></Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => openEdit(s)}><Pencil className="w-3.5 h-3.5 mr-2" />Edit</DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleToggle(s)}>
                            {s.enabled ? <><PowerOff className="w-3.5 h-3.5 mr-2" />Pause</> : <><Power className="w-3.5 h-3.5 mr-2" />Enable</>}
                          </DropdownMenuItem>
                          <DropdownMenuItem className="text-red-400" onClick={() => handleDelete(s.id)}>
                            <Trash2 className="w-3.5 h-3.5 mr-2" />Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Create / Edit Dialog */}
      <Dialog open={isDialogOpen} onOpenChange={(o) => { if (!o) { setCreateOpen(false); setEditOpen(false); } }}>
        <DialogContent className="bg-card border-border text-foreground sm:max-w-lg">
          <DialogHeader><DialogTitle>{editOpen ? "Edit Schedule" : "New Discovery Schedule"}</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Schedule Name</Label>
              <Input value={formName} onChange={(e) => setFormName(e.target.value)} placeholder="e.g., Weekly domain scan" />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label>Target Type</Label>
                <select value={formTargetType} onChange={(e) => setFormTargetType(e.target.value)}
                  className="w-full h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground">
                  <option value="domain">Domain</option>
                  <option value="ip">IP Address</option>
                  <option value="asn">ASN</option>
                  <option value="cidr">CIDR</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label>Scan Depth</Label>
                <select value={formDepth} onChange={(e) => setFormDepth(e.target.value)}
                  className="w-full h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground">
                  <option value="standard">Standard</option>
                  <option value="deep">Deep</option>
                </select>
              </div>
            </div>

            <div className="space-y-2">
              <Label>Target</Label>
              <Input value={formTarget} onChange={(e) => setFormTarget(e.target.value)} placeholder={placeholder} />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label>Frequency</Label>
                <select value={formFreq} onChange={(e) => setFormFreq(e.target.value)}
                  className="w-full h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground">
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label>Run at (UTC)</Label>
                <select value={formHour} onChange={(e) => setFormHour(Number(e.target.value))}
                  className="w-full h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground">
                  {Array.from({ length: 24 }, (_, i) => (
                    <option key={i} value={i}>{String(i).padStart(2, "0")}:00</option>
                  ))}
                </select>
              </div>
            </div>

            {formFreq === "weekly" && (
              <div className="space-y-2">
                <Label>Day of Week</Label>
                <select value={formDow} onChange={(e) => setFormDow(Number(e.target.value))}
                  className="w-full h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground">
                  {DAYS.map((d, i) => <option key={i} value={i}>{d}</option>)}
                </select>
              </div>
            )}

            {formFreq === "monthly" && (
              <div className="space-y-2">
                <Label>Day of Month</Label>
                <select value={formDom} onChange={(e) => setFormDom(Number(e.target.value))}
                  className="w-full h-10 rounded-md border border-border bg-background px-3 text-sm text-foreground">
                  {Array.from({ length: 28 }, (_, i) => (
                    <option key={i + 1} value={i + 1}>{i + 1}</option>
                  ))}
                </select>
              </div>
            )}

            <div className="flex gap-3 pt-2">
              <Button variant="outline" className="flex-1" onClick={() => { setCreateOpen(false); setEditOpen(false); }}>Cancel</Button>
              <Button className="flex-1 bg-[#00b8d4] hover:bg-[#00b8d4]/90"
                onClick={editOpen ? handleEdit : handleCreate}
                disabled={saving || !isFormValid}>
                {saving ? "Saving…" : editOpen ? "Save Changes" : "Create Schedule"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}