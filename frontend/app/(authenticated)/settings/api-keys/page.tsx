// FILE: app/(authenticated)/settings/api-keys/page.tsx
// API Keys management — generate, view, revoke API keys
"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Key, Plus, Check, Copy, Trash2, X, RefreshCcw, Pencil } from "lucide-react";
import { cn } from "../../../lib/utils";
import { Button } from "../../../ui/button";
import { Input } from "../../../ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../../ui/dialog";
import { getApiKeys, createApiKey, updateApiKey, revokeApiKey, isPlanError } from "../../../lib/api";
import { useOrg } from "../../contexts/OrgContext";
import { usePlanLimit, PlanLimitDialog } from "../../../ui/plan-limit-dialog";

function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "Never";
  let d: Date;
  if (typeof iso === "string" && !iso.endsWith("Z") && !iso.includes("+")) d = new Date(iso + "Z");
  else d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  const sec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (sec < 60) return "just now";
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  let d: Date;
  if (typeof iso === "string" && !iso.endsWith("Z") && !iso.includes("+")) d = new Date(iso + "Z");
  else d = new Date(iso);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export default function ApiKeysPage() {
  const { canDo } = useOrg();
  const planLimit = usePlanLimit();
  const canManage = canDo("manage_api_keys");

  const [keys, setKeys] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [expiresInDays, setExpiresInDays] = useState<string>("90");
  const [creating, setCreating] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<any>(null);
  const [revoking, setRevoking] = useState(false);
  const [renameTarget, setRenameTarget] = useState<any>(null);
  const [renameValue, setRenameValue] = useState("");
  const [renaming, setRenaming] = useState(false);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [showRevoked, setShowRevoked] = useState(false);

  const visibleKeys = showRevoked ? keys : keys.filter((k) => k.isActive);
  const revokedCount = keys.filter((k) => !k.isActive).length;

  const load = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true); else setLoading(true);
    try { setKeys(await getApiKeys()); }
    catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to load" });
    }
    finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { load(); }, []);
  useEffect(() => { if (banner) { const t = setTimeout(() => setBanner(null), 5000); return () => clearTimeout(t); } }, [banner]);

  async function handleCreate() {
    if (!keyName.trim()) return;
    try {
      setCreating(true);
      const result = await createApiKey({ name: keyName.trim(), expiresInDays: expiresInDays ? Number(expiresInDays) : undefined });
      setNewKey(result.key); setKeyName(""); await load(true);
    } catch (e: any) {
      if (isPlanError(e)) { setCreateOpen(false); planLimit.handle(e.planError); }
      else setBanner({ kind: "err", text: e?.message || "Failed" });
    } finally { setCreating(false); }
  }

  async function handleRename() {
    if (!renameTarget || !renameValue.trim() || renameValue.trim() === renameTarget.name) {
      setRenameTarget(null);
      return;
    }
    try {
      setRenaming(true);
      await updateApiKey(renameTarget.id, { name: renameValue.trim() });
      setBanner({ kind: "ok", text: "API key renamed." });
      setRenameTarget(null);
      await load(true);
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed to rename" });
    } finally { setRenaming(false); }
  }

  async function handleRevoke() {
    if (!revokeTarget) return;
    try {
      setRevoking(true);
      await revokeApiKey(revokeTarget.id);
      setBanner({ kind: "ok", text: "API key revoked." });
      setRevokeTarget(null);
      await load(true);
    } catch (e: any) {
      setBanner({ kind: "err", text: e?.message || "Failed" });
    } finally { setRevoking(false); }
  }

  function handleCopy() {
    if (newKey) { navigator.clipboard.writeText(newKey); setCopied(true); setTimeout(() => setCopied(false), 2000); }
  }

  return (
    <main className="flex-1 overflow-y-auto bg-background">
      <div className="p-8 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-foreground flex items-center gap-3">
              <Key className="w-7 h-7 text-primary" />API Keys
            </h1>
            <p className="text-muted-foreground mt-1">Manage API keys for programmatic access.</p>
          </div>
          <div className="flex items-center gap-2">
            {revokedCount > 0 && (
              <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={showRevoked}
                  onChange={(e) => setShowRevoked(e.target.checked)}
                  className="accent-primary"
                />
                Show revoked ({revokedCount})
              </label>
            )}
            <Button variant="outline" onClick={() => load(true)} disabled={refreshing} className="border-border text-foreground hover:bg-accent">
              <RefreshCcw className={cn("w-4 h-4 mr-2", refreshing && "animate-spin")} />
              {refreshing ? "Refreshing…" : "Refresh"}
            </Button>
            {canManage && (
              <Button onClick={() => { setCreateOpen(true); setNewKey(null); }} className="bg-primary hover:bg-primary/90">
                <Plus className="w-4 h-4 mr-2" />Generate Key
              </Button>
            )}
          </div>
        </div>

        {banner && (
          <div className={cn("rounded-xl border px-4 py-3 text-sm flex items-center justify-between",
            banner.kind === "ok" ? "border-[#10b981]/30 bg-[#10b981]/10 text-[#b7f7d9]" : "border-red-500/30 bg-red-500/10 text-red-200")}>
            <span>{banner.text}</span>
            <button onClick={() => setBanner(null)} className="hover:opacity-70"><X className="w-4 h-4" /></button>
          </div>
        )}

        {loading ? <div className="text-muted-foreground text-sm">Loading...</div> : (
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            {visibleKeys.length === 0 ? (
              <div className="p-12 text-center">
                <Key className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" />
                <h3 className="text-foreground font-semibold mb-2">No API keys yet</h3>
                <p className="text-muted-foreground text-sm mb-4">Generate an API key to access Nano EASM programmatically.</p>
                {canManage && (
                  <Button onClick={() => { setCreateOpen(true); setNewKey(null); }} className="bg-primary hover:bg-primary/90">
                    <Plus className="w-4 h-4 mr-2" />Generate Key
                  </Button>
                )}
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-muted/30">
                  <tr>
                    <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Name</th>
                    <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Key</th>
                    <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Created</th>
                    <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Last Used</th>
                    <th className="text-left p-4 text-sm font-semibold text-muted-foreground">Status</th>
                    {canManage && <th className="text-right p-4 text-sm font-semibold text-muted-foreground">Actions</th>}
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {visibleKeys.map((k) => {
                    const expiresAt = k.expiresAt ? new Date(k.expiresAt.endsWith("Z") || k.expiresAt.includes("+") ? k.expiresAt : k.expiresAt + "Z") : null;
                    const isExpired = !!(expiresAt && expiresAt.getTime() < Date.now());
                    const daysUntilExpiry = expiresAt ? Math.ceil((expiresAt.getTime() - Date.now()) / 86400000) : null;
                    const isExpiringSoon = !isExpired && daysUntilExpiry !== null && daysUntilExpiry <= 7;
                    const dimmed = !k.isActive || isExpired;
                    return (
                      <tr key={k.id} className={cn("hover:bg-accent/30 transition-colors", dimmed && "opacity-50")}>
                        <td className="p-4">
                          <div className="flex items-center gap-2">
                            <Key className="w-4 h-4 text-muted-foreground" />
                            <span className="text-sm font-medium text-foreground">{k.name}</span>
                          </div>
                        </td>
                        <td className="p-4"><code className="text-xs text-muted-foreground font-mono">{k.keyPrefix}•••••••••</code></td>
                        <td className="p-4 text-sm text-muted-foreground">
                          {formatDate(k.createdAt)}<br />
                          <span className="text-xs">by {k.createdBy}</span>
                          {expiresAt ? (
                            <>
                              <br />
                              <span className={cn(
                                "text-xs",
                                isExpired ? "text-red-400" : isExpiringSoon ? "text-amber-400" : ""
                              )}>
                                {isExpired ? "Expired " : "Expires "}{formatDate(k.expiresAt)}
                              </span>
                            </>
                          ) : (
                            <>
                              <br />
                              <span className="text-xs">No expiry</span>
                            </>
                          )}
                        </td>
                        <td className="p-4 text-sm text-muted-foreground">{timeAgo(k.lastUsedAt)}</td>
                        <td className="p-4">
                          {!k.isActive ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-red-500/15 text-red-400 text-xs font-semibold border border-red-500/30">Revoked</span>
                          ) : isExpired ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-zinc-500/15 text-zinc-300 text-xs font-semibold border border-zinc-500/30">Expired</span>
                          ) : isExpiringSoon ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-amber-500/15 text-amber-300 text-xs font-semibold border border-amber-500/30">Expires in {daysUntilExpiry}d</span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-[#10b981]/15 text-[#10b981] text-xs font-semibold border border-[#10b981]/30">Active</span>
                          )}
                        </td>
                        {canManage && (
                          <td className="p-4 text-right">
                            {k.isActive && (
                              <div className="flex items-center justify-end gap-2">
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  onClick={() => { setRenameTarget(k); setRenameValue(k.name); }}
                                  className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground hover:bg-accent"
                                  title="Rename"
                                >
                                  <Pencil className="w-3.5 h-3.5" />
                                </Button>
                                <Button size="sm" variant="outline" onClick={() => setRevokeTarget(k)} className="border-red-500/50 text-red-400 hover:bg-red-500/10 text-xs">
                                  Revoke
                                </Button>
                              </div>
                            )}
                          </td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* Create Dialog */}
        <Dialog
          open={createOpen}
          onOpenChange={(o) => {
            if (!o) {
              setCreateOpen(false);
              setNewKey(null);
              setKeyName("");
              setCopied(false);
            }
          }}
        >
          <DialogContent className="bg-card border-border text-foreground sm:max-w-[480px]">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Key className="w-5 h-5 text-primary" />
                {newKey ? "API Key Created" : "Generate API Key"}
              </DialogTitle>
            </DialogHeader>
            {newKey ? (
              <div className="space-y-4 pt-2">
                <div className="flex items-center gap-2 text-sm text-[#b7f7d9]">
                  <Check className="w-4 h-4 text-[#10b981]" />
                  Copy it now — you won&apos;t see it again.
                </div>
                <div className="flex items-center gap-2">
                  <code className="flex-1 bg-muted/30 rounded-lg px-3 py-2.5 font-mono text-xs text-foreground break-all border border-border">
                    {newKey}
                  </code>
                  <Button size="sm" variant="outline" onClick={handleCopy} className="shrink-0">
                    {copied ? <><Check className="w-3 h-3 mr-1" />Copied</> : <><Copy className="w-3 h-3 mr-1" />Copy</>}
                  </Button>
                </div>
                <div className="flex justify-end pt-2">
                  <Button
                    onClick={() => { setCreateOpen(false); setNewKey(null); setCopied(false); }}
                    className="bg-primary hover:bg-primary/90"
                  >
                    Done
                  </Button>
                </div>
              </div>
            ) : (
              <div className="space-y-4 pt-2">
                <div className="space-y-1.5">
                  <label className="text-sm font-medium text-foreground block">Key Name</label>
                  <Input placeholder="e.g., CI/CD Pipeline" value={keyName} onChange={(e) => setKeyName(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <label className="text-sm font-medium text-foreground block">Expires In</label>
                  <select value={expiresInDays} onChange={(e) => setExpiresInDays(e.target.value)} className="h-10 w-full rounded-md px-3 bg-input-background border border-border text-foreground text-sm">
                    <option value="30">30 days</option>
                    <option value="90">90 days</option>
                    <option value="180">180 days</option>
                    <option value="365">1 year</option>
                    <option value="">Never</option>
                  </select>
                </div>
                <div className="flex gap-3 justify-end pt-2">
                  <Button variant="outline" onClick={() => setCreateOpen(false)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
                  <Button onClick={handleCreate} disabled={creating || !keyName.trim()} className="bg-primary hover:bg-primary/90">
                    <Key className="w-4 h-4 mr-2" />{creating ? "Generating..." : "Generate"}
                  </Button>
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>

        {/* Rename Dialog */}
        <Dialog open={!!renameTarget} onOpenChange={(o) => { if (!o) setRenameTarget(null); }}>
          <DialogContent className="bg-card border-border text-foreground sm:max-w-[440px]">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Pencil className="w-5 h-5 text-primary" />Rename API Key
              </DialogTitle>
            </DialogHeader>
            <div className="space-y-4 pt-2">
              <div className="space-y-1.5">
                <label className="text-sm font-medium text-foreground block">Key Name</label>
                <Input
                  value={renameValue}
                  onChange={(e) => setRenameValue(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") handleRename(); }}
                  autoFocus
                />
              </div>
              <div className="flex gap-3 justify-end pt-2">
                <Button variant="outline" onClick={() => setRenameTarget(null)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
                <Button
                  onClick={handleRename}
                  disabled={renaming || !renameValue.trim() || renameValue.trim() === renameTarget?.name}
                  className="bg-primary hover:bg-primary/90"
                >
                  {renaming ? "Saving..." : "Save"}
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>

        {/* Revoke Dialog */}
        <Dialog open={!!revokeTarget} onOpenChange={(o) => { if (!o) setRevokeTarget(null); }}>
          <DialogContent className="bg-card border-border text-foreground sm:max-w-[440px]">
            <DialogHeader><DialogTitle>Revoke API Key</DialogTitle></DialogHeader>
            <p className="text-sm text-muted-foreground">
              Revoke <span className="text-foreground font-semibold">{revokeTarget?.name}</span>?
              Any applications using this key will immediately lose access.
            </p>
            <div className="flex gap-3 justify-end pt-4">
              <Button variant="outline" onClick={() => setRevokeTarget(null)} className="border-border text-foreground hover:bg-accent">Cancel</Button>
              <Button onClick={handleRevoke} disabled={revoking} className="bg-[#ef4444] hover:bg-[#dc2626] text-white">
                {revoking ? "Revoking..." : "Revoke Key"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <PlanLimitDialog {...planLimit} />
    </main>
  );
}