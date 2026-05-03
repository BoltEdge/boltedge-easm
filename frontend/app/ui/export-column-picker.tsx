// FILE: app/ui/export-column-picker.tsx
//
// Reusable modal for picking which columns to include in a CSV
// download. Used by both the asset-group export and the discovery
// export — same UX, different column lists.
//
// The modal handles the auth'd fetch + blob + browser download
// itself, so call sites just specify the endpoint and column
// catalogue.

"use client";

import React, { useMemo, useState } from "react";
import { Loader2, Download, X } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "./dialog";
import { Button } from "./button";
import { cn } from "../lib/utils";
import { getAccessToken } from "../lib/auth";
import { API_BASE_URL } from "../lib/api";

export type ExportColumn = {
  /** Column key matched against the backend's column catalogue */
  key: string;
  /** Human label shown next to the checkbox */
  label: string;
};

export type ExportColumnGroup = {
  /** Section heading e.g. "Identification" */
  title: string;
  columns: ExportColumn[];
};

export type ExportPreset = {
  key: string;
  label: string;
  /** Column keys this preset selects */
  columns: string[];
};

export type ExportColumnPickerProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  /** Optional one-line subtitle under the title */
  description?: string;
  groups: ExportColumnGroup[];
  presets: ExportPreset[];
  /** Which preset to apply when the modal first opens */
  defaultPreset: string;
  /**
   * Backend endpoint that returns text/csv. We append `columns=...`
   * (and any `extraParams`) to it. Example: "/groups/42/assets/export"
   */
  endpoint: string;
  /** Additional query params (e.g. "ids=1,2,3" for selected-only export) */
  extraParams?: Record<string, string>;
  /** Filename for the downloaded file */
  filename: string;
  /** Optional callback after a successful download */
  onDownloaded?: () => void;
};

export function ExportColumnPicker({
  open,
  onOpenChange,
  title,
  description,
  groups,
  presets,
  defaultPreset,
  endpoint,
  extraParams,
  filename,
  onDownloaded,
}: ExportColumnPickerProps) {
  const allColumnKeys = useMemo(
    () => groups.flatMap((g) => g.columns.map((c) => c.key)),
    [groups],
  );

  const initialSelection = useMemo(() => {
    const preset = presets.find((p) => p.key === defaultPreset);
    return new Set(preset?.columns ?? allColumnKeys);
  }, [presets, defaultPreset, allColumnKeys]);

  const [selected, setSelected] = useState<Set<string>>(initialSelection);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Reset selection whenever the modal opens — avoids stale state
  // from a previous open.
  React.useEffect(() => {
    if (open) {
      setSelected(initialSelection);
      setError(null);
    }
  }, [open, initialSelection]);

  function toggle(key: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function applyPreset(presetKey: string) {
    const preset = presets.find((p) => p.key === presetKey);
    if (!preset) return;
    setSelected(new Set(preset.columns));
  }

  // Detect which preset (if any) currently matches the selected set.
  // Used to render the active preset button in primary state.
  const activePresetKey = useMemo(() => {
    for (const p of presets) {
      if (
        p.columns.length === selected.size &&
        p.columns.every((c) => selected.has(c))
      ) {
        return p.key;
      }
    }
    return null;
  }, [presets, selected]);

  async function handleDownload() {
    if (selected.size === 0) {
      setError("Pick at least one column.");
      return;
    }
    setDownloading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.set("columns", Array.from(selected).join(","));
      for (const [k, v] of Object.entries(extraParams || {})) {
        if (v) params.set(k, v);
      }
      const url = `${API_BASE_URL}${endpoint}?${params.toString()}`;
      const token = getAccessToken();
      const res = await fetch(url, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        credentials: "include",
      });
      if (!res.ok) {
        throw new Error(`Server returned ${res.status}`);
      }
      const blob = await res.blob();
      const objectUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = objectUrl;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(objectUrl);

      onOpenChange(false);
      onDownloaded?.();
    } catch (e: any) {
      setError(e?.message || "Download failed.");
    } finally {
      setDownloading(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border text-foreground sm:max-w-[520px] max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
        </DialogHeader>

        {description && (
          <p className="text-sm text-muted-foreground -mt-2">{description}</p>
        )}

        {/* Presets */}
        <div className="space-y-2">
          <div className="text-[11px] font-medium text-muted-foreground uppercase tracking-wide">
            Quick presets
          </div>
          <div className="flex gap-2">
            {presets.map((p) => (
              <button
                key={p.key}
                type="button"
                onClick={() => applyPreset(p.key)}
                className={cn(
                  "flex-1 rounded-lg border px-3 py-2 text-sm font-medium transition-colors",
                  activePresetKey === p.key
                    ? "border-primary bg-primary/10 text-foreground"
                    : "border-border text-muted-foreground hover:bg-accent",
                )}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* Column groups */}
        <div className="space-y-4">
          {groups.map((group) => (
            <div key={group.title}>
              <div className="text-[11px] font-medium text-muted-foreground uppercase tracking-wide mb-2">
                {group.title}
              </div>
              <div className="grid grid-cols-2 gap-x-4 gap-y-2">
                {group.columns.map((col) => (
                  <label
                    key={col.key}
                    className="flex items-center gap-2 text-sm text-foreground cursor-pointer hover:text-foreground/90"
                  >
                    <input
                      type="checkbox"
                      checked={selected.has(col.key)}
                      onChange={() => toggle(col.key)}
                      className="rounded border-border accent-[var(--primary,_#14b8a6)]"
                    />
                    <span>{col.label}</span>
                  </label>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between pt-2">
          <span className="text-xs text-muted-foreground">
            {selected.size} {selected.size === 1 ? "column" : "columns"} selected
          </span>
          <div className="flex gap-3">
            <Button
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={downloading}
              className="border-border text-foreground hover:bg-accent"
            >
              Cancel
            </Button>
            <Button
              onClick={handleDownload}
              disabled={downloading || selected.size === 0}
              className="bg-primary hover:bg-primary/90"
            >
              {downloading ? (
                <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Downloading…</>
              ) : (
                <><Download className="w-4 h-4 mr-2" />Download CSV</>
              )}
            </Button>
          </div>
        </div>

        {error && (
          <div className="mt-2 flex items-center justify-between rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-200">
            <span>{error}</span>
            <button onClick={() => setError(null)} className="opacity-60 hover:opacity-100">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
