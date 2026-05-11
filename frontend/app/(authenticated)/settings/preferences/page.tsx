"use client";

import { usePreferences } from "../../../lib/usePreferences";

export default function PreferencesPage() {
  const { prefs, loaded, update } = usePreferences();
  if (!loaded) return <div className="p-6 text-sm text-white/55">Loading…</div>;

  return (
    <div className="mx-auto max-w-3xl px-6 py-10 space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Preferences</h1>
        <p className="mt-2 text-sm text-white/65">Personal display settings.</p>
      </div>

      <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-5">
        <label className="flex items-start gap-3 cursor-pointer">
          <input
            type="checkbox"
            className="mt-1"
            checked={prefs.showProvenanceTags}
            onChange={(e) => update({ showProvenanceTags: e.target.checked })}
          />
          <div className="min-w-0">
            <div className="text-sm font-semibold text-white">Show recurrence tags on findings</div>
            <div className="mt-1 text-xs text-white/65 leading-relaxed">
              Adds a small pill next to each finding — NEW for first detections,
              SEEN BEFORE for recurrences, RESOLVED BEFORE for regressions of
              previously-fixed findings. Only affects your own view.
            </div>
          </div>
        </label>
      </div>
    </div>
  );
}
