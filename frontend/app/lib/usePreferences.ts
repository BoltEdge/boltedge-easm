"use client";

import { useEffect, useState, useCallback } from "react";
import { getPreferences, patchPreferences, type UserPreferences } from "./api";

const DEFAULTS: UserPreferences = { showProvenanceTags: false };

export function usePreferences() {
  const [prefs, setPrefs] = useState<UserPreferences>(DEFAULTS);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getPreferences()
      .then((p) => {
        if (!cancelled) setPrefs(p);
      })
      .catch(() => {
        // Keep DEFAULTS on failure — the toggle just stays off.
      })
      .finally(() => {
        if (!cancelled) setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const update = useCallback(async (patch: Partial<UserPreferences>) => {
    setPrefs((cur) => ({ ...cur, ...patch })); // optimistic
    try {
      const next = await patchPreferences(patch);
      setPrefs(next);
    } catch {
      // Roll back on failure — the toggle reverts.
      const fresh = await getPreferences().catch(() => DEFAULTS);
      setPrefs(fresh);
    }
  }, []);

  return { prefs, loaded, update };
}
