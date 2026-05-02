/**
 * Display IDs — the human-readable identifier format the API emits.
 *
 *   SC0042 — scan job 42      MO0012 — monitor 12
 *   AS0150 — asset 150        AL0034 — monitor alert 34
 *   FN0299 — finding 299      OR0003 — organisation 3
 *
 * Backend serializers now return `displayId` alongside the integer `id`
 * on every entity. UI surfaces should use `displayId` for display; calls
 * back to the API can use either form (backend accepts both).
 *
 * If `displayId` is missing for any reason (older response, draft entity),
 * `formatId(prefix, id)` produces the same value the backend would.
 */

export type EntityPrefix =
  | "AK"  // API key
  | "AS"  // Asset
  | "GR"  // Asset group
  | "LG"  // Audit log entry
  | "BL"  // Blocked IP
  | "DC"  // Discovery job
  | "FN"  // Finding
  | "MO"  // Monitor
  | "AL"  // Monitor alert
  | "OR"  // Organisation
  | "IN"  // Pending invite
  | "AN"  // Platform announcement
  | "QS"  // Quick scan log
  | "RP"  // Report
  | "SC"  // Scan job
  | "PR"  // Scan profile
  | "SH"  // Scan schedule
  | "US"; // User

/**
 * Format an integer id into the display form.
 *
 *   formatId("SC", 42)    → "SC0042"
 *   formatId("AS", 150)   → "AS0150"
 *   formatId("FN", 12345) → "FN12345"   // grows naturally for big ids
 *
 * Use the API's `displayId` field whenever possible — call this only as
 * a fallback when you don't have it.
 */
export function formatId(prefix: EntityPrefix, integerId: number | string): string {
  const n = typeof integerId === "string" ? parseInt(integerId, 10) : integerId;
  if (!Number.isFinite(n)) return `${prefix}????`;
  return `${prefix}${String(n).padStart(4, "0")}`;
}

/**
 * Parse a display id back to its integer form.
 *
 *   parseId("SC0042")  → 42
 *   parseId("invalid") → null
 */
export function parseId(displayId: string): number | null {
  if (!displayId || typeof displayId !== "string") return null;
  const m = displayId.trim().toUpperCase().match(/^([A-Z]{2})(\d+)$/);
  if (!m) return null;
  const n = parseInt(m[2], 10);
  return Number.isFinite(n) ? n : null;
}

/**
 * Coalesce a possibly-missing `displayId` into a presentable string.
 * Falls back to `formatId(prefix, id)` when the API didn't provide one,
 * and finally to the raw integer if even that fails.
 */
export function displayIdOf(
  entity: { displayId?: string | null; id: number | string } | null | undefined,
  prefix: EntityPrefix,
): string {
  if (!entity) return "";
  if (entity.displayId) return entity.displayId;
  return formatId(prefix, entity.id);
}
