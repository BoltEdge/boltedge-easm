// Stripe frontend config.
//
// All Stripe keys we read here are PUBLIC by design. The publishable
// key (`pk_test_...` / `pk_live_...`) is safe to ship in client JS;
// the secret key (`sk_*`) MUST never be exposed and is read only on
// the backend.
//
// `NEXT_PUBLIC_*` vars are baked into the bundle at build time, so
// changing them on a running container requires a rebuild.

import { BILLING_ENABLED } from "./billing-config";

export const STRIPE_PUBLISHABLE_KEY =
  process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY || "";

export type BillingCycle = "monthly" | "annual";

export type StripePlanKey =
  | "starter"
  | "professional"
  | "enterprise_silver";

/**
 * Whether a given plan key is purchasable through Stripe Checkout.
 * Free is never purchasable; Enterprise Gold is sales-priced and
 * routed through the contact form, not Checkout.
 */
export function isStripePurchasable(plan: string): plan is StripePlanKey {
  return (
    plan === "starter" ||
    plan === "professional" ||
    plan === "enterprise_silver"
  );
}

/**
 * Whether the frontend should expose Stripe Checkout buttons for this
 * plan. Combines the feature flag with the per-plan eligibility check.
 *
 * The actual Price IDs live on the backend in `STRIPE_PRICE_*` env vars
 * — the frontend only needs to know "yes/no, can the user click Buy".
 */
export function canCheckout(plan: string): boolean {
  return BILLING_ENABLED && isStripePurchasable(plan);
}
