// Feature flag: set NEXT_PUBLIC_ENABLE_BILLING=true to restore full payment/pricing UI.
// When false: plans are free tiers, no prices shown, no checkout triggered.
export const BILLING_ENABLED = process.env.NEXT_PUBLIC_ENABLE_BILLING === "true";
