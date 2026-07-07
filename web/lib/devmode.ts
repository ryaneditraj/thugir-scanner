import type { Tier } from "./patterns/types";

// Local development / demo mode. When DEV_MODE=1 the app runs WITHOUT Supabase, Upstash,
// or Razorpay: auth is bypassed with a fake user, scans are not persisted, and protected
// routes are reachable. This lets the real scan engine + blur gate be tested end-to-end.
//
// NEVER enable this in production. It is opt-in via the DEV_MODE env var only.
export const IS_DEV_MODE = process.env.DEV_MODE === "1";

export const DEV_USER = {
  id: "00000000-0000-0000-0000-000000000000",
  email: "dev@thugir.local"
};

// Optionally test tier-gated UI/blur behaviour: DEV_TIER=free|deep|continuous (default free).
export function devTier(): Tier {
  const t = process.env.DEV_TIER;
  if (t === "deep" || t === "continuous") return t;
  return "free";
}
