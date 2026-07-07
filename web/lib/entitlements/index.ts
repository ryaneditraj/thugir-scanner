import type { Tier } from "../patterns/types";
import { getServiceSupabase } from "../supabase/server";
import { IS_DEV_MODE, devTier } from "../devmode";
import { getPreviewTier } from "../admin/preview-tier";

// Resolve the highest tier a user is currently entitled to. Free is always available.
export async function resolveUserTier(userId: string): Promise<Tier> {
  // Admin preview override wins (only admins can ever have one set) — lets an operator view the
  // platform as a free / deep / continuous customer for testing.
  const override = await getPreviewTier(userId);
  if (override) return override;

  if (IS_DEV_MODE) return devTier();
  const svc = getServiceSupabase();
  const { data } = await svc
    .from("entitlements")
    .select("kind, status, expires_at")
    .eq("user_id", userId)
    .eq("status", "active");
  const now = Date.now();
  const active = (data ?? []).filter(
    (e) => !e.expires_at || new Date(e.expires_at).getTime() > now
  );
  if (active.some((e) => e.kind === "continuous_sub")) return "continuous";
  if (active.some((e) => e.kind === "deep_scan_credit")) return "deep";
  return "free";
}

// Whether a user holds at least one consumable deep scan credit.
export async function hasDeepCredit(userId: string): Promise<boolean> {
  const svc = getServiceSupabase();
  const { data } = await svc
    .from("entitlements")
    .select("id")
    .eq("user_id", userId)
    .eq("kind", "deep_scan_credit")
    .eq("status", "active")
    .limit(1);
  return (data ?? []).length > 0;
}

// Consume one deep scan credit (mark it consumed). Returns true if one was consumed.
export async function consumeDeepCredit(userId: string): Promise<boolean> {
  const svc = getServiceSupabase();
  const { data } = await svc
    .from("entitlements")
    .select("id")
    .eq("user_id", userId)
    .eq("kind", "deep_scan_credit")
    .eq("status", "active")
    .limit(1);
  const credit = (data ?? [])[0];
  if (!credit) return false;
  await svc.from("entitlements").update({ status: "consumed" }).eq("id", credit.id);
  return true;
}
