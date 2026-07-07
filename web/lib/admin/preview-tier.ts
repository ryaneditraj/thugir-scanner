import { promises as fs } from "fs";
import path from "path";
import type { Tier } from "../patterns/types";
import { IS_DEV_MODE } from "../devmode";

// Per-admin "preview tier" override. Lets a signed-in admin force their OWN account to behave as
// free / deep / continuous so they can see the platform the way each tier of customer sees it.
//
// This NEVER grants entitlements to non-admins: only the admin API (gated by getAdminContext) can
// write a row, so any stored override necessarily belongs to an admin account.
//   - DEV_MODE: a JSON map on disk (Vercel's fs is read-only, so prod uses Supabase).
//   - PROD: the `admin_tier_overrides` table, keyed by admin id.

const DEV_FILE = path.join(process.cwd(), ".data", "admin-preview-tier.json");

function isTier(v: unknown): v is Tier {
  return v === "free" || v === "deep" || v === "continuous";
}

async function readDevMap(): Promise<Record<string, Tier>> {
  try {
    const raw = await fs.readFile(DEV_FILE, "utf8");
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const out: Record<string, Tier> = {};
    for (const [k, v] of Object.entries(parsed)) if (isTier(v)) out[k] = v;
    return out;
  } catch {
    return {};
  }
}

async function writeDevMap(map: Record<string, Tier>): Promise<void> {
  await fs.mkdir(path.dirname(DEV_FILE), { recursive: true });
  await fs.writeFile(DEV_FILE, JSON.stringify(map, null, 2), "utf8");
}

// Resolve the override for a user, or null if none is set.
export async function getPreviewTier(userId: string): Promise<Tier | null> {
  if (IS_DEV_MODE) {
    const map = await readDevMap();
    return map[userId] ?? null;
  }
  const { getServiceSupabase } = await import("../supabase/server");
  const svc = getServiceSupabase();
  const { data } = await svc
    .from("admin_tier_overrides")
    .select("tier")
    .eq("admin_id", userId)
    .maybeSingle();
  return isTier(data?.tier) ? (data!.tier as Tier) : null;
}

// Set (or clear, when tier is null) the override for a user.
export async function setPreviewTier(userId: string, tier: Tier | null): Promise<void> {
  if (IS_DEV_MODE) {
    const map = await readDevMap();
    if (tier) map[userId] = tier;
    else delete map[userId];
    await writeDevMap(map);
    return;
  }
  const { getServiceSupabase } = await import("../supabase/server");
  const svc = getServiceSupabase();
  if (tier) {
    await svc
      .from("admin_tier_overrides")
      .upsert({ admin_id: userId, tier, updated_at: new Date().toISOString() });
  } else {
    await svc.from("admin_tier_overrides").delete().eq("admin_id", userId);
  }
}
