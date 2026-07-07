import { NextRequest, NextResponse } from "next/server";
import { getAdminContext, writeAudit } from "@/lib/auth/admin";
import { getPreviewTier, setPreviewTier } from "@/lib/admin/preview-tier";
import { resolveUserTier } from "@/lib/entitlements";
import type { Tier } from "@/lib/patterns/types";

export const runtime = "nodejs";

const TIERS: Tier[] = ["free", "deep", "continuous"];

// GET — the current admin's preview override (if any) and the tier that resolves right now.
export async function GET() {
  const admin = await getAdminContext();
  if (!admin) return NextResponse.json({ error: "forbidden" }, { status: 403 });
  const override = await getPreviewTier(admin.userId);
  const effective = await resolveUserTier(admin.userId);
  return NextResponse.json({ override, effective });
}

// POST { tier: "free" | "deep" | "continuous" | "auto" } — set or clear the override for the
// signed-in admin's own account. Any admin role may toggle their own preview. Audited.
export async function POST(req: NextRequest) {
  const admin = await getAdminContext();
  if (!admin) return NextResponse.json({ error: "forbidden" }, { status: 403 });

  let body: { tier?: string };
  try {
    body = (await req.json()) as { tier?: string };
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const raw = body.tier;
  const next: Tier | null = raw && TIERS.includes(raw as Tier) ? (raw as Tier) : null;
  if (raw && next === null && raw !== "auto") {
    return NextResponse.json({ error: "invalid tier" }, { status: 400 });
  }

  const before = await getPreviewTier(admin.userId);
  await setPreviewTier(admin.userId, next);

  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? undefined;
  await writeAudit({
    actorAdminId: admin.userId,
    action: "admin.preview_tier.set",
    targetType: "admin_tier_overrides",
    targetId: admin.userId,
    before: { tier: before },
    after: { tier: next },
    ip
  });

  const effective = await resolveUserTier(admin.userId);
  return NextResponse.json({ override: next, effective, ok: true });
}
