import { NextRequest, NextResponse } from "next/server";
import { getAdminContext, roleAtLeast, writeAudit } from "@/lib/auth/admin";
import { loadMaskedSettings, applyPatch } from "@/lib/settings/store";
import type { DeepPartial, PlatformSettings } from "@/lib/settings/schema";

export const runtime = "nodejs";

// GET — masked settings for the panel (AI keys reduced to set/last4).
export async function GET() {
  const admin = await getAdminContext();
  if (!admin) return NextResponse.json({ error: "forbidden" }, { status: 403 });
  return NextResponse.json({ settings: await loadMaskedSettings() });
}

// PATCH — owner only. Deep-merges the partial; empty AI keys are preserved. Audited.
export async function PATCH(req: NextRequest) {
  const admin = await getAdminContext();
  if (!admin || !roleAtLeast(admin.role, "owner"))
    return NextResponse.json({ error: "forbidden — owner role required" }, { status: 403 });

  let patch: DeepPartial<PlatformSettings>;
  try {
    patch = (await req.json()) as DeepPartial<PlatformSettings>;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const masked = await applyPatch(patch);

  // Audit: record which sections changed, never the secret values.
  const sections = Object.keys(patch ?? {});
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? undefined;
  await writeAudit({
    actorAdminId: admin.userId,
    action: "settings.update",
    targetType: "platform_settings",
    targetId: "singleton",
    after: { sections },
    ip
  });

  return NextResponse.json({ settings: masked, ok: true });
}
