import { NextRequest, NextResponse } from "next/server";
import { getAdminContext, roleAtLeast, writeAudit } from "@/lib/auth/admin";
import { getServiceSupabase } from "@/lib/supabase/server";
import { IS_DEV_MODE } from "@/lib/devmode";
import { STATIC_PATTERNS } from "@/lib/patterns";

export const runtime = "nodejs";

// GET  /api/admin/patterns          -> list all patterns (incl. disabled)
// POST /api/admin/patterns          -> create a pattern (analyst+); snapshots a version + audits
export async function GET() {
  const admin = await getAdminContext();
  if (!admin) return NextResponse.json({ error: "forbidden" }, { status: 403 });
  // DEV_MODE: serve the built-in static library so the console is populated without Supabase.
  if (IS_DEV_MODE) {
    const patterns = STATIC_PATTERNS.map((p) => ({
      id: p.slug,
      slug: p.slug,
      platform: p.platform,
      category: p.category,
      severity_default: p.severityDefault,
      title: p.title,
      tier_required: p.tierRequired,
      enabled: p.enabled,
      version: p.version
    }));
    return NextResponse.json({ patterns });
  }
  const svc = getServiceSupabase();
  const { data } = await svc.from("patterns").select("*").order("updated_at", { ascending: false });
  return NextResponse.json({ patterns: data ?? [] });
}

export async function POST(req: NextRequest) {
  const admin = await getAdminContext();
  if (!admin || !roleAtLeast(admin.role, "analyst"))
    return NextResponse.json({ error: "forbidden" }, { status: 403 });

  const body = await req.json().catch(() => null);
  if (!body?.slug || !body?.platform || !body?.detector_kind)
    return NextResponse.json({ error: "slug, platform, detector_kind required" }, { status: 400 });

  const svc = getServiceSupabase();
  const row = {
    slug: body.slug,
    platform: body.platform,
    category: body.category ?? "Uncategorized",
    severity_default: body.severity_default ?? "medium",
    title: body.title ?? body.slug,
    description: body.description ?? "",
    impact_oneline: body.impact_oneline ?? "",
    detector_kind: body.detector_kind,
    detector_config: body.detector_config ?? {},
    tier_required: body.tier_required ?? "free",
    remediation_json: body.remediation_json ?? null,
    fix_prompt: body.fix_prompt ?? null,
    enabled: body.enabled ?? true,
    created_by: admin.userId,
    version: 1
  };
  const { data, error } = await svc.from("patterns").insert(row).select("*").single();
  if (error) return NextResponse.json({ error: error.message }, { status: 400 });

  await svc.from("pattern_versions").insert({
    pattern_id: data.id,
    version: 1,
    snapshot: data,
    changed_by: admin.userId
  });
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? undefined;
  await writeAudit({
    actorAdminId: admin.userId,
    action: "pattern.create",
    targetType: "pattern",
    targetId: data.id,
    after: data,
    ip
  });

  return NextResponse.json({ pattern: data });
}
