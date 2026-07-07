import { NextRequest, NextResponse } from "next/server";
import { getAdminContext, roleAtLeast, writeAudit } from "@/lib/auth/admin";
import { getServiceSupabase } from "@/lib/supabase/server";

export const runtime = "nodejs";

// PATCH /api/admin/patterns/:id  -> update; bumps version, snapshots, audits
export async function PATCH(req: NextRequest, { params }: { params: { id: string } }) {
  const admin = await getAdminContext();
  if (!admin || !roleAtLeast(admin.role, "analyst"))
    return NextResponse.json({ error: "forbidden" }, { status: 403 });

  const patch = await req.json().catch(() => null);
  if (!patch) return NextResponse.json({ error: "invalid json" }, { status: 400 });

  const svc = getServiceSupabase();
  const { data: before } = await svc.from("patterns").select("*").eq("id", params.id).single();
  if (!before) return NextResponse.json({ error: "not found" }, { status: 404 });

  const nextVersion = (before.version ?? 1) + 1;
  const update = {
    ...patch,
    version: nextVersion,
    updated_at: new Date().toISOString()
  };
  delete update.id;
  delete update.created_by;

  const { data: after, error } = await svc
    .from("patterns")
    .update(update)
    .eq("id", params.id)
    .select("*")
    .single();
  if (error) return NextResponse.json({ error: error.message }, { status: 400 });

  await svc.from("pattern_versions").insert({
    pattern_id: params.id,
    version: nextVersion,
    snapshot: after,
    changed_by: admin.userId
  });
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? undefined;
  await writeAudit({
    actorAdminId: admin.userId,
    action: "pattern.update",
    targetType: "pattern",
    targetId: params.id,
    before,
    after,
    ip
  });

  return NextResponse.json({ pattern: after });
}

// DELETE disables (soft) rather than hard-deletes, preserving version history.
export async function DELETE(req: NextRequest, { params }: { params: { id: string } }) {
  const admin = await getAdminContext();
  if (!admin || !roleAtLeast(admin.role, "owner"))
    return NextResponse.json({ error: "forbidden" }, { status: 403 });

  const svc = getServiceSupabase();
  const { data: before } = await svc.from("patterns").select("*").eq("id", params.id).single();
  if (!before) return NextResponse.json({ error: "not found" }, { status: 404 });

  await svc.from("patterns").update({ enabled: false }).eq("id", params.id);
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? undefined;
  await writeAudit({
    actorAdminId: admin.userId,
    action: "pattern.disable",
    targetType: "pattern",
    targetId: params.id,
    before,
    ip
  });
  return NextResponse.json({ disabled: true });
}
