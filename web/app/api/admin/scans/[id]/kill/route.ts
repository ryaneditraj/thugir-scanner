import { NextRequest, NextResponse } from "next/server";
import { getAdminContext, writeAudit } from "@/lib/auth/admin";
import { getServiceSupabase } from "@/lib/supabase/server";

export const runtime = "nodejs";

// POST /api/admin/scans/:id/kill -> mark a stuck/abusive scan as killed.
// The worker checks scan.status cooperatively and aborts when it sees "killed".
export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  const admin = await getAdminContext();
  if (!admin) return NextResponse.json({ error: "forbidden" }, { status: 403 });

  const svc = getServiceSupabase();
  const { data: before } = await svc.from("scans").select("*").eq("id", params.id).single();
  if (!before) return NextResponse.json({ error: "not found" }, { status: 404 });

  await svc
    .from("scans")
    .update({ status: "killed", finished_at: new Date().toISOString(), error: "killed by admin" })
    .eq("id", params.id);

  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? undefined;
  await writeAudit({
    actorAdminId: admin.userId,
    action: "scan.kill",
    targetType: "scan",
    targetId: params.id,
    before,
    ip
  });
  return NextResponse.json({ killed: true });
}
