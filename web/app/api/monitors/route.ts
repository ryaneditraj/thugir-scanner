import { NextRequest, NextResponse } from "next/server";
import { getServerSupabase, getServiceSupabase } from "@/lib/supabase/server";
import { resolveUserTier } from "@/lib/entitlements";
import { IS_DEV_MODE, DEV_USER } from "@/lib/devmode";
import { normalizeTarget, BlockedTargetError } from "@/lib/checks/http";

export const runtime = "nodejs";

// GET /api/monitors — list monitors for the signed-in continuous subscriber.
// POST /api/monitors { url } — register a target for scheduled Deep Scans.
export async function GET() {
  if (IS_DEV_MODE) {
    return NextResponse.json({ monitors: [], mode: "dev" });
  }
  const supabase = getServerSupabase();
  const {
    data: { user }
  } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Sign in required" }, { status: 401 });

  const tier = await resolveUserTier(user.id);
  if (tier !== "continuous") {
    return NextResponse.json({ error: "Continuous Protection required" }, { status: 402 });
  }

  const { data, error } = await supabase
    .from("monitors")
    .select("id, target_url, enabled, interval_hours, last_run_at, next_run_at")
    .order("created_at", { ascending: false });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ monitors: data ?? [] });
}

export async function POST(req: NextRequest) {
  let userId: string;
  if (IS_DEV_MODE) {
    return NextResponse.json({
      status: "ok",
      mode: "dev",
      message: "Monitors require production Supabase + Continuous tier"
    });
  }
  const supabase = getServerSupabase();
  const {
    data: { user }
  } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Sign in required" }, { status: 401 });
  userId = user.id;

  const tier = await resolveUserTier(userId);
  if (tier !== "continuous") {
    return NextResponse.json(
      { error: "Continuous Protection required", hint: "Upgrade to schedule re-scans." },
      { status: 402 }
    );
  }

  let body: { url?: string; intervalHours?: number };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  if (!body.url) return NextResponse.json({ error: "Missing url" }, { status: 400 });

  let target: URL;
  try {
    target = normalizeTarget(body.url);
  } catch (e) {
    return NextResponse.json({ error: (e as BlockedTargetError).message }, { status: 400 });
  }

  const interval = Math.min(168, Math.max(1, Number(body.intervalHours) || 24));
  const svc = getServiceSupabase();
  const { data, error } = await svc
    .from("monitors")
    .upsert(
      {
        user_id: userId,
        target_url: target.toString(),
        enabled: true,
        interval_hours: interval,
        next_run_at: new Date().toISOString()
      },
      { onConflict: "user_id,target_url" }
    )
    .select("id, target_url, interval_hours, next_run_at")
    .single();

  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ status: "ok", monitor: data });
}
