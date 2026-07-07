import { NextRequest, NextResponse } from "next/server";
import { getServerSupabase, getServiceSupabase } from "@/lib/supabase/server";
import { consumeDeepCredit, resolveUserTier } from "@/lib/entitlements";
import { createAndEnqueueDeepScan } from "@/lib/scans/enqueue";
import { normalizeTarget, BlockedTargetError } from "@/lib/checks/http";
import { IS_DEV_MODE, DEV_USER } from "@/lib/devmode";

export const runtime = "nodejs";

// POST /api/scan/deep  { url }
// Deep Scan is NOT executed here. We verify entitlement + domain ownership, create a queued
// scan row, and hand off to the Python worker via QStash. Vercel never runs the heavy scan.
export async function POST(req: NextRequest) {
  let user: { id: string };
  if (IS_DEV_MODE) {
    user = DEV_USER;
  } else {
    const supabase = getServerSupabase();
    const {
      data: { user: authed }
    } = await supabase.auth.getUser();
    if (!authed) return NextResponse.json({ error: "Sign in required" }, { status: 401 });
    user = authed;
  }

  let body: { url?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  if (!body.url) return NextResponse.json({ error: "Missing url" }, { status: 400 });

  let target;
  try {
    target = normalizeTarget(body.url);
  } catch (e) {
    return NextResponse.json({ error: (e as BlockedTargetError).message }, { status: 400 });
  }
  const domain = target.hostname.toLowerCase();

  const svc = getServiceSupabase();

  // Domain verification is NOT required to start a deep scan. We record whether the domain happens
  // to be verified (it unlocks heavier active probing in the worker), but never block on it.
  const { data: verification } = await svc
    .from("domain_verifications")
    .select("verified")
    .eq("user_id", user.id)
    .eq("domain", domain)
    .eq("verified", true)
    .maybeSingle();
  const isVerified = Boolean(verification);

  // Entitlement gate: continuous subscribers scan freely; deep tier consumes one credit.
  const tier = await resolveUserTier(user.id);
  if (tier === "free") {
    return NextResponse.json(
      { error: "no_deep_credit", hint: "Upgrade to Deep Scan or Continuous Protection." },
      { status: 402 }
    );
  }
  if (tier === "deep") {
    const consumed = await consumeDeepCredit(user.id);
    if (!consumed) {
      return NextResponse.json(
        { error: "no_deep_credit", hint: "No Deep Scan credits left. Purchase another or upgrade." },
        { status: 402 }
      );
    }
  }

  try {
    const { scanId } = await createAndEnqueueDeepScan({
      userId: user.id,
      targetUrl: target.toString(),
      verifiedDomain: isVerified
    });
    return NextResponse.json({ scanId, status: "queued" });
  } catch (e) {
    return NextResponse.json({ error: "Could not enqueue scan" }, { status: 502 });
  }
}
