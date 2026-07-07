import { NextRequest, NextResponse } from "next/server";
import { getServerSupabase } from "@/lib/supabase/server";
import { getRazorpay, DEEP_SCAN_AMOUNT_INR } from "@/lib/razorpay";
import { IS_DEV_MODE, DEV_USER } from "@/lib/devmode";

export const runtime = "nodejs";

// POST /api/billing/create-order  { kind: "deep_scan_credit" | "continuous_sub" }
// Creates a Razorpay order (or subscription) so the client can open Checkout.
export async function POST(req: NextRequest) {
  let userId: string;
  let email: string | undefined;
  if (IS_DEV_MODE) {
    userId = DEV_USER.id;
    email = DEV_USER.email;
  } else {
    const supabase = getServerSupabase();
    const {
      data: { user }
    } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Sign in required" }, { status: 401 });
    userId = user.id;
    email = user.email;
  }

  let body: { kind?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  const kind = body.kind === "continuous_sub" ? "continuous_sub" : "deep_scan_credit";

  try {
    const rzp = getRazorpay();
    const keyId = process.env.NEXT_PUBLIC_RAZORPAY_KEY_ID || process.env.RAZORPAY_KEY_ID;
    if (!keyId) return NextResponse.json({ error: "Razorpay public key not configured" }, { status: 503 });

    if (kind === "continuous_sub") {
      const planId = process.env.RAZORPAY_CONTINUOUS_PLAN_ID;
      if (!planId) {
        return NextResponse.json(
          { error: "Continuous plan is not configured (RAZORPAY_CONTINUOUS_PLAN_ID)" },
          { status: 503 }
        );
      }
      const sub = await rzp.subscriptions.create({
        plan_id: planId,
        total_count: 12,
        notes: { user_id: userId, kind: "continuous_sub", email: email ?? "" }
      });
      return NextResponse.json({
        kind,
        subscriptionId: sub.id,
        keyId,
        prefill: { email }
      });
    }

    const amount = DEEP_SCAN_AMOUNT_INR > 0 ? DEEP_SCAN_AMOUNT_INR : 49900; // paise; default ₹499
    const order = await rzp.orders.create({
      amount,
      currency: "INR",
      notes: { user_id: userId, kind: "deep_scan_credit", email: email ?? "" },
      receipt: `deep_${userId.slice(0, 8)}_${Date.now()}`
    });
    return NextResponse.json({
      kind,
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      keyId,
      prefill: { email }
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Billing unavailable";
    return NextResponse.json({ error: msg }, { status: 503 });
  }
}
