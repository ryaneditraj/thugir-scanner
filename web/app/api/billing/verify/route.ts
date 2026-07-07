import { NextRequest, NextResponse } from "next/server";
import { getServerSupabase, getServiceSupabase } from "@/lib/supabase/server";
import { verifyPaymentSignature, verifySubscriptionSignature } from "@/lib/razorpay";
import { IS_DEV_MODE, DEV_USER } from "@/lib/devmode";

export const runtime = "nodejs";

// POST /api/billing/verify
// Client-side checkout success fallback — grants entitlement after signature check.
// Webhook remains the primary grant path; this is for fast UX when webhooks lag.
export async function POST(req: NextRequest) {
  let userId: string;
  if (IS_DEV_MODE) {
    userId = DEV_USER.id;
  } else {
    const supabase = getServerSupabase();
    const {
      data: { user }
    } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "Sign in required" }, { status: 401 });
    userId = user.id;
  }

  let body: {
    orderId?: string;
    subscriptionId?: string;
    paymentId?: string;
    signature?: string;
    kind?: string;
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const kind = body.kind === "continuous_sub" ? "continuous_sub" : "deep_scan_credit";
  const { orderId, subscriptionId, paymentId, signature } = body;

  if (!paymentId || !signature) {
    return NextResponse.json({ error: "Missing payment fields" }, { status: 400 });
  }

  // Subscriptions sign HMAC(payment_id|subscription_id); orders sign HMAC(order_id|payment_id).
  let valid = false;
  if (kind === "continuous_sub") {
    if (!subscriptionId) {
      return NextResponse.json({ error: "Missing subscription id" }, { status: 400 });
    }
    valid = verifySubscriptionSignature(paymentId, subscriptionId, signature);
  } else {
    if (!orderId) {
      return NextResponse.json({ error: "Missing order id" }, { status: 400 });
    }
    valid = verifyPaymentSignature(orderId, paymentId, signature);
  }
  if (!valid) {
    return NextResponse.json({ error: "Invalid payment signature" }, { status: 401 });
  }

  const svc = getServiceSupabase();

  // Idempotent: skip if this payment already granted an entitlement.
  const { data: existing } = await svc
    .from("entitlements")
    .select("id")
    .eq("razorpay_ref", paymentId)
    .maybeSingle();
  if (existing?.id) return NextResponse.json({ status: "ok", alreadyGranted: true });

  const { error } = await svc.from("entitlements").insert({
    user_id: userId,
    kind,
    status: "active",
    razorpay_ref: paymentId,
    expires_at:
      kind === "continuous_sub"
        ? new Date(Date.now() + 31 * 24 * 3600 * 1000).toISOString()
        : null
  });
  if (error) return NextResponse.json({ error: "Could not grant entitlement" }, { status: 500 });

  return NextResponse.json({ status: "ok", kind });
}
