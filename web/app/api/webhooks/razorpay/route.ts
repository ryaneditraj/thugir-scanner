import { NextRequest, NextResponse } from "next/server";
import { verifyWebhookSignature, getRazorpay } from "@/lib/razorpay";
import { getServiceSupabase } from "@/lib/supabase/server";

export const runtime = "nodejs";

// Razorpay webhook. We verify the signature against the RAW body before trusting anything,
// then grant entitlements. This is the same class of check we sell, so it must be airtight.
export async function POST(req: NextRequest) {
  const signature = req.headers.get("x-razorpay-signature");
  if (!signature) return NextResponse.json({ error: "missing signature" }, { status: 400 });

  const rawBody = await req.text(); // RAW body required for HMAC
  if (!verifyWebhookSignature(rawBody, signature)) {
    return NextResponse.json({ error: "invalid signature" }, { status: 401 });
  }

  let event: any;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return NextResponse.json({ error: "invalid json" }, { status: 400 });
  }

  const svc = getServiceSupabase();
  const type: string = event?.event ?? "";

  // Idempotency key: payment id / subscription charge id / event id.
  const eventId: string | undefined =
    event?.payload?.payment?.entity?.id ||
    event?.payload?.subscription?.entity?.id ||
    event?.id;

  async function grantOnce(userId: string, kind: "deep_scan_credit" | "continuous_sub", ref: string | undefined) {
    if (ref) {
      const { data: existing } = await svc
        .from("entitlements")
        .select("id")
        .eq("razorpay_ref", ref)
        .maybeSingle();
      if (existing?.id) return;
    }
    await svc.from("entitlements").insert({
      user_id: userId,
      kind,
      status: "active",
      razorpay_ref: ref ?? null,
      expires_at:
        kind === "continuous_sub"
          ? new Date(Date.now() + 31 * 24 * 3600 * 1000).toISOString()
          : null
    });
  }

  try {
    if (type === "payment.captured" || type === "order.paid") {
      let notes: Record<string, string> =
        event?.payload?.order?.entity?.notes || event?.payload?.payment?.entity?.notes || {};
      // Order notes are NOT copied onto the payment entity, so payment.captured can arrive with
      // empty notes. Fall back to fetching the order to recover user_id/kind.
      if (!notes.user_id) {
        const orderId = event?.payload?.payment?.entity?.order_id;
        if (orderId) {
          try {
            const order = await getRazorpay().orders.fetch(orderId);
            notes = (order?.notes as Record<string, string>) || notes;
          } catch {
            /* order fetch failed — leave notes as-is; verify path is the backup grant */
          }
        }
      }
      const userId = notes.user_id;
      const kind = notes.kind === "continuous_sub" ? "continuous_sub" : "deep_scan_credit";
      if (userId) await grantOnce(userId, kind, eventId);
    } else if (type === "subscription.charged") {
      const notes = event?.payload?.subscription?.entity?.notes || {};
      const userId = notes.user_id;
      if (userId) await grantOnce(userId, "continuous_sub", eventId);
    } else if (type === "subscription.cancelled") {
      const notes = event?.payload?.subscription?.entity?.notes || {};
      const userId = notes.user_id;
      if (userId) {
        await svc
          .from("entitlements")
          .update({ status: "cancelled" })
          .eq("user_id", userId)
          .eq("kind", "continuous_sub")
          .eq("status", "active");
      }
    }
  } catch (e) {
    // Return 500 so Razorpay retries; never throw the raw error to the caller.
    return NextResponse.json({ error: "processing failed" }, { status: 500 });
  }

  return NextResponse.json({ received: true });
}
