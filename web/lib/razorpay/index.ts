import crypto from "node:crypto";
import Razorpay from "razorpay";

// Razorpay: one-time charge for Deep Scan, subscription for Continuous Protection.
// We eat our own dog food and verify the webhook signature on every event.

export const DEEP_SCAN_AMOUNT_INR = Number(process.env.DEEP_SCAN_AMOUNT_INR ?? "0"); // set per launch
export const CONTINUOUS_PLAN_ID = process.env.RAZORPAY_CONTINUOUS_PLAN_ID ?? "";

let rzp: Razorpay | null = null;
export function getRazorpay(): Razorpay {
  if (rzp) return rzp;
  const key_id = process.env.RAZORPAY_KEY_ID;
  const key_secret = process.env.RAZORPAY_KEY_SECRET;
  if (!key_id || !key_secret) throw new Error("Razorpay keys are not configured");
  rzp = new Razorpay({ key_id, key_secret });
  return rzp;
}

// Verify the X-Razorpay-Signature header against the RAW request body. The raw body MUST be
// used (not a re-serialized JSON object) or the HMAC will not match.
export function verifyWebhookSignature(rawBody: string, signature: string): boolean {
  const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
  if (!secret) throw new Error("RAZORPAY_WEBHOOK_SECRET is not configured");
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
  } catch {
    return false;
  }
}

function _hmacEquals(payload: string, signature: string): boolean {
  const secret = process.env.RAZORPAY_KEY_SECRET;
  if (!secret) throw new Error("RAZORPAY_KEY_SECRET is not configured");
  const expected = crypto.createHmac("sha256", secret).update(payload).digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
  } catch {
    return false;
  }
}

// One-time order checkout success signature: HMAC(order_id | payment_id).
export function verifyPaymentSignature(orderId: string, paymentId: string, signature: string): boolean {
  return _hmacEquals(`${orderId}|${paymentId}`, signature);
}

// Subscription checkout success signature. IMPORTANT: Razorpay signs
// HMAC(payment_id | subscription_id) for subscriptions — the OPPOSITE field order from orders.
// Getting this backwards makes every Continuous Protection checkout fail verification.
export function verifySubscriptionSignature(
  paymentId: string,
  subscriptionId: string,
  signature: string
): boolean {
  return _hmacEquals(`${paymentId}|${subscriptionId}`, signature);
}
