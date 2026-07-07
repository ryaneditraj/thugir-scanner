import { NextResponse } from "next/server";
import { IS_DEV_MODE } from "@/lib/devmode";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function configured(name: string): boolean {
  const v = (process.env[name] || "").trim();
  if (!v) return false;
  // Treat demo placeholders as not production-ready.
  if (/demo|placeholder|your_/i.test(v)) return false;
  return true;
}

/** Lightweight operator health check — no secrets. */
export async function GET() {
  const supabaseConfigured =
    configured("NEXT_PUBLIC_SUPABASE_URL") && configured("NEXT_PUBLIC_SUPABASE_ANON_KEY");
  const serviceRole = configured("SUPABASE_SERVICE_ROLE_KEY");
  const razorpay =
    configured("RAZORPAY_KEY_ID") &&
    configured("RAZORPAY_KEY_SECRET") &&
    configured("NEXT_PUBLIC_RAZORPAY_KEY_ID");
  const razorpayWebhook = configured("RAZORPAY_WEBHOOK_SECRET");

  let supabaseReachable: boolean | null = null;
  if (supabaseConfigured && serviceRole && !IS_DEV_MODE) {
    try {
      const { getServiceSupabase } = await import("@/lib/supabase/server");
      const svc = getServiceSupabase();
      const { error } = await svc.from("profiles").select("id", { count: "exact", head: true });
      supabaseReachable = !error;
    } catch {
      supabaseReachable = false;
    }
  }

  const checks = {
    ok: true,
    mode: IS_DEV_MODE ? "dev" : "prod",
    supabase: supabaseConfigured,
    supabaseReachable,
    serviceRole,
    razorpay,
    razorpayWebhook,
    worker: configured("WORKER_URL"),
    openrouter: configured("OPENROUTER_API_KEY"),
    upstash:
      configured("UPSTASH_REDIS_REST_URL") && configured("UPSTASH_REDIS_REST_TOKEN"),
    billingReady: razorpay && razorpayWebhook,
    notes: IS_DEV_MODE
      ? "DEV_MODE: auth/billing backends bypassed for local UI + scan engine testing"
      : undefined,
  };
  return NextResponse.json(checks);
}
