"use client";

import { createBrowserClient } from "@supabase/ssr";

// Browser client. Uses the anon key only; all privileged access is gated by RLS or
// happens server-side via route handlers.
export function getBrowserSupabase() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  );
}
