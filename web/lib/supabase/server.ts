import { cookies } from "next/headers";
import { createServerClient, type CookieOptions } from "@supabase/ssr";
import { createClient } from "@supabase/supabase-js";

function requirePublicSupabaseEnv() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !anon) {
    throw new Error("NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY are required");
  }
  return { url, anon };
}

// Auth-aware client for Server Components / route handlers (respects the user's session + RLS).
export function getServerSupabase() {
  const { url, anon } = requirePublicSupabaseEnv();
  const cookieStore = cookies();
  return createServerClient(url, anon, {
    cookies: {
      get: (name: string) => cookieStore.get(name)?.value,
      set: (name: string, value: string, options: CookieOptions) => {
        try {
          cookieStore.set({ name, value, ...options });
        } catch {
          /* called from a Server Component render - safe to ignore */
        }
      },
      remove: (name: string, options: CookieOptions) => {
        try {
          cookieStore.set({ name, value: "", ...options });
        } catch {
          /* ignore */
        }
      }
    }
  });
}

// Service-role client. SERVER ONLY. Bypasses RLS - use for trusted writes (entitlements,
// scan inserts, audit log). Never import this into a client component.
export function getServiceSupabase() {
  const { url } = requirePublicSupabaseEnv();
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!serviceKey) throw new Error("SUPABASE_SERVICE_ROLE_KEY is not configured");
  return createClient(url, serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false }
  });
}
