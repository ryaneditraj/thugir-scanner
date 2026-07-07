"use client";

import { getBrowserSupabase } from "@/lib/supabase/client";

export default function SignOutButton() {
  async function signOut() {
    try {
      const supabase = getBrowserSupabase();
      await supabase.auth.signOut();
    } catch {
      /* DEV_MODE or missing Supabase — still leave the portal */
    }
    window.location.assign("/");
  }

  return (
    <button type="button" className="btn-ghost signout-btn" onClick={signOut}>
      Sign out
    </button>
  );
}
