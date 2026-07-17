"use client";

import { useState, useMemo } from "react";
import { useSearchParams } from "next/navigation";
import { getBrowserSupabase } from "@/lib/supabase/client";

export default function LoginForm() {
  const searchParams = useSearchParams();
  const nextPath = searchParams.get("next") || "/dashboard";
  const redirectTo = useMemo(() => {
    const origin =
      typeof window !== "undefined"
        ? window.location.origin
        : process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000";
    const path = nextPath.startsWith("/") ? nextPath : "/dashboard";
    return `${origin}${path}`;
  }, [nextPath]);

  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function sendLink(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const supabase = getBrowserSupabase();
      const { error: authError } = await supabase.auth.signInWithOtp({
        email,
        options: { emailRedirectTo: redirectTo }
      });
      if (authError) setError(authError.message);
      else setSent(true);
    } catch {
      setError("Could not reach auth service. Check Supabase configuration.");
    } finally {
      setBusy(false);
    }
  }

  async function google() {
    setError(null);
    try {
      const supabase = getBrowserSupabase();
      const { error: authError } = await supabase.auth.signInWithOAuth({
        provider: "google",
        options: { redirectTo }
      });
      if (authError) setError(authError.message);
    } catch {
      setError("Could not start Google sign-in. Check Supabase configuration.");
    }
  }

  return (
    <article className="login-card">
      <span className="login-eyebrow">Thugir Scanner</span>
      <h1>Sign in</h1>
      <p className="login-sub">Access your scans, Deep Scan credits, and Continuous Protection.</p>
      {sent ? (
        <p className="notice ok">Check your email for a magic link — it opens your account dashboard.</p>
      ) : (
        <>
          <form onSubmit={sendLink}>
            <label className="fld">
              <span>Email</span>
              <input
                type="email"
                required
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
              />
            </label>
            <button className="btn btn-primary" type="submit" disabled={busy}>
              {busy ? "Sending…" : "Email me a magic link"}
            </button>
          </form>
          <div style={{ marginTop: 14, display: "grid", gap: 10 }}>
            <span className="muted" style={{ textAlign: "center", fontSize: 12 }}>
              or
            </span>
            <button className="btn secondary" type="button" onClick={google} disabled={busy}>
              Continue with Google
            </button>
          </div>
        </>
      )}
      {error && <p className="notice" style={{ marginTop: 12 }}>{error}</p>}
      <p className="login-fine">Authorized testing only · scans are logged to your account</p>
    </article>
  );
}
