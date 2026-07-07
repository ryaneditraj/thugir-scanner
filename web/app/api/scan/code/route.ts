import { NextRequest, NextResponse } from "next/server";
import { runRepoScan, RepoError } from "@/lib/codescan";
import { getServerSupabase } from "@/lib/supabase/server";
import { resolveUserTier } from "@/lib/entitlements";
import { IS_DEV_MODE, DEV_USER } from "@/lib/devmode";
import { loadSettings } from "@/lib/settings/store";

export const runtime = "nodejs";
export const maxDuration = 120;

// POST /api/scan/code  { repo }
// Scans a public GitHub repository's source for code-level vulnerabilities (secrets, injection
// sinks, disabled TLS, unsafe deserialization, XSS). Available to deep/continuous tiers (and any
// tier in DEV_MODE / under an admin preview tier).
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

  const tier = await resolveUserTier(userId);
  if (!IS_DEV_MODE && tier === "free")
    return NextResponse.json({ error: "needs_deep", hint: "Code scanning requires a Deep or Continuous plan." }, { status: 402 });

  const settings = await loadSettings();
  if (settings.general.maintenanceMode)
    return NextResponse.json({ error: "Scanning is temporarily unavailable." }, { status: 503 });

  let body: { repo?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  if (!body.repo) return NextResponse.json({ error: "Missing repository URL" }, { status: 400 });

  try {
    const result = await runRepoScan(body.repo);
    return NextResponse.json(result);
  } catch (e) {
    if (e instanceof RepoError) return NextResponse.json({ error: e.message }, { status: 400 });
    return NextResponse.json({ error: "Code scan failed" }, { status: 500 });
  }
}
