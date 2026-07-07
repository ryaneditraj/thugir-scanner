import { NextRequest, NextResponse } from "next/server";
import { getServerSupabase, getServiceSupabase } from "@/lib/supabase/server";
import { makeToken, rootDomain, verifyOwnership, type VerifyMethod } from "@/lib/ownership";
import { BlockedTargetError } from "@/lib/checks/http";

export const runtime = "nodejs";

// GET /api/ownership/verify?domain=example.com  -> returns the token + instructions
export async function GET(req: NextRequest) {
  const supabase = getServerSupabase();
  const {
    data: { user }
  } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Sign in required" }, { status: 401 });

  const input = req.nextUrl.searchParams.get("domain");
  if (!input) return NextResponse.json({ error: "Missing domain" }, { status: 400 });
  let domain: string;
  try {
    domain = rootDomain(input);
  } catch (e) {
    return NextResponse.json({ error: (e as BlockedTargetError).message }, { status: 400 });
  }
  const token = makeToken(user.id, domain);

  const svc = getServiceSupabase();
  await svc
    .from("domain_verifications")
    .upsert(
      { user_id: user.id, domain, method: "well_known", token, verified: false },
      { onConflict: "user_id,domain" }
    );

  return NextResponse.json({
    domain,
    token,
    methods: {
      well_known: { path: `/.well-known/thugir-verify.txt`, content: token },
      meta_tag: { tag: `<meta name="thugir-site-verification" content="${token}">` },
      dns_txt: { name: domain, type: "TXT", value: `thugir-verify=${token}` }
    }
  });
}

// POST /api/ownership/verify  { domain, method }
export async function POST(req: NextRequest) {
  const supabase = getServerSupabase();
  const {
    data: { user }
  } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Sign in required" }, { status: 401 });

  let body: { domain?: string; method?: VerifyMethod };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  if (!body.domain || !body.method)
    return NextResponse.json({ error: "Missing domain or method" }, { status: 400 });

  let domain: string;
  try {
    domain = rootDomain(body.domain);
  } catch (e) {
    return NextResponse.json({ error: (e as BlockedTargetError).message }, { status: 400 });
  }
  const token = makeToken(user.id, domain);
  const result = await verifyOwnership(domain, token, body.method);

  const svc = getServiceSupabase();
  await svc
    .from("domain_verifications")
    .upsert(
      {
        user_id: user.id,
        domain,
        method: body.method,
        token,
        verified: result.verified,
        verified_at: result.verified ? new Date().toISOString() : null
      },
      { onConflict: "user_id,domain" }
    );

  return NextResponse.json({ domain, verified: result.verified, detail: result.detail });
}
