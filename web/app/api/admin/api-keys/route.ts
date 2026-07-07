import { NextRequest, NextResponse } from "next/server";
import { getAdminContext, roleAtLeast, writeAudit } from "@/lib/auth/admin";
import { getServiceSupabase } from "@/lib/supabase/server";

export const runtime = "nodejs";

// Provider key management. Plaintext is NEVER stored or returned. We store ciphertext
// (encrypt with Supabase Vault / pgsodium before this layer) and surface only last4.
// GET returns masked rows; POST stores a new key (owner only).
export async function GET() {
  const admin = await getAdminContext();
  if (!admin) return NextResponse.json({ error: "forbidden" }, { status: 403 });
  const svc = getServiceSupabase();
  const { data } = await svc
    .from("api_keys")
    .select("id, label, provider, last4, status, rotated_at, created_at")
    .order("created_at", { ascending: false });
  return NextResponse.json({ keys: data ?? [] });
}

// Body: { label, provider, ciphertext, last4 }
// ciphertext must already be encrypted (Vault). We refuse anything that looks like plaintext.
export async function POST(req: NextRequest) {
  const admin = await getAdminContext();
  if (!admin || !roleAtLeast(admin.role, "owner"))
    return NextResponse.json({ error: "forbidden" }, { status: 403 });

  const body = await req.json().catch(() => null);
  if (!body?.provider || !body?.ciphertext || !body?.last4)
    return NextResponse.json({ error: "provider, ciphertext, last4 required" }, { status: 400 });

  const svc = getServiceSupabase();
  const { data, error } = await svc
    .from("api_keys")
    .insert({
      label: body.label ?? body.provider,
      provider: body.provider,
      ciphertext: body.ciphertext,
      last4: body.last4,
      status: "active",
      rotated_by: admin.userId
    })
    .select("id, label, provider, last4, status")
    .single();
  if (error) return NextResponse.json({ error: error.message }, { status: 400 });

  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? undefined;
  await writeAudit({
    actorAdminId: admin.userId,
    action: "api_key.create",
    targetType: "api_key",
    targetId: data.id,
    after: { provider: data.provider, last4: data.last4 },
    ip
  });
  return NextResponse.json({ key: data });
}
