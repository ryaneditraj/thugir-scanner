import { NextRequest, NextResponse } from "next/server";
import { getAdminContext } from "@/lib/auth/admin";
import { testTierAi } from "@/lib/ai/analyze";
import type { AiProvider, TierName } from "@/lib/settings/schema";

export const runtime = "nodejs";

const TIERS: TierName[] = ["free", "deep", "continuous"];
const PROVIDERS: AiProvider[] = ["hackclub", "openrouter", "anthropic", "openai"];

// POST { tier, provider?, model?, baseUrl?, apiKey? }
// Runs a tiny live prompt through the tier's AI config and reports success / precise failure.
// Overrides let the operator test what's typed into the form before saving it.
export async function POST(req: NextRequest) {
  const admin = await getAdminContext();
  if (!admin) return NextResponse.json({ error: "forbidden" }, { status: 403 });

  let body: { tier?: string; provider?: string; model?: string; baseUrl?: string; apiKey?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  if (!body.tier || !TIERS.includes(body.tier as TierName))
    return NextResponse.json({ error: "invalid tier" }, { status: 400 });

  const provider = body.provider && PROVIDERS.includes(body.provider as AiProvider) ? (body.provider as AiProvider) : undefined;

  const result = await testTierAi(body.tier as TierName, {
    provider,
    model: typeof body.model === "string" ? body.model : undefined,
    baseUrl: typeof body.baseUrl === "string" ? body.baseUrl : undefined,
    apiKey: typeof body.apiKey === "string" ? body.apiKey : undefined
  });

  return NextResponse.json(result);
}
