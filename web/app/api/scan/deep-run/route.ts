import { NextRequest, NextResponse } from "next/server";
import { runDeepScan } from "@/lib/checks/runner";
import { BlockedTargetError } from "@/lib/checks/http";
import { serializeFindings } from "@/lib/findings/gate";
import { getServerSupabase, getServiceSupabase } from "@/lib/supabase/server";
import { resolveUserTier } from "@/lib/entitlements";
import { IS_DEV_MODE, DEV_USER } from "@/lib/devmode";
import { enrichScanResults } from "@/lib/scans/enrich";
import { loadSettings } from "@/lib/settings/store";

export const runtime = "nodejs";
export const maxDuration = 120; // deep scan crawls a few pages + more scripts

// POST /api/scan/deep-run  { url }
// Runs a Deep Scan INLINE (full pattern library + shallow crawl) and returns unlocked findings.
// No verified-domain requirement. Available to deep/continuous tiers (and any tier in DEV_MODE,
// or when an admin sets a preview tier). Heavy active probing remains a worker job in production.
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
    return NextResponse.json({ error: "needs_deep", hint: "A Deep Scan requires a Deep or Continuous plan." }, { status: 402 });

  const settings = await loadSettings();
  if (settings.general.maintenanceMode)
    return NextResponse.json({ error: "Scanning is temporarily unavailable." }, { status: 503 });

  let body: { url?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  if (!body.url) return NextResponse.json({ error: "Missing url" }, { status: 400 });

  let result;
  try {
    result = await runDeepScan(body.url, {
      maxScripts: Math.max(settings.scan.freeMaxScripts, 24),
      extraBlockedDomains: settings.security.extraBlockedDomains
    });
  } catch (e) {
    if (e instanceof BlockedTargetError) return NextResponse.json({ error: e.message }, { status: 400 });
    return NextResponse.json({ error: "Scan failed" }, { status: 500 });
  }

  const origin = (() => {
    try {
      return new URL(result.finalUrl || result.target).origin;
    } catch {
      return result.target;
    }
  })();

  const { findings, ai, stats } = await enrichScanResults({
    findings: result.findings,
    target: result.target,
    detectedPlatform: result.detectedPlatform,
    tier: "deep",
    isDeep: true,
    combined: result.combined,
    origin,
    pagesCrawled: result.pagesCrawled
  });
  result.findings = findings;

  let scanId: string | null = null;
  if (!IS_DEV_MODE) {
    const svc = getServiceSupabase();
    const { data: scan } = await svc
      .from("scans")
      .insert({
        user_id: userId,
        target_url: result.target,
        tier: "deep",
        detected_platform: result.detectedPlatform,
        status: "done",
        verified_domain: false,
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString()
      })
      .select("id")
      .single();
    scanId = scan?.id ?? null;
    if (scan?.id) {
      const rows = result.findings.map((f) => ({
        scan_id: scan.id,
        category: f.category,
        title: f.title,
        severity: f.severity,
        tier_required: f.tierRequired,
        impact_oneline: f.impactOneline,
        evidence_json: { ...f.evidence, maxDamageOneline: f.maxDamageOneline },
        remediation_json: f.remediation ?? null,
        fix_prompt: f.fixPrompt ?? null,
        confidence: f.confidence
      }));
      if (rows.length) await svc.from("findings").insert(rows);
    }
  }

  return NextResponse.json({
    scanId,
    target: result.target,
    detectedPlatform: result.detectedPlatform,
    pagesCrawled: result.pagesCrawled,
    ai: ai
      ? {
          summary: ai.summary,
          maxCompanyDamage: ai.maxCompanyDamage,
          attackChain: ai.attackChain,
          riskLevel: ai.riskLevel,
          model: ai.model
        }
      : null,
    meta: {
      totalFindings: stats.totalFindings,
      aiFindingsAdded: stats.aiFindingsAdded,
      probesRun: result.probesRun,
      pagesCrawled: result.pagesCrawled.length
    },
    findings: serializeFindings(result.findings, "deep")
  });
}
