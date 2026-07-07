import { NextRequest, NextResponse } from "next/server";
import { runFreeScan, runDeepScan } from "@/lib/checks/runner";
import { BlockedTargetError } from "@/lib/checks/http";
import { serializeFindings } from "@/lib/findings/gate";
import { getServerSupabase, getServiceSupabase } from "@/lib/supabase/server";
import { checkFreeScanLimit } from "@/lib/ratelimit";
import { resolveUserTier } from "@/lib/entitlements";
import { IS_DEV_MODE, DEV_USER } from "@/lib/devmode";
import { enrichScanResults } from "@/lib/scans/enrich";
import { loadSettings } from "@/lib/settings/store";

export const runtime = "nodejs";
export const maxDuration = 120;

// POST /api/scan/free  { url, attest: true }
// Free Starter Scan: runs fully inside this Vercel function. Requires an account, a
// click-through ownership attestation, and passes the abuse rate limit.
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

  // Platform settings drive availability, attestation requirement, scan limits, and AI config.
  const settings = await loadSettings();
  if (settings.general.maintenanceMode || !settings.scan.freeScanEnabled) {
    return NextResponse.json(
      { error: "The free scan is temporarily unavailable. Please check back soon." },
      { status: 503 }
    );
  }

  let body: { url?: string; attest?: boolean };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  if (!body.url) return NextResponse.json({ error: "Missing url" }, { status: 400 });
  if (settings.scan.requireAttestation && !body.attest)
    return NextResponse.json(
      { error: "You must confirm you own or are authorized to scan this URL." },
      { status: 400 }
    );

  const ip =
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-real-ip") ||
    "unknown";
  const limit = await checkFreeScanLimit(userId, ip);
  if (!limit.ok) {
    return NextResponse.json(
      { error: "Rate limit reached. Try again later.", reset: limit.reset },
      { status: 429 }
    );
  }

  // Request log: every free scan is attributable to an account + IP (abuse trail).
  console.info(
    `[scan:free] ${new Date().toISOString()} user=${userId} ip=${ip} target=${(body.url || "").slice(0, 200)}`
  );

  // Entitled users (deep/continuous — including admins using the tier-preview switch) get a full,
  // UNBLURRED scan straight from the homepage: we run the deep engine and never gate the results.
  const userTier = await resolveUserTier(userId);
  const isDeep = userTier !== "free";

  let result: {
    target: string;
    finalUrl: string;
    detectedPlatform: string | null;
    findings: Awaited<ReturnType<typeof runFreeScan>>["findings"];
    lockedTeasers?: Awaited<ReturnType<typeof runFreeScan>>["lockedTeasers"];
    combined?: string;
    pagesCrawled?: string[];
    probesRun?: number;
  };
  try {
    if (isDeep) {
      const deep = await runDeepScan(body.url, {
        maxScripts: Math.max(settings.scan.freeMaxScripts, 24),
        extraBlockedDomains: settings.security.extraBlockedDomains
      });
      result = { ...deep };
    } else {
      result = await runFreeScan(body.url, {
        maxScripts: settings.scan.freeMaxScripts,
        extraBlockedDomains: settings.security.extraBlockedDomains
      });
    }
  } catch (e) {
    if (e instanceof BlockedTargetError)
      return NextResponse.json({ error: e.message }, { status: 400 });
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
    tier: isDeep ? "deep" : "free",
    isDeep,
    combined: result.combined,
    origin,
    pagesCrawled: result.pagesCrawled
  });
  result.findings = findings;

  // Persist the scan + findings (service role; RLS still protects reads by owner).
  // Skipped entirely in DEV_MODE so the scan engine can be tested without Supabase.
  let scanId: string | null = null;
  if (!IS_DEV_MODE) {
    const svc = getServiceSupabase();
    const { data: scan } = await svc
      .from("scans")
      .insert({
        user_id: userId,
        target_url: result.target,
        tier: isDeep ? "deep" : "free",
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

  // Deep/continuous users: everything is unlocked, no paywall. Free users see free findings fully,
  // plus an HONEST count of the additional CHECKS a Deep Scan runs (never fabricated findings),
  // which the client renders as a blurred, locked paywall preview.
  const lockedTeasers = result.lockedTeasers ?? [];
  const lockedCategories = Array.from(new Set(lockedTeasers.map((t) => t.category)));
  return NextResponse.json({
    scanId,
    tier: isDeep ? "deep" : "free",
    target: result.target,
    detectedPlatform: result.detectedPlatform,
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
      probesRun: "probesRun" in result ? (result as { probesRun?: number }).probesRun : undefined
    },
    findings: serializeFindings(result.findings, userTier),
    locked: isDeep ? null : { checkCount: lockedTeasers.length, categories: lockedCategories },
    upgrade: isDeep ? null : { tier: "deep", reason: "Unlock full evidence, fixes, and deeper structural checks." }
  });
}
