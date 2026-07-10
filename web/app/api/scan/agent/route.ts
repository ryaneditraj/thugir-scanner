import { NextRequest, NextResponse } from "next/server";
import { runAgentScan, agentAvailability, mapAgentFindings } from "@/lib/agent";
import { IS_DEV_MODE } from "@/lib/devmode";
import { loadSettings } from "@/lib/settings/store";

export const runtime = "nodejs";
export const maxDuration = 300;

/**
 * POST /api/scan/agent
 * { url, scan_mode?: "quick"|"standard"|"deep", command?: string }
 *
 * Runs the Thugir Agent Engine (Python). Requires Python + LLM API key
 * on the host — not available on serverless Vercel without a worker.
 */
export async function POST(req: NextRequest) {
  const settings = await loadSettings();
  if (settings.general.maintenanceMode) {
    return NextResponse.json({ error: "Scanning is temporarily unavailable." }, { status: 503 });
  }

  const avail = agentAvailability();
  if (!avail.available) {
    return NextResponse.json(
      {
        error: "agent_unavailable",
        reason: avail.reason,
        hint: "Install Python 3.10+, pip install -r services/thugir-agent/requirements.txt, set THUGIR_AGENT_LLM_API_KEY"
      },
      { status: 503 }
    );
  }

  let body: { url?: string; scan_mode?: string; command?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  if (!body.url) return NextResponse.json({ error: "Missing url" }, { status: 400 });

  const scanMode = body.scan_mode === "deep" || body.scan_mode === "standard" ? body.scan_mode : "quick";

  if (!IS_DEV_MODE && process.env.THUGIR_AGENT_SCAN_ENABLED !== "1") {
    return NextResponse.json(
      {
        error: "agent_disabled",
        hint: "Set THUGIR_AGENT_SCAN_ENABLED=1 on a worker with Python, or use power-scan --agent locally"
      },
      { status: 403 }
    );
  }

  const result = runAgentScan({
    url: body.url,
    scan_mode: scanMode,
    command: body.command
  });

  if (!result.ok) {
    return NextResponse.json(
      { error: result.error || "Agent scan failed", detail: result },
      { status: 500 }
    );
  }

  const findings = mapAgentFindings(result.findings || [], body.url);

  return NextResponse.json({
    engine: "thugir-agent",
    target: result.target,
    scan_mode: result.scan_mode,
    exit_code: result.exit_code,
    exit_meaning: result.exit_meaning,
    finding_count: findings.length,
    findings,
    summary: result.summary,
    report_path: result.report_path,
    run_dir: result.run_dir
  });
}

export async function GET() {
  const avail = agentAvailability();
  return NextResponse.json({
    engine: "thugir-agent",
    ...avail
  });
}
