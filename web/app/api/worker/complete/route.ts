import { NextRequest, NextResponse } from "next/server";
import { getServiceSupabase } from "@/lib/supabase/server";
import { computeScanDelta, formatDeltaText, type FindingRow } from "@/lib/monitors/delta";
import { sendEmail } from "@/lib/email/send";

export const runtime = "nodejs";

type CompleteBody = {
  scanId?: string;
  monitorId?: string;
  previousScanId?: string;
  secret?: string;
};

async function loadFindings(scanId: string): Promise<FindingRow[]> {
  const svc = getServiceSupabase();
  const { data } = await svc
    .from("findings")
    .select("category, title, severity, impact_oneline")
    .eq("scan_id", scanId);
  return (data ?? []) as FindingRow[];
}

// POST /api/worker/complete — worker callback after a monitor-linked scan finishes.
export async function POST(req: NextRequest) {
  const expected = process.env.WORKER_CALLBACK_SECRET;
  let body: CompleteBody;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const headerSecret = req.headers.get("x-worker-secret");
  const secret = headerSecret ?? body.secret;
  if (!expected || secret !== expected) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { scanId, monitorId, previousScanId } = body;
  if (!scanId) return NextResponse.json({ error: "Missing scanId" }, { status: 400 });

  const svc = getServiceSupabase();
  const { data: scan } = await svc
    .from("scans")
    .select("id, user_id, target_url, status, monitor_id")
    .eq("id", scanId)
    .maybeSingle();

  if (!scan) return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  if (scan.status !== "done") {
    return NextResponse.json({ status: "ignored", reason: "scan not done" });
  }

  const effectiveMonitorId = monitorId ?? scan.monitor_id;
  if (!effectiveMonitorId) {
    return NextResponse.json({ status: "ok", emailed: false, reason: "not a monitor scan" });
  }

  const current = await loadFindings(scanId);
  const prevId = previousScanId ?? null;
  const previous = prevId ? await loadFindings(prevId) : [];
  const delta = computeScanDelta(previous, current);

  const site = process.env.NEXT_PUBLIC_SITE_URL ?? "https://thugirlabs.com";
  const scanUrl = `${site.replace(/\/$/, "")}/scans/${scanId}`;
  const { subject, text, html } = formatDeltaText(scan.target_url, delta, scanUrl);

  const { data: profile } = await svc
    .from("profiles")
    .select("email")
    .eq("id", scan.user_id)
    .maybeSingle();

  let emailed = false;
  if (profile?.email) {
    emailed = await sendEmail({ to: profile.email, subject, text, html });
  }

  await svc
    .from("monitors")
    .update({ delta_notified_at: new Date().toISOString() })
    .eq("id", effectiveMonitorId);

  return NextResponse.json({
    status: "ok",
    emailed,
    delta: {
      new: delta.newFindings.length,
      resolved: delta.resolvedFindings.length,
      unchanged: delta.unchangedCount
    }
  });
}
