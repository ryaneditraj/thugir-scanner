import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import FindingCard from "@/components/scan/FindingCard";
import ScanResultsPanel from "@/components/scan/ScanResultsPanel";
import ScanShareBar from "@/components/scan/ScanShareBar";
import type { ScanFinding } from "@/components/scan/types";
import { getServerSupabase } from "@/lib/supabase/server";
import { resolveUserTier } from "@/lib/entitlements";
import { serializeDbFinding, type DbFindingRow } from "@/lib/findings/gate";

export const dynamic = "force-dynamic";

export default async function ScanDetailPage({ params }: { params: { id: string } }) {
  const supabase = getServerSupabase();
  const {
    data: { user }
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const { data: scan } = await supabase
    .from("scans")
    .select("id, target_url, tier, status, detected_platform, created_at, finished_at, error")
    .eq("id", params.id)
    .maybeSingle();
  if (!scan) notFound();

  const tier = await resolveUserTier(user.id);
  const { data: rows } = await supabase
    .from("findings")
    .select(
      "id, scan_id, category, title, severity, tier_required, impact_oneline, evidence_json, remediation_json, fix_prompt, confidence, status"
    )
    .eq("scan_id", scan.id);

  const findings: ScanFinding[] = (rows ?? []).map((r) => {
    const s = serializeDbFinding(r as DbFindingRow, tier);
    return {
      id: s.id,
      category: s.category,
      title: s.title,
      severity: s.severity,
      tierRequired: s.tierRequired,
      impactOneline: s.impactOneline,
      maxDamageOneline: "maxDamageOneline" in s ? s.maxDamageOneline : undefined,
      unlocked: s.unlocked,
      evidence: "evidence" in s && s.evidence ? s.evidence : undefined,
      remediation: "remediation" in s && s.remediation ? s.remediation : undefined,
      fixPrompt: "fixPrompt" in s && s.fixPrompt ? s.fixPrompt : undefined,
      status: s.status
    };
  });

  const visible = findings.filter((f) => f.unlocked !== false);
  const locked = findings.filter((f) => f.unlocked === false);
  const critCount = visible.filter((f) => f.severity === "critical").length;

  return (
    <article className="scan-report-page">
      <Link href="/dashboard" className="back-link">
        ← Back to dashboard
      </Link>

      <header className="scan-report-header">
        <div>
          <p className="dash-eyebrow">Scan report</p>
          <h1>{scan.target_url}</h1>
        </div>
        <div className="scan-report-badges">
          <span className={`dash-plan-badge tier-${scan.tier}`}>{scan.tier}</span>
          <span className={`status-pill status-${scan.status}`}>{scan.status}</span>
        </div>
      </header>

      <div className="scan-report-meta">
        <span>
          Scanned <b>{new Date(scan.finished_at ?? scan.created_at).toLocaleString()}</b>
        </span>
        {scan.detected_platform && (
          <span>
            Stack:{" "}
            <Link href={`/platforms/${scan.detected_platform}`}>
              <b>{scan.detected_platform}</b>
            </Link>
          </span>
        )}
        {critCount > 0 && (
          <span>
            <b>{critCount}</b> critical open
          </span>
        )}
      </div>

      {scan.error && (
        <p className="notice" style={{ marginBottom: 16 }}>
          Scan ended with error: {scan.error}
        </p>
      )}

      <ScanShareBar scanId={scan.id} target={scan.target_url} />

      <ScanResultsPanel
        scanId={scan.id}
        target={scan.target_url}
        tierLabel={scan.tier}
        detectedPlatform={scan.detected_platform}
        findings={visible}
        showShare={false}
        hideHeader
      />

      {locked.length > 0 && (
        <section className="scan-locked-section" style={{ marginTop: 28 }}>
          <h2 className="scan-section-title">Locked findings</h2>
          <p className="result-head">Upgrade to unlock evidence and fix prompts</p>
          {locked.map((f) => (
            <FindingCard key={f.id ?? f.title} finding={f} locked />
          ))}
        </section>
      )}
    </article>
  );
}
