import { notFound, redirect } from "next/navigation";
import Link from "next/link";
import { getServerSupabase } from "@/lib/supabase/server";
import { resolveUserTier } from "@/lib/entitlements";
import { serializeDbFinding, type DbFindingRow } from "@/lib/findings/gate";

export const dynamic = "force-dynamic";

function evidenceLines(ev?: Record<string, unknown>): string {
  if (!ev) return "";
  return Object.entries(ev)
    .map(([k, v]) => `${k}: ${v && typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join("\n");
}

export default async function ScanDetailPage({ params }: { params: { id: string } }) {
  const supabase = getServerSupabase();
  const {
    data: { user }
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const { data: scan } = await supabase
    .from("scans")
    .select("id, target_url, tier, status, detected_platform, created_at")
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

  const findings = (rows ?? []).map((r) => serializeDbFinding(r as DbFindingRow, tier));
  const locked = findings.filter((f) => !f.unlocked);
  const visible = findings.filter((f) => f.unlocked);

  return (
    <article>
      <Link href="/dashboard" className="back-link">
        ← Back to dashboard
      </Link>
      <h1 style={{ fontFamily: "var(--display)", marginBottom: 8 }}>Scan report</h1>
      <div className="scan-report-meta">
        <span>
          Target: <b>{scan.target_url}</b>
        </span>
        <span>
          Tier: <b>{scan.tier}</b>
        </span>
        <span>
          Status: <span className={`status-pill status-${scan.status}`}>{scan.status}</span>
        </span>
        {scan.detected_platform && (
          <span>
            Stack: <b>{scan.detected_platform}</b>
          </span>
        )}
      </div>

      <h2 style={{ fontFamily: "var(--display)", fontSize: 22, marginBottom: 14 }}>Findings</h2>
      {visible.length === 0 && <p className="muted">No unlocked findings for your current plan.</p>}
      {visible.map((f) => {
        const unlocked = f as typeof f & {
          maxDamageOneline?: string;
          evidence?: Record<string, unknown>;
          remediation?: { summary: string; steps: string[] };
          fixPrompt?: string;
        };
        return (
        <div className="finding" key={f.id}>
          <h3>
            <span className={`tag ${f.severity}`}>{f.severity}</span>
            <span className="tag verified">verified</span>
            {f.title}
          </h3>
          <p className="impact">{f.impactOneline}</p>
          {unlocked.maxDamageOneline && (
            <div className="max-damage">
              <span className="max-damage-label">Worst case for your company</span>
              <p>{unlocked.maxDamageOneline}</p>
            </div>
          )}
          {(unlocked.evidence || unlocked.remediation || unlocked.fixPrompt) && (
            <details>
              <summary>Evidence &amp; fix</summary>
              <div className="finding-detail">
                {unlocked.evidence && Object.keys(unlocked.evidence).length > 0 && (
                  <div className="fd-block">
                    <div className="fd-label">Evidence</div>
                    <pre className="code">{evidenceLines(unlocked.evidence)}</pre>
                  </div>
                )}
                {unlocked.remediation && (
                  <div className="fd-block">
                    <div className="fd-label">How to fix</div>
                    <p className="fd-text">{unlocked.remediation.summary}</p>
                    {unlocked.remediation.steps?.length > 0 && (
                      <ol className="fd-steps">
                        {unlocked.remediation.steps.map((s: string, i: number) => (
                          <li key={i}>{s}</li>
                        ))}
                      </ol>
                    )}
                  </div>
                )}
                {unlocked.fixPrompt && (
                  <div className="fd-block">
                    <div className="fd-label">Fix prompt</div>
                    <pre className="code">{unlocked.fixPrompt}</pre>
                  </div>
                )}
              </div>
            </details>
          )}
        </div>
        );
      })}

      {locked.length > 0 && (
        <section style={{ marginTop: 28 }}>
          <h2 style={{ fontFamily: "var(--display)", fontSize: 22, marginBottom: 14 }}>Locked findings</h2>
          {locked.map((f) => (
            <div className="finding locked" key={f.id}>
              <h3>
                <span className={`tag ${f.severity}`}>{f.severity}</span>
                {f.title}
              </h3>
              <p className="impact">{f.impactOneline}</p>
              <div className="lock-row">
                <span aria-hidden="true">🔒</span>
                <span>Unlock full evidence + fix with a {f.tierRequired} scan.</span>
              </div>
            </div>
          ))}
        </section>
      )}
    </article>
  );
}
