import { notFound, redirect } from "next/navigation";
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

  // RLS ensures the user can only read their own scan.
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
      <h1 style={{ fontFamily: "var(--display)" }}>Scan report</h1>
      <p className="kv">
        <b>{scan.target_url}</b> - {scan.tier} scan - {scan.status}
        {scan.detected_platform ? ` - ${scan.detected_platform}` : ""}
      </p>

      <h2 style={{ fontFamily: "var(--display)" }}>Findings</h2>
      {visible.length === 0 && <p className="muted">No unlocked findings.</p>}
      {visible.map((f: any) => (
        <div className="finding" key={f.id}>
          <h3>
            <span className={`badge ${f.severity}`}>{f.severity}</span>
            {f.title}
          </h3>
          <p className="impact">{f.impactOneline}</p>
          {f.maxDamageOneline && (
            <div className="max-damage">
              <span className="max-damage-label">Worst case for your company</span>
              <p>{f.maxDamageOneline}</p>
            </div>
          )}
          {f.remediation && (
            <details>
              <summary>How to fix</summary>
              <p className="kv">{f.remediation.summary}</p>
              <ol>{f.remediation.steps?.map((s: string, i: number) => <li key={i} className="kv">{s}</li>)}</ol>
              {f.fixPrompt && <pre className="code">{f.fixPrompt}</pre>}
            </details>
          )}
        </div>
      ))}

      {locked.length > 0 && (
        <>
          <h2 style={{ fontFamily: "var(--display)", marginTop: 24 }}>Locked findings</h2>
          {locked.map((f: any) => (
            <div className="finding locked" key={f.id}>
              <h3>
                <span className={`badge ${f.severity}`}>{f.severity}</span>
                {f.title}
              </h3>
              <p className="impact">{f.impactOneline}</p>
              <div className="lock-row">
                <span className="lockicon">[locked]</span>
                <span>Unlock full evidence + fix with a {f.tierRequired} scan.</span>
              </div>
            </div>
          ))}
        </>
      )}
    </article>
  );
}
