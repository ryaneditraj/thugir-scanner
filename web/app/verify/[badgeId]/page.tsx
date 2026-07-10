import type { Metadata } from "next";
import { getServiceSupabase } from "@/lib/supabase/server";

export const metadata: Metadata = {
  title: "Scan verification",
  description: "Public verification of a Thugir security scan."
};

// Public trust-badge verification page. Shows only a pass/attention summary for a scan -
// never the findings themselves (those stay private to the owner).
export default async function VerifyPage({ params }: { params: { badgeId: string } }) {
  let summary: { domain: string; date: string; clean: boolean; criticals: number } | null = null;
  try {
    const svc = getServiceSupabase();
    const { data: scan } = await svc
      .from("scans")
      .select("id, target_url, finished_at, status, tier")
      .eq("id", params.badgeId)
      .eq("status", "done")
      .maybeSingle();
    if (scan) {
      const { count } = await svc
        .from("findings")
        .select("id", { count: "exact", head: true })
        .eq("scan_id", scan.id)
        .eq("severity", "critical")
        .eq("status", "open");
      const criticals = count ?? 0;
      summary = {
        domain: new URL(scan.target_url).hostname,
        date: scan.finished_at ?? "",
        clean: criticals === 0,
        criticals
      };
    }
  } catch {
    summary = null;
  }

  return (
    <article className="page-pad">
      <h1 style={{ fontFamily: "var(--display)" }}>Scan verification</h1>
      {!summary && <p className="notice">No verified scan found for this badge.</p>}
      {summary && (
        <div className="card" style={{ maxWidth: 560 }}>
          <p className="kv">
            <b>{summary.domain}</b> was scanned by Thugir
            {summary.date ? ` on ${new Date(summary.date).toLocaleDateString()}` : ""}.
          </p>
          {summary.clean ? (
            <p style={{ marginTop: 12 }}>
              <span className="tag low">passed</span>{" "}
              <span className="muted">No open critical issues at scan time.</span>
            </p>
          ) : (
            <p style={{ marginTop: 12 }}>
              <span className="tag high">attention</span>{" "}
              <span className="muted">{summary.criticals} open critical issue(s) at scan time.</span>
            </p>
          )}
          <p className="muted" style={{ marginTop: 14 }}>
            Verification reflects the state at scan time only.
          </p>
        </div>
      )}
    </article>
  );
}
