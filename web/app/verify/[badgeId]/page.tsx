import type { Metadata } from "next";
import Link from "next/link";
import { getServiceSupabase } from "@/lib/supabase/server";
import { VerifyBadgeCard } from "@/components/VerifyBadgeCard";

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
    <div className="page-pad" style={{ maxWidth: 720, margin: "0 auto" }}>
      <Link href="/" className="back-link">
        ← Back to scanner
      </Link>
      <h1 className="verify-page-title">Scan verification</h1>
      {!summary && (
        <p className="notice">
          No verified scan found for this badge.{" "}
          <Link href="/verify/demo" style={{ color: "inherit", textDecoration: "underline" }}>
            View the demo badge
          </Link>
          .
        </p>
      )}
      {summary && (
        <VerifyBadgeCard
          domain={summary.domain}
          scannedAt={summary.date}
          status={summary.clean ? "passed" : "attention"}
          criticalCount={summary.criticals}
          badgeId={params.badgeId}
        />
      )}
    </div>
  );
}
