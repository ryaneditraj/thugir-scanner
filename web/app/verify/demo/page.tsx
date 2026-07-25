import type { Metadata } from "next";
import Link from "next/link";
import { VerifyBadgeCard } from "@/components/VerifyBadgeCard";

export const metadata: Metadata = {
  title: "Verified scan badge (demo)",
  description: "Public verification badge for a Thugir security scan — demo badge."
};

// Static demo badge — works without Supabase. Use this on stage when judges need a
// shareable trust seal without understanding pattern internals.
export default function VerifyDemoPage() {
  return (
    <div className="page-pad" style={{ maxWidth: 720, margin: "0 auto" }}>
      <Link href="/" className="back-link">
        ← Back to scanner
      </Link>
      <VerifyBadgeCard
        domain="petstore.swagger.io"
        scannedAt={new Date().toISOString()}
        status="passed"
        criticalCount={0}
        badgeId="demo"
        isDemo
      />
      <p className="muted" style={{ marginTop: 20, textAlign: "center" }}>
        After a real scan, share <code>/verify/&lt;scan-id&gt;</code> — only pass/attention is public.
      </p>
    </div>
  );
}
