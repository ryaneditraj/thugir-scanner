import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Sample Deep Scan report",
  description: "An example of what a Thugir Deep Scan report looks like.",
  alternates: { canonical: "/report/sample" }
};

export default function SampleReportPage() {
  return (
    <article>
      <h1 style={{ fontFamily: "var(--display)" }}>Sample Deep Scan report</h1>
      <p className="lead muted">
        This is a redacted example of a Deep Scan report for a fictional Lovable + Supabase app.
      </p>

      <div className="card" style={{ marginTop: 16 }}>
        <p className="kv">
          Target <b>https://demo-app.example</b> - built with <b>Lovable</b> - 4 issues, 1 critical
        </p>
      </div>

      <div className="finding">
        <h3>
          <span className="badge critical">critical</span>Supabase table `profiles` readable without auth
        </h3>
        <p className="impact">Anyone can read every user profile, including emails.</p>
        <p className="kv">
          <b>Evidence:</b> GET /rest/v1/profiles?select=* returned 200 with 1,402 rows while
          unauthenticated.
        </p>
        <p className="kv"><b>Fix prompt:</b></p>
        <pre className="code">Enable Row Level Security on the profiles table and add a policy
allowing a user to read only their own row (id = auth.uid()). Output the SQL.</pre>
      </div>

      <div className="finding">
        <h3>
          <span className="badge high">high</span>Stripe webhook accepts unsigned requests
        </h3>
        <p className="impact">An attacker can forge a "payment succeeded" event and unlock paid features.</p>
        <p className="kv"><b>Evidence:</b> POST /api/webhook with no stripe-signature returned 200.</p>
      </div>

      <p style={{ marginTop: 24 }}>
        <a className="btn" href="/dashboard">
          Run a Deep Scan on your app
        </a>
      </p>
    </article>
  );
}
