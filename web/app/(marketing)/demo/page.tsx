import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Sample report",
  description:
    "A representative Thugir Scanner report for a fictional app — every value is fabricated for illustration."
};

// Fully static, clearly-labeled DEMO. No real scan runs here; all data is fabricated.
export default function DemoPage() {
  return (
    <div className="demo-wrap">
      <div className="demo-banner">
        <span>● Demo report — sample data for illustration, not a real scan</span>
        <a href="/#scan" className="btn-arrow">Run a real scan</a>
      </div>

      <header className="demo-header" data-reveal>
        <h1>What a scan report looks like.</h1>
        <p className="lead">
          This is a representative Free Scan for a fictional app, <code>demo-shop.app</code>. The
          findings, evidence and values below are fabricated to show the format — your real report
          contains the captured request/response from your own app.
        </p>
      </header>

      <p className="result-head">
        CASE FILE · <b>demo-shop.app</b> · stack: Next.js + Supabase · 4 confirmed · 3 sealed
      </p>

      <div className="ai-analysis risk-critical">
        <div className="ai-analysis-head">
          <span className="ai-chip">◆ Analyst summary</span>
          <span className="tag critical">critical risk</span>
        </div>
        <p className="ai-summary">
          An anonymous visitor can read your full customer table, and a live Stripe secret key is
          shipped in the browser bundle. Either issue alone is enough to exfiltrate customer data or
          move money. Treat both as actively exploitable and rotate the exposed secrets immediately.
        </p>
      </div>

      {/* Lead finding, fully expanded on the dark document */}
      <section className="demo-section" data-reveal>
        <h2>Confirmed findings</h2>
        <div className="finding-doc" style={{ marginBottom: 14 }}>
          <div className="fd-head">
            <span className="fd-id">FINDING 01 · CONFIRMED</span>
            <span className="tag critical">critical</span>
          </div>
          <div className="fd-body">
            <h3>Environment file reachable over HTTP</h3>
            <p>
              A production request for <code>/.env</code> returns the file contents instead of a
              404, exposing live credentials to anyone on the internet.
            </p>

            <div className="fd-label">Evidence captured</div>
            <div className="fd-evidence">{`$ GET https://demo-shop.app/.env
< HTTP/2 `}<span className="ok">200</span>{`
< content-type: application/octet-stream

DATABASE_URL=postgres://`}<span className="rd">██████████</span>{`
STRIPE_SECRET_KEY=sk_live_`}<span className="rd">████████</span>{`
JWT_SECRET=`}<span className="rd">██████████</span></div>

            <div className="fd-label">Impact</div>
            <p>
              The database URL and Stripe live key grant full read/write to customer data and the
              ability to move money. Every value in the file must be treated as compromised.
            </p>

            <div className="fd-label">Reproduce</div>
            <ol className="fd-steps">
              <li>Open <code>https://demo-shop.app/.env</code> in a browser.</li>
              <li>Observe a 200 response with <code>KEY=VALUE</code> lines.</li>
            </ol>

            <div className="fd-label">Fix</div>
            <div className="fd-fix">
              Stop serving dotfiles from the web root, redeploy so <code>/.env</code> returns 404,
              then rotate <code>DATABASE_URL</code>, <code>STRIPE_SECRET_KEY</code> and{" "}
              <code>JWT_SECRET</code> — they must be considered leaked.
            </div>
          </div>
        </div>

        {DEMO_FINDINGS.map((f, i) => (
          <div className="finding" key={f.title}>
            <h3>
              <span className={`tag ${f.severity}`}>{f.severity}</span>
              <span className="tag verified">verified</span>
              {f.title}
            </h3>
            <p className="impact">{f.impact}</p>
            <details>
              <summary>Evidence &amp; fix</summary>
              <pre className="code">{f.evidence}</pre>
              <p className="dim" style={{ marginTop: 10 }}>
                <b>Fix:</b> {f.fix}
              </p>
            </details>
          </div>
        ))}
      </section>

      {/* Sealed teasers */}
      <section className="demo-section" data-reveal>
        <p className="result-head">SEALED · 3 exhibits need a Deep Scan to confirm</p>
        {DEMO_SEALED.map((t) => (
          <div className="finding locked" key={t.title}>
            <h3>
              <span className={`tag ${t.severity}`}>{t.severity}</span>
              <span className="tag low">sealed</span>
              {t.title}
            </h3>
            <p className="impact">{t.impact}</p>
            <div className="lock-row">Full evidence + fix unlock with a Deep Scan.</div>
          </div>
        ))}
      </section>

      {/* CTA */}
      <section className="demo-cta" data-reveal>
        <h2>This took about ten seconds. Yours will too.</h2>
        <p className="lead" style={{ margin: "0 auto 22px" }}>
          Point the scanner at your own app and get a real, evidence-backed report.
        </p>
        <div className="cta-actions">
          <a className="btn btn-primary btn-arrow" href="/#scan">Run a free scan</a>
          <a className="btn btn-ghost" href="/#pricing">See pricing</a>
        </div>
      </section>
    </div>
  );
}

const DEMO_FINDINGS: { title: string; severity: string; impact: string; evidence: string; fix: string }[] = [
  {
    title: "Customer table readable by anonymous requests",
    severity: "critical",
    impact:
      "Row-level security is off on the users table — an unauthenticated API call returns other people's records.",
    evidence:
      "$ GET https://demo-shop.app/rest/v1/users?select=*\n  apikey: <anon public key>\n< HTTP/2 200\n[ { \"id\": 1, \"email\": \"a***@***.com\", \"stripe_customer\": \"cus_***\" }, … 4,812 rows ]",
    fix: "Enable RLS on every public table and add explicit policies (e.g. user_id = auth.uid()). Verify the anon role can no longer select rows it doesn't own."
  },
  {
    title: "Stripe secret key shipped in the browser bundle",
    severity: "critical",
    impact:
      "A live sk_live_ key was found in client-side JavaScript — anyone can read it from devtools and charge or refund at will.",
    evidence:
      "$ GET https://demo-shop.app/assets/index-4f9a.js\n  …const stripe = require('stripe')('sk_live_51M█████████');…",
    fix: "Move all secret keys to server-side environment variables, never reference them in client code, then rotate the leaked key in the Stripe dashboard."
  },
  {
    title: "Security headers missing",
    severity: "medium",
    impact:
      "No Content-Security-Policy or HSTS — the app is more exposed to clickjacking, mixed content and protocol-downgrade attacks.",
    evidence:
      "$ curl -sI https://demo-shop.app\n< HTTP/2 200\n  (no content-security-policy)\n  (no strict-transport-security)\n  (no x-frame-options)",
    fix: "Add a Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options and X-Frame-Options at the edge or in your framework config."
  }
];

const DEMO_SEALED: { title: string; severity: string; impact: string }[] = [
  {
    title: "Broken access control on record lookup (IDOR)",
    severity: "high",
    impact: "Incrementing an object id appears to return another account's order — needs authenticated probing to confirm."
  },
  {
    title: "Webhook endpoint accepts unsigned requests",
    severity: "high",
    impact: "A payment webhook responded 200 to a request with no signature header — potential forged-event abuse."
  },
  {
    title: "Session token not rotated on privilege change",
    severity: "medium",
    impact: "Tokens issued before a role change may remain valid — requires a multi-step authenticated flow to verify."
  }
];
