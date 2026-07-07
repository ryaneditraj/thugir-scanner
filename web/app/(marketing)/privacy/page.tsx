import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description: "How Thugir Scanner handles your data and scan results."
};

export default function PrivacyPage() {
  return (
    <article className="doc">
      <h1>Privacy Policy</h1>
      <p className="updated">Last updated · 1 July 2026</p>

      <p>
        This policy explains what Thugir Scanner ("the Service," operated by Thugir Labs) collects,
        why, and how we handle it. Scan results can contain sensitive findings about the systems you
        test, so we treat them carefully.
      </p>

      <h2>What we collect</h2>
      <ul>
        <li><b>Account data</b> — your email and authentication details.</li>
        <li><b>Scan requests</b> — the target URL, your account ID, originating IP address, and timestamp. We keep this as an abuse and audit trail.</li>
        <li><b>Scan results</b> — the findings and the evidence captured during a scan (e.g. response snippets, matched-and-redacted secrets, HTTP metadata).</li>
        <li><b>Usage data</b> — basic logs needed to operate, secure, and rate-limit the Service.</li>
      </ul>

      <h2>How we use it</h2>
      <ul>
        <li>To run scans and show you the results.</li>
        <li>To enforce authorized-testing rules, rate limits, and prevent abuse.</li>
        <li>To operate billing for paid plans.</li>
        <li>To improve detection accuracy in aggregate.</li>
      </ul>

      <h2>Scan evidence &amp; secrets</h2>
      <p>
        When a check detects a credential, we store only a redacted/masked sample as evidence — not
        the full secret where we can avoid it. Scan results are visible only to the account that ran
        the scan. We never sell scan data.
      </p>

      <h2>Sharing</h2>
      <p>
        We don't sell your data. We share it only with infrastructure providers needed to run the
        Service (hosting, database, payments), under their respective terms, and where required by
        law.
      </p>

      <h2>Retention</h2>
      <p>
        Scan results and request logs are retained while your account is active and for a limited
        period afterward for security and audit purposes. You can request deletion of your account
        and associated scan data.
      </p>

      <h2>Your choices</h2>
      <p>
        You can access, export, or delete your scan data and account. Contact us to make a request.
      </p>

      <h2>Contact</h2>
      <p>
        Privacy questions? Reach us via <a href="https://thugirlabs.com">thugirlabs.com</a>.
      </p>
    </article>
  );
}
