import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Terms of Service",
  description: "The terms that govern use of Thugir Scanner."
};

export default function TermsPage() {
  return (
    <article className="doc">
      <h1>Terms of Service</h1>
      <p className="updated">Last updated · 1 July 2026</p>

      <p>
        These terms govern your use of Thugir Scanner ("the Service"), operated by Thugir Labs. By
        creating an account or running a scan, you agree to them. If you don't agree, don't use the
        Service.
      </p>

      <h2>1. Authorized testing only</h2>
      <p>
        You may only scan a domain or application that you own or are explicitly authorized to test.
        Before any scan you must confirm this. Scanning systems you don't control may be illegal in
        your jurisdiction and is a breach of these terms. We log every scan request against your
        account and originating IP address, rate-limit usage, and decline scans of well-known
        third-party platforms on the free tier.
      </p>

      <h2>2. The scan is a point-in-time check</h2>
      <p>
        Thugir Scanner reports issues it can confirm with captured evidence at the time of the scan.
        It is not a guarantee that your application is free of vulnerabilities, and a clean result
        does not certify security. You remain responsible for the security of your systems.
      </p>

      <h2>3. Accounts</h2>
      <p>
        You're responsible for activity under your account and for keeping your credentials secure.
        We may suspend accounts that abuse the Service, scan unauthorized targets, or attempt to
        disrupt it.
      </p>

      <h2>4. Acceptable use</h2>
      <ul>
        <li>No scanning of targets you don't own or aren't authorized to test.</li>
        <li>No attempts to overload, reverse-engineer, or circumvent the Service or its limits.</li>
        <li>No use of findings to attack systems rather than to fix your own.</li>
      </ul>

      <h2>5. Paid plans</h2>
      <p>
        Deep Scan is billed per scan; Continuous is billed monthly. Prices shown are launch pricing
        and may change with notice. Taxes may apply.
      </p>

      <h2>6. Disclaimer &amp; liability</h2>
      <p>
        The Service is provided "as is," without warranties of any kind. To the maximum extent
        permitted by law, Thugir Labs is not liable for indirect or consequential damages arising
        from use of the Service. Nothing here limits liability that cannot be limited by law.
      </p>

      <h2>7. Changes</h2>
      <p>
        We may update these terms. Material changes will be reflected by the "last updated" date
        above; continued use after a change means you accept it.
      </p>

      <h2>8. Contact</h2>
      <p>
        Questions about these terms? Reach us via <a href="https://thugirlabs.com">thugirlabs.com</a>.
      </p>
    </article>
  );
}
