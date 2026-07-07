import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "How Thugir scans work",
  description:
    "Exactly what the free scan and Deep Scan do, what we send to your site, and what we never do.",
  alternates: { canonical: "/how-scans-work" }
};

export default function HowScansWorkPage() {
  return (
    <article>
      <h1 style={{ fontFamily: "var(--display)" }}>How our scans work</h1>
      <p className="lead muted">
        Transparency matters for a security product. Here is precisely what happens.
      </p>

      <h2 style={{ fontFamily: "var(--display)" }}>Free starter scan</h2>
      <ul>
        <li>We fetch your homepage and up to a dozen same-origin scripts.</li>
        <li>We check a small fixed set of paths (e.g. /.env, /.git/HEAD) for accidental exposure.</li>
        <li>
          We do one harmless read against your Supabase/Firebase endpoint to test whether data is
          readable without authentication. We never write and never enumerate beyond a single row.
        </li>
        <li>No crawling, no login, no multi-step probing. It is a single, low-impact pass.</li>
      </ul>

      <h2 style={{ fontFamily: "var(--display)" }}>Deep Scan</h2>
      <ul>
        <li>Runs only after you verify you control the domain.</li>
        <li>Crawls a capped number of pages and applies the full pattern library for your platform.</li>
        <li>
          Runs constrained, scoped probes for issues like IDOR and injection with hard runtime and
          request caps - not an open-ended autonomous attack.
        </li>
        <li>Returns full evidence and copy-paste fixes for your AI builder.</li>
      </ul>

      <h2 style={{ fontFamily: "var(--display)" }}>What we never do</h2>
      <ul>
        <li>We do not scan targets you have not attested to owning (and we verify ownership for Deep Scans).</li>
        <li>We do not modify your data.</li>
        <li>We do not store the secrets we find in plaintext; evidence is redacted.</li>
      </ul>
    </article>
  );
}
