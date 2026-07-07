import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { STATIC_PATTERNS } from "@/lib/patterns";

export const dynamic = "force-static";

export function generateStaticParams() {
  return STATIC_PATTERNS.filter((p) => p.enabled).map((p) => ({ slug: p.slug }));
}

export function generateMetadata({ params }: { params: { slug: string } }): Metadata {
  const p = STATIC_PATTERNS.find((x) => x.slug === params.slug && x.enabled);
  if (!p) return { title: "Vulnerability" };
  return {
    title: `${p.title} — vibe-coded app security`,
    description: p.impactOneline
  };
}

export default function VulnerabilityPage({ params }: { params: { slug: string } }) {
  const p = STATIC_PATTERNS.find((x) => x.slug === params.slug && x.enabled);
  if (!p) notFound();

  return (
    <article className="doc">
      <p className="updated">
        {p.platform} · {p.category} · {p.tierRequired} tier
      </p>
      <h1>{p.title}</h1>
      <p>
        <span className={`tag ${p.severityDefault}`}>{p.severityDefault}</span>
      </p>
      <p>
        <strong>Why it matters:</strong> {p.impactOneline}
      </p>
      <h2>What we look for</h2>
      <p>{p.description}</p>
      {p.remediation && (
        <>
          <h2>How to fix</h2>
          <p>{p.remediation.summary}</p>
          <ul>
            {p.remediation.steps.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ul>
        </>
      )}
      {p.fixPrompt && (
        <>
          <h2>Paste into your AI editor</h2>
          <pre className="code">{p.fixPrompt}</pre>
        </>
      )}
      <p style={{ marginTop: 32 }}>
        <a className="btn btn-primary" href="/#scan">
          Scan your app for this issue
        </a>
      </p>
    </article>
  );
}
