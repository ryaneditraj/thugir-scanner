import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { STATIC_PATTERNS, type Platform } from "@/lib/patterns";

export const dynamic = "force-static";

const PLATFORMS: { id: Platform; name: string; blurb: string }[] = [
  {
    id: "lovable",
    name: "Lovable",
    blurb: "Lovable apps often pair a polished UI with an open Supabase data layer."
  },
  {
    id: "bolt",
    name: "Bolt.new",
    blurb: "Bolt/Vite scaffolds frequently expose secrets via VITE_ public env prefixes."
  },
  {
    id: "v0",
    name: "v0",
    blurb: "v0 Next.js apps often ship Server Actions without re-checking authorization."
  },
  {
    id: "replit",
    name: "Replit",
    blurb: "Replit Secrets belong on the server — AI frontends sometimes read them in the browser."
  },
  {
    id: "cursor",
    name: "Cursor",
    blurb: "Cursor-built Next.js apps commonly put server secrets under NEXT_PUBLIC_."
  },
  {
    id: "windsurf",
    name: "Windsurf",
    blurb: "Windsurf scaffolds share the public-env-prefix trap with other AI IDEs."
  },
  {
    id: "supabase",
    name: "Supabase",
    blurb: "The #1 vibe-code failure mode: service_role in the client or RLS left off."
  },
  {
    id: "firebase",
    name: "Firebase",
    blurb: "Open security rules and client-exposed admin credentials show up constantly."
  }
];

export function generateStaticParams() {
  return PLATFORMS.map((p) => ({ platform: p.id }));
}

export function generateMetadata({
  params
}: {
  params: { platform: string };
}): Metadata {
  const p = PLATFORMS.find((x) => x.id === params.platform);
  if (!p) return { title: "Platform" };
  return {
    title: `Scan your ${p.name} app for AI-builder security issues`,
    description: `${p.blurb} Thugir checks the exact misconfigurations ${p.name} scaffolds ship by default — with evidence and fix prompts.`
  };
}

export default function PlatformPage({ params }: { params: { platform: string } }) {
  const p = PLATFORMS.find((x) => x.id === params.platform);
  if (!p) notFound();

  const patterns = STATIC_PATTERNS.filter(
    (pat) => pat.enabled && (pat.platform === p.id || pat.platform === "generic")
  );
  const free = patterns.filter((pat) => pat.tierRequired === "free");
  const deep = patterns.filter((pat) => pat.tierRequired !== "free");

  return (
    <article className="doc">
      <p className="updated">Platform guide</p>
      <h1>Security for {p.name}-built apps</h1>
      <p>{p.blurb}</p>
      <p>
        Thugir Scanner is built for vibe-coded apps — not a generic CVE checklist. We encode the
        mistakes AI scaffolds repeat, prove each finding with evidence, and give you a fix prompt
        you can paste into Cursor or Claude.
      </p>

      <h2>What we check on free scans ({free.length})</h2>
      <ul>
        {free.map((pat) => (
          <li key={pat.slug}>
            <strong>{pat.title}</strong> — {pat.impactOneline}
          </li>
        ))}
      </ul>

      <h2>Unlocked with Deep Scan ({deep.length})</h2>
      <ul>
        {deep.map((pat) => (
          <li key={pat.slug}>
            <strong>{pat.title}</strong> — {pat.impactOneline}
          </li>
        ))}
      </ul>

      <p style={{ marginTop: 32 }}>
        <a className="btn btn-primary" href="/#scan">
          Scan your {p.name} app free
        </a>
      </p>
    </article>
  );
}
